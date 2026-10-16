package operator

import (
	"context"
	"fmt"
	"sort"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

// FinalizerCleanup is the single finalizer name used by the operator for
// cross-namespace cleanup of resources a namespaced CR cannot own via
// ownerReferences. Kubernetes forbids a namespaced owner in namespace A
// from owning any object in namespace B, so we fall back to:
//
//  1. Put the child in podtrace-system, with labels naming the owning CR.
//  2. Add this finalizer to the CR at first reconcile.
//  3. On CR deletion, list children by label and delete them before
//     clearing the finalizer.
//
// This is the standard pattern in Prometheus Operator, cert-manager, etc.
const FinalizerCleanup = "podtrace.io/cleanup"

func ensureFinalizer(obj client.Object) bool {
	return controllerutil.AddFinalizer(obj, FinalizerCleanup)
}

func removeFinalizer(obj client.Object) bool {
	return controllerutil.RemoveFinalizer(obj, FinalizerCleanup)
}

// finalizerUpdateOutcome classifies the error from a set/clear-finalizer
// Update.
func finalizerUpdateOutcome(err error) (ctrl.Result, bool) {
	switch {
	case apierrors.IsNotFound(err):
		return ctrl.Result{}, true
	case apierrors.IsConflict(err):
		return ctrl.Result{RequeueAfter: time.Second}, true
	default:
		return ctrl.Result{}, false
	}
}

// cleanupPodTraceChildren deletes the bundle ConfigMap + Secret this
// PodTrace owns across namespaces. Called on CR deletion.
func cleanupPodTraceChildren(ctx context.Context, c client.Client, pt *podtracev1alpha1.PodTrace, systemNS string) error {
	bundleName := ExporterBundleName(pt.UID)
	for _, obj := range []client.Object{
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: bundleName, Namespace: systemNS}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: bundleName, Namespace: systemNS}},
	} {
		if err := c.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete %T %s/%s: %w", obj, systemNS, bundleName, err)
		}
	}
	return nil
}

// cleanupOrphanBundles deletes exporter-bundle ConfigMaps/Secrets for this
// PodTrace that live in any namespace other than keepNS.
func cleanupOrphanBundles(ctx context.Context, c client.Client, pt *podtracev1alpha1.PodTrace, keepNS string) error {
	return cleanupOrphanBundlesOutside(ctx, c, pt, []string{keepNS})
}

// cleanupOrphanBundlesOutside deletes exporter-bundle ConfigMaps/Secrets for
// this PodTrace that live in none of the keep namespaces.
func cleanupOrphanBundlesOutside(ctx context.Context, c client.Client, pt *podtracev1alpha1.PodTrace, keep []string) error {
	keepSet := make(map[string]struct{}, len(keep))
	for _, ns := range keep {
		keepSet[ns] = struct{}{}
	}
	sel := client.MatchingLabels{
		LabelManagedBy:    ManagedByValue,
		LabelComponent:    ComponentBundle,
		LabelPodTraceName: pt.Name,
		LabelPodTraceNS:   pt.Namespace,
	}

	var cms corev1.ConfigMapList
	if err := c.List(ctx, &cms, sel); err != nil {
		return fmt.Errorf("list bundle ConfigMaps: %w", err)
	}
	for i := range cms.Items {
		if _, ok := keepSet[cms.Items[i].Namespace]; ok {
			continue
		}
		if err := c.Delete(ctx, &cms.Items[i]); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete orphan bundle ConfigMap %s/%s: %w",
				cms.Items[i].Namespace, cms.Items[i].Name, err)
		}
	}

	var secrets corev1.SecretList
	if err := c.List(ctx, &secrets, sel); err != nil {
		return fmt.Errorf("list bundle Secrets: %w", err)
	}
	for i := range secrets.Items {
		if _, ok := keepSet[secrets.Items[i].Namespace]; ok {
			continue
		}
		if err := c.Delete(ctx, &secrets.Items[i]); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete orphan bundle Secret %s/%s: %w",
				secrets.Items[i].Namespace, secrets.Items[i].Name, err)
		}
	}
	return nil
}

// candidateSystemNamespaces returns the deduplicated set of namespaces a
// CR's children may live in: the currently effective system namespace plus
// the operator default (they differ when TracerConfig.spec.systemNamespace
// is set, and the effective one may have changed between create and delete).
func candidateSystemNamespaces(effective, fallback string) []string {
	if effective == "" || effective == fallback {
		return []string{fallback}
	}
	return []string{effective, fallback}
}

// cleanupPodTraceSessionChildren deletes all resources this PodTraceSession
// owns across namespaces:
//
//   - per-node Jobs in the system namespace
//   - exporter bundle ConfigMap + optional Secret in the system namespace
//   - per-session Role + RoleBinding in the user namespace
//
// Called on CR deletion via the shared FinalizerCleanup finalizer.
// Each delete is NotFound-idempotent so repeated cleanup passes do
// not error.
func cleanupPodTraceSessionChildren(ctx context.Context, c client.Client, s *podtracev1alpha1.PodTraceSession, systemNS string) error {
	var jobs batchv1.JobList
	if err := c.List(ctx, &jobs, client.InNamespace(systemNS), client.MatchingLabels{
		LabelManagedBy:   ManagedByValue,
		LabelComponent:   ComponentSession,
		LabelSessionName: s.Name,
		LabelSessionNS:   s.Namespace,
	}); err != nil {
		return fmt.Errorf("list session Jobs: %w", err)
	}
	policy := metav1.DeletePropagationBackground
	for i := range jobs.Items {
		j := &jobs.Items[i]
		if j.UID == types.UID("") {
			continue
		}
		if err := c.Delete(ctx, j, &client.DeleteOptions{PropagationPolicy: &policy}); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete Job %s/%s: %w", j.Namespace, j.Name, err)
		}
	}

	bundleName := SessionBundleName(s.UID)
	objstoreCredsName := SessionObjectStoreCredsName(s.UID)
	for _, obj := range []client.Object{
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: bundleName, Namespace: systemNS}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: bundleName, Namespace: systemNS}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: objstoreCredsName, Namespace: systemNS}},
	} {
		if err := c.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete session bundle %T: %w", obj, err)
		}
	}

	if err := cleanupSessionReportRBAC(ctx, c, s); err != nil {
		return err
	}
	if err := cleanupSessionPodReadRBAC(ctx, c, s); err != nil {
		return err
	}
	if err := cleanupSessionReportStaging(ctx, c, s, systemNS); err != nil {
		return err
	}
	if err := cleanupSessionServiceAccount(ctx, c, s, systemNS); err != nil {
		return err
	}
	return nil
}

// sessionChildNamespaces returns every namespace that currently holds a
// resource labelled as owned by this session, unioned with the caller's
// best-effort seed (the currently-resolved system namespace plus the operator
// default).
func sessionChildNamespaces(ctx context.Context, c client.Client, s *podtracev1alpha1.PodTraceSession, seed []string) ([]string, error) {
	set := map[string]struct{}{}
	for _, ns := range seed {
		if ns != "" {
			set[ns] = struct{}{}
		}
	}
	sel := client.MatchingLabels(sessionRBACLabels(s))

	var jobs batchv1.JobList
	if err := c.List(ctx, &jobs, sel); err != nil {
		return nil, fmt.Errorf("list session Jobs for cleanup: %w", err)
	}
	for i := range jobs.Items {
		set[jobs.Items[i].Namespace] = struct{}{}
	}
	var configMaps corev1.ConfigMapList
	if err := c.List(ctx, &configMaps, sel); err != nil {
		return nil, fmt.Errorf("list session ConfigMaps for cleanup: %w", err)
	}
	for i := range configMaps.Items {
		set[configMaps.Items[i].Namespace] = struct{}{}
	}
	var secrets corev1.SecretList
	if err := c.List(ctx, &secrets, sel); err != nil {
		return nil, fmt.Errorf("list session Secrets for cleanup: %w", err)
	}
	for i := range secrets.Items {
		set[secrets.Items[i].Namespace] = struct{}{}
	}
	var serviceAccounts corev1.ServiceAccountList
	if err := c.List(ctx, &serviceAccounts, sel); err != nil {
		return nil, fmt.Errorf("list session ServiceAccounts for cleanup: %w", err)
	}
	for i := range serviceAccounts.Items {
		set[serviceAccounts.Items[i].Namespace] = struct{}{}
	}

	out := make([]string, 0, len(set))
	for ns := range set {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out, nil
}
