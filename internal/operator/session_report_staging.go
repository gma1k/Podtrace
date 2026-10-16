package operator

import (
	"context"
	"errors"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

// A reportRef.secret report reaches the tenant namespace in two steps.
//
// The operator holds secrets update only in its own namespace, and Kubernetes
// refuses to let it create a Role granting a verb it lacks, so the session
// Job cannot be given update on the tenant's Secret. Instead each Job writes
// its report into a staging Secret next to it, in the system namespace, and
// once the session is terminal the operator merges the staged reports and
// creates the tenant Secret itself, using only the create and delete verbs it
// holds cluster-wide. The Job's ServiceAccount never touches the tenant
// namespace.

// ComponentReportStaging labels the per-node staging Secrets.
const ComponentReportStaging = "report-staging"

// SessionReportStagingName names the staging Secret of one node's Job. It is
// the Job's own name: unique per session and node, and a valid Secret name.
func SessionReportStagingName(sessionUID types.UID, node string) string {
	return SessionJobName(sessionUID, node)
}

// SessionReportStagingRoleName names the system-namespace Role and RoleBinding
// that let the session ServiceAccount write its staging Secrets.
func SessionReportStagingRoleName(sessionUID types.UID) string {
	return "podtrace-session-staging-" + shortUID(sessionUID)
}

// reportSinkIsSecret reports whether the session's report goes to a Secret.
func reportSinkIsSecret(s *podtracev1alpha1.PodTraceSession) bool {
	resource, name := reportRefResource(s.Spec.ReportRef)
	return resource == "secrets" && name != ""
}

func reportStagingLabels(s *podtracev1alpha1.PodTraceSession) map[string]string {
	return map[string]string{
		LabelManagedBy:   ManagedByValue,
		LabelComponent:   ComponentReportStaging,
		LabelSessionName: s.Name,
		LabelSessionNS:   s.Namespace,
	}
}

// ensureSessionReportStaging pre-creates the staging Secret of every node and
// grants the session ServiceAccount, in each system namespace, get and delete
// on those Secrets by name plus create. Create cannot be scoped by name; the
// CLI recreates a staging Secret it may not update, keeping its labels.
func ensureSessionReportStaging(ctx context.Context, c client.Client, s *podtracev1alpha1.PodTraceSession, nodesByNamespace map[string][]string) error {
	for ns, nodes := range nodesByNamespace {
		names := make([]string, 0, len(nodes))
		for _, node := range nodes {
			name := SessionReportStagingName(s.UID, node)
			names = append(names, name)
			labels := reportStagingLabels(s)
			labels[LabelNodeName] = node
			staging := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
				Type:       corev1.SecretTypeOpaque,
			}
			if err := c.Create(ctx, staging); err != nil && !apierrors.IsAlreadyExists(err) {
				return fmt.Errorf("pre-create report staging Secret %s/%s: %w", ns, name, err)
			}
		}
		sort.Strings(names)

		roleName := SessionReportStagingRoleName(s.UID)
		role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: roleName, Namespace: ns}}
		if _, err := controllerutil.CreateOrUpdate(ctx, c, role, func() error {
			role.Labels = mergeLabels(role.Labels, sessionRBACLabels(s))
			role.Rules = []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: names, Verbs: []string{"get", "delete"}},
				{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"create"}},
			}
			return nil
		}); err != nil {
			return fmt.Errorf("ensure report staging Role in %s: %w", ns, err)
		}
		binding := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: roleName, Namespace: ns}}
		if _, err := controllerutil.CreateOrUpdate(ctx, c, binding, func() error {
			binding.Labels = mergeLabels(binding.Labels, sessionRBACLabels(s))
			binding.RoleRef = rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: roleName}
			binding.Subjects = sessionSubjects(s, []string{ns})
			return nil
		}); err != nil {
			return fmt.Errorf("ensure report staging RoleBinding in %s: %w", ns, err)
		}
	}
	return nil
}

// checkSecretReportTarget fails when spec.reportRef.secret names a Secret
// this session (or an earlier run of its schedule) did not create, so a
// session can never be aimed at an existing Secret to overwrite it.
func checkSecretReportTarget(ctx context.Context, c client.Client, s *podtracev1alpha1.PodTraceSession) error {
	_, name := reportRefResource(s.Spec.ReportRef)
	var existing corev1.Secret
	err := c.Get(ctx, client.ObjectKey{Namespace: s.Namespace, Name: name}, &existing)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect session report Secret %s/%s: %w", s.Namespace, name, err)
	}
	if reportObjectOwnedBySession(existing.Labels, s) || reportObjectOfSchedule(existing.Labels, controllingSchedule(s)) {
		return nil
	}
	return &reportObjectConflictError{namespace: s.Namespace, name: name, resource: "secrets"}
}

// errNothingStaged reports a session that ended before any Job had a
// staging Secret, so there is no report to publish.
var errNothingStaged = errors.New("no staged report: the session ended before any Job ran")

// publishSessionSecretReport merges every staged per-node report into the
// tenant's reportRef Secret, then deletes the staging Secrets.
func publishSessionSecretReport(ctx context.Context, c client.Client, reader client.Reader, s *podtracev1alpha1.PodTraceSession) error {
	if err := checkSecretReportTarget(ctx, c, s); err != nil {
		return err
	}
	var staged corev1.SecretList
	if err := c.List(ctx, &staged, client.MatchingLabels(reportStagingLabels(s))); err != nil {
		return fmt.Errorf("list report staging Secrets: %w", err)
	}
	if len(staged.Items) == 0 {
		return errNothingStaged
	}
	data := map[string][]byte{}
	for i := range staged.Items {
		var full corev1.Secret
		if err := reader.Get(ctx, client.ObjectKeyFromObject(&staged.Items[i]), &full); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return fmt.Errorf("read report staging Secret %s/%s: %w", staged.Items[i].Namespace, staged.Items[i].Name, err)
		}
		for k, v := range full.Data {
			data[k] = v
		}
	}

	_, name := reportRefResource(s.Spec.ReportRef)
	labels := sessionRBACLabels(s)
	labels[reportManagedBy] = reportManagedVal
	labels[labelReportKind] = reportKindValue
	if schedule := controllingSchedule(s); schedule != "" {
		labels[LabelSchedule] = schedule
	}
	report := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: s.Namespace, Labels: labels},
		Type:       corev1.SecretTypeOpaque,
		Data:       data,
	}
	if err := applySecret(ctx, c, reader, report); err != nil {
		return fmt.Errorf("publish session report Secret %s/%s: %w", s.Namespace, name, err)
	}

	// The staging grant includes an unscoped secrets create; it must not
	// outlive the report it was for.
	namespaces := map[string]struct{}{}
	for i := range staged.Items {
		namespaces[staged.Items[i].Namespace] = struct{}{}
	}
	for ns := range namespaces {
		if err := cleanupSessionReportStaging(ctx, c, s, ns); err != nil {
			return err
		}
	}
	return nil
}

// cleanupSessionReportStaging deletes the session's staging Secrets and the
// staging Role and RoleBinding in systemNS.
func cleanupSessionReportStaging(ctx context.Context, c client.Client, s *podtracev1alpha1.PodTraceSession, systemNS string) error {
	var staged corev1.SecretList
	if err := c.List(ctx, &staged, client.InNamespace(systemNS), client.MatchingLabels(reportStagingLabels(s))); err != nil {
		return fmt.Errorf("list report staging Secrets: %w", err)
	}
	for i := range staged.Items {
		if err := c.Delete(ctx, &staged.Items[i]); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete report staging Secret %s/%s: %w", systemNS, staged.Items[i].Name, err)
		}
	}
	name := SessionReportStagingRoleName(s.UID)
	for _, obj := range []client.Object{
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: systemNS}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: systemNS}},
	} {
		if err := c.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete report staging RBAC %T in %s: %w", obj, systemNS, err)
		}
	}
	return nil
}
