package operator

import (
	"context"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func ensureSessionServiceAccount(ctx context.Context, c client.Client, s *podtracev1alpha1.PodTraceSession, systemNS string) error {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      SessionServiceAccountName(s.UID),
			Namespace: systemNS,
		},
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, c, sa, func() error {
		sa.Labels = mergeLabels(sa.Labels, sessionRBACLabels(s))
		return nil
	}); err != nil {
		return fmt.Errorf("ensure session SA: %w", err)
	}
	return nil
}

// cleanupSessionServiceAccount deletes the per-session ServiceAccount in
// the system namespace.
func cleanupSessionServiceAccount(ctx context.Context, c client.Client, s *podtracev1alpha1.PodTraceSession, systemNS string) error {
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{
		Name: SessionServiceAccountName(s.UID), Namespace: systemNS,
	}}
	if err := c.Delete(ctx, sa); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete session SA %s/%s: %w", systemNS, sa.Name, err)
	}
	return nil
}

func sessionSubjects(s *podtracev1alpha1.PodTraceSession, systemNamespaces []string) []rbacv1.Subject {
	seen := make(map[string]struct{}, len(systemNamespaces))
	subs := make([]rbacv1.Subject, 0, len(systemNamespaces))
	for _, ns := range systemNamespaces {
		if ns == "" {
			continue
		}
		if _, dup := seen[ns]; dup {
			continue
		}
		seen[ns] = struct{}{}
		subs = append(subs, rbacv1.Subject{
			Kind:      rbacv1.ServiceAccountKind,
			Name:      SessionServiceAccountName(s.UID),
			Namespace: ns,
		})
	}
	return subs
}

func ensureSessionReportRBAC(ctx context.Context, c client.Client, s *podtracev1alpha1.PodTraceSession, scheme *runtime.Scheme, systemNamespaces []string) error {
	roleName := SessionReportRoleName(s.UID)
	bindingName := SessionReportRoleBindingName(s.UID)

	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: roleName, Namespace: s.Namespace},
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, c, role, func() error {
		role.Labels = mergeLabels(role.Labels, map[string]string{
			LabelManagedBy:   ManagedByValue,
			LabelComponent:   ComponentSession,
			LabelSessionName: s.Name,
			LabelSessionNS:   s.Namespace,
		})
		role.Rules = buildSessionReportRules(s.Spec.ReportRef)
		return controllerutil.SetControllerReference(s, role, scheme)
	}); err != nil {
		return fmt.Errorf("ensure session report Role: %w", err)
	}

	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: bindingName, Namespace: s.Namespace},
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, c, binding, func() error {
		binding.Labels = mergeLabels(binding.Labels, map[string]string{
			LabelManagedBy:   ManagedByValue,
			LabelComponent:   ComponentSession,
			LabelSessionName: s.Name,
			LabelSessionNS:   s.Namespace,
		})
		binding.RoleRef = rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     roleName,
		}
		binding.Subjects = sessionSubjects(s, systemNamespaces)
		return controllerutil.SetControllerReference(s, binding, scheme)
	}); err != nil {
		return fmt.Errorf("ensure session report RoleBinding: %w", err)
	}
	return nil
}

// cleanupSessionReportRBAC deletes the per-session Role+RoleBinding in
// the user namespace.
func cleanupSessionReportRBAC(ctx context.Context, c client.Client, s *podtracev1alpha1.PodTraceSession) error {
	objects := []client.Object{
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{
			Name: SessionReportRoleBindingName(s.UID), Namespace: s.Namespace,
		}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{
			Name: SessionReportRoleName(s.UID), Namespace: s.Namespace,
		}},
	}
	for _, obj := range objects {
		if err := c.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete session RBAC %T: %w", obj, err)
		}
	}
	return nil
}

// sessionRBACLabels are the labels every per-session RBAC object carries, so
// the cross-namespace pod-read grants can be located and cleaned up by label.
func sessionRBACLabels(s *podtracev1alpha1.PodTraceSession) map[string]string {
	return map[string]string{
		LabelManagedBy:   ManagedByValue,
		LabelComponent:   ComponentSession,
		LabelSessionName: s.Name,
		LabelSessionNS:   s.Namespace,
	}
}

// sessionPodNamespaces returns the namespaces the in-Job CLI reads pods from
// BEYOND the session's own namespace: the resolved namespaceSelector allowlist
// (when spec.selector is set) plus any cross-namespace podRefs.
func sessionPodNamespaces(s *podtracev1alpha1.PodTraceSession, targets sessionTargets) []string {
	set := map[string]struct{}{}
	if s.Spec.Selector != nil {
		for _, ns := range targets.Namespaces {
			if ns != "" && ns != s.Namespace {
				set[ns] = struct{}{}
			}
		}
	}
	for _, ref := range targets.PodRefs {
		if ref.Namespace != "" && ref.Namespace != s.Namespace {
			set[ref.Namespace] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for ns := range set {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out
}

// ensureSessionPodReadRBAC grants the session SA pods+events read in each
// extra namespace a cross-namespace session targets.
func ensureSessionPodReadRBAC(ctx context.Context, c client.Client, s *podtracev1alpha1.PodTraceSession, scheme *runtime.Scheme, namespaces []string, systemNamespaces []string) error {
	for _, ns := range namespaces {
		sameNS := ns == s.Namespace
		role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: SessionPodReadRoleName(s.UID), Namespace: ns}}
		if _, err := controllerutil.CreateOrUpdate(ctx, c, role, func() error {
			role.Labels = mergeLabels(role.Labels, sessionRBACLabels(s))
			role.Rules = []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list", "watch"}},
				{APIGroups: []string{""}, Resources: []string{"events"}, Verbs: []string{"get", "list", "watch"}},
			}
			if sameNS {
				return controllerutil.SetControllerReference(s, role, scheme)
			}
			return nil
		}); err != nil {
			return fmt.Errorf("ensure session pod-read Role in %s: %w", ns, err)
		}

		binding := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: SessionPodReadRoleBindingName(s.UID), Namespace: ns}}
		if _, err := controllerutil.CreateOrUpdate(ctx, c, binding, func() error {
			binding.Labels = mergeLabels(binding.Labels, sessionRBACLabels(s))
			binding.RoleRef = rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "Role",
				Name:     SessionPodReadRoleName(s.UID),
			}
			binding.Subjects = sessionSubjects(s, systemNamespaces)
			if sameNS {
				return controllerutil.SetControllerReference(s, binding, scheme)
			}
			return nil
		}); err != nil {
			return fmt.Errorf("ensure session pod-read RoleBinding in %s: %w", ns, err)
		}
	}
	return pruneSessionPodReadRBAC(ctx, c, s, namespaces)
}

// cleanupSessionPodReadRBAC deletes the cross-namespace pod-read Role+RoleBinding
// for a session.
func cleanupSessionPodReadRBAC(ctx context.Context, c client.Client, s *podtracev1alpha1.PodTraceSession) error {
	return pruneSessionPodReadRBAC(ctx, c, s, nil)
}

// pruneSessionPodReadRBAC deletes the session's pod-read Role+RoleBinding in
// every namespace not in keep.
func pruneSessionPodReadRBAC(ctx context.Context, c client.Client, s *podtracev1alpha1.PodTraceSession, keep []string) error {
	keepSet := make(map[string]struct{}, len(keep))
	for _, ns := range keep {
		keepSet[ns] = struct{}{}
	}
	sel := client.MatchingLabels(sessionRBACLabels(s))

	var bindings rbacv1.RoleBindingList
	if err := c.List(ctx, &bindings, sel); err != nil {
		return fmt.Errorf("list session pod-read RoleBindings: %w", err)
	}
	for i := range bindings.Items {
		if bindings.Items[i].Name != SessionPodReadRoleBindingName(s.UID) {
			continue
		}
		if _, ok := keepSet[bindings.Items[i].Namespace]; ok {
			continue
		}
		if err := c.Delete(ctx, &bindings.Items[i]); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete session pod-read RoleBinding %s/%s: %w",
				bindings.Items[i].Namespace, bindings.Items[i].Name, err)
		}
	}

	var roles rbacv1.RoleList
	if err := c.List(ctx, &roles, sel); err != nil {
		return fmt.Errorf("list session pod-read Roles: %w", err)
	}
	for i := range roles.Items {
		if roles.Items[i].Name != SessionPodReadRoleName(s.UID) {
			continue
		}
		if _, ok := keepSet[roles.Items[i].Namespace]; ok {
			continue
		}
		if err := c.Delete(ctx, &roles.Items[i]); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete session pod-read Role %s/%s: %w",
				roles.Items[i].Namespace, roles.Items[i].Name, err)
		}
	}
	return nil
}

func buildSessionReportRules(ref *podtracev1alpha1.ReportReference) []rbacv1.PolicyRule {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"events"},
			Verbs:     []string{"get", "list", "watch"},
		},
	}
	resource, name := reportRefResource(ref)
	if resource == "" || name == "" || resource == "secrets" {
		return rules
	}
	rules = append(rules,
		rbacv1.PolicyRule{
			APIGroups:     []string{""},
			Resources:     []string{resource},
			ResourceNames: []string{name},
			Verbs:         []string{"get", "update"},
		},
	)
	return rules
}

const (
	labelReportKind  = "podtrace.io/kind"
	reportKindValue  = "session-report"
	reportManagedBy  = "podtrace.io/managed-by"
	reportManagedVal = "podtrace-cli"
)

// reportObjectConflictError signals that spec.reportRef names a
// pre-existing ConfigMap/Secret the session did not create.
type reportObjectConflictError struct {
	namespace string
	name      string
	resource  string
}

func (e *reportObjectConflictError) Error() string {
	return fmt.Sprintf("spec.reportRef names %s %s/%s which already exists and was not created by this session; "+
		"pick a name that does not collide with an existing object", e.resource, e.namespace, e.name)
}

// ensureSessionReportObject pre-creates an empty report ConfigMap in the
// session namespace so the Job's ServiceAccount needs only scoped get/update.
// A Secret report is staged instead; see session_report_staging.go.
func ensureSessionReportObject(ctx context.Context, c client.Client, s *podtracev1alpha1.PodTraceSession) error {
	resource, name := reportRefResource(s.Spec.ReportRef)
	if name == "" {
		return nil
	}
	labels := sessionRBACLabels(s)
	labels[reportManagedBy] = reportManagedVal
	labels[labelReportKind] = reportKindValue
	schedule := controllingSchedule(s)
	if schedule != "" {
		labels[LabelSchedule] = schedule
	}
	var obj client.Object
	switch resource {
	case "configmaps":
		obj = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: s.Namespace, Labels: labels}}
	default:
		return nil
	}
	err := c.Create(ctx, obj)
	if err == nil {
		return nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("pre-create session report %s/%s: %w", s.Namespace, name, err)
	}

	existing := obj.DeepCopyObject().(client.Object)
	if getErr := c.Get(ctx, client.ObjectKey{Namespace: s.Namespace, Name: name}, existing); getErr != nil {
		return fmt.Errorf("inspect existing session report %s/%s: %w", s.Namespace, name, getErr)
	}
	if reportObjectOwnedBySession(existing.GetLabels(), s) {
		return nil
	}
	if !reportObjectOfSchedule(existing.GetLabels(), schedule) {
		return &reportObjectConflictError{namespace: s.Namespace, name: name, resource: resource}
	}
	merged := existing.GetLabels()
	for k, v := range labels {
		merged[k] = v
	}
	existing.SetLabels(merged)
	if err := c.Update(ctx, existing); err != nil {
		return fmt.Errorf("take over session report %s/%s from an earlier run: %w", s.Namespace, name, err)
	}
	return nil
}

// controllingSchedule returns the name of the PodTraceSchedule that controls
// the session, or "" for a session no schedule owns.
func controllingSchedule(s *podtracev1alpha1.PodTraceSession) string {
	ref := metav1.GetControllerOf(s)
	if ref == nil || ref.Kind != "PodTraceSchedule" {
		return ""
	}
	if gv, err := schema.ParseGroupVersion(ref.APIVersion); err != nil || gv.Group != podtracev1alpha1.GroupVersion.Group {
		return ""
	}
	return ref.Name
}

// reportObjectOfSchedule reports whether a pre-existing report object was
// created by a session of the named schedule.
func reportObjectOfSchedule(labels map[string]string, schedule string) bool {
	return schedule != "" &&
		labels[labelReportKind] == reportKindValue &&
		labels[reportManagedBy] == reportManagedVal &&
		labels[LabelSchedule] == schedule
}

// reportObjectOwnedBySession reports whether a pre-existing report object
// carries the labels this session stamps on the objects it creates.
func reportObjectOwnedBySession(labels map[string]string, s *podtracev1alpha1.PodTraceSession) bool {
	return labels[labelReportKind] == reportKindValue &&
		labels[reportManagedBy] == reportManagedVal &&
		labels[LabelSessionName] == s.Name &&
		labels[LabelSessionNS] == s.Namespace
}

// reportRefResource decodes spec.reportRef into the (resource, name)
// tuple the RBAC grant needs.
func reportRefResource(ref *podtracev1alpha1.ReportReference) (string, string) {
	switch {
	case ref == nil:
		return "", ""
	case ref.ConfigMap != nil && ref.ConfigMap.Name != "":
		return "configmaps", ref.ConfigMap.Name
	case ref.Secret != nil && ref.Secret.Name != "":
		return "secrets", ref.Secret.Name
	}
	return "", ""
}

// reportToSpecFromReportRef renders the session's reportRef into the
// form the CLI's --report-to flag parses. Returns empty string when no
func reportToSpecFromReportRef(s *podtracev1alpha1.PodTraceSession) string {
	if s == nil || s.Spec.ReportRef == nil {
		return ""
	}
	switch {
	case s.Spec.ReportRef.ConfigMap != nil && s.Spec.ReportRef.ConfigMap.Name != "":
		return "configmap/" + s.Namespace + "/" + s.Spec.ReportRef.ConfigMap.Name
	case s.Spec.ReportRef.Secret != nil && s.Spec.ReportRef.Secret.Name != "":
		return "secret/" + s.Namespace + "/" + s.Spec.ReportRef.Secret.Name
	case s.Spec.ReportRef.ObjectStore != nil && s.Spec.ReportRef.ObjectStore.URI != "":
		return s.Spec.ReportRef.ObjectStore.URI
	}
	return ""
}
