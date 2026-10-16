package operator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/fleet"
	"github.com/gma1k/podtrace/internal/imagepolicy"
	"github.com/gma1k/podtrace/internal/safeconv"
)

// TracerConfigReconciler owns one agent fleet per TracerConfig: the agent
// DaemonSet, its ServiceAccount, and the ClusterRole/Binding that grants
// agents the minimum RBAC to do their job.
type TracerConfigReconciler struct {
	client.Client
	APIReader       client.Reader
	Scheme          *runtime.Scheme
	SystemNamespace string
}

// +kubebuilder:rbac:groups=podtrace.io,resources=tracerconfigs,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=podtrace.io,resources=tracerconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=podtrace.io,resources=tracerconfigs/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles;clusterrolebindings,verbs=get;list;watch;create;update;patch;delete

// Reconcile ensures the agent DaemonSet and its RBAC match spec.
// Idempotent; re-queues on transient API errors.
func (r *TracerConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("tracerconfig", req.Name)

	var tc podtracev1alpha1.TracerConfig
	if err := r.Get(ctx, req.NamespacedName, &tc); err != nil {
		if apierrors.IsNotFound(err) {
			forgetTracerConfigMetrics(req.Name)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get TracerConfig: %w", err)
	}

	if err := validateTracerConfigName(tc.Name); err != nil {
		r.setCondition(&tc, ConditionDegraded, metav1.ConditionTrue, "InvalidName", err.Error())
		r.setCondition(&tc, ConditionReady, metav1.ConditionFalse, "InvalidName", err.Error())
		if uerr := r.Status().Update(ctx, &tc); uerr != nil && !apierrors.IsConflict(uerr) {
			return ctrl.Result{}, fmt.Errorf("update status: %w", uerr)
		}
		return ctrl.Result{}, nil
	}

	if err := imagepolicy.RepoAllowed(tc.Spec.Image, config.AllowedAgentImageRepos()); err != nil {
		logger.Info("refusing agent fleet: image not allowed", "image", tc.Spec.Image, "error", err.Error())
		r.setCondition(&tc, ConditionDegraded, metav1.ConditionTrue, "ImageNotAllowed", err.Error())
		r.setCondition(&tc, ConditionReady, metav1.ConditionFalse, "ImageNotAllowed", err.Error())
		if uerr := r.Status().Update(ctx, &tc); uerr != nil && !apierrors.IsConflict(uerr) {
			return ctrl.Result{}, fmt.Errorf("update status: %w", uerr)
		}
		return ctrl.Result{}, nil
	}

	if err := podtracev1alpha1.ValidateSystemNamespace(tc.Spec.SystemNamespace); err != nil {
		logger.Info("refusing agent fleet: system namespace not allowed", "systemNamespace", tc.Spec.SystemNamespace)
		r.setCondition(&tc, ConditionDegraded, metav1.ConditionTrue, "SystemNamespaceInvalid", err.Error())
		r.setCondition(&tc, ConditionReady, metav1.ConditionFalse, "SystemNamespaceInvalid", err.Error())
		if uerr := r.Status().Update(ctx, &tc); uerr != nil && !apierrors.IsConflict(uerr) {
			return ctrl.Result{}, fmt.Errorf("update status: %w", uerr)
		}
		return ctrl.Result{}, nil
	}

	systemNS := r.systemNamespaceFor(&tc)

	if err := r.ensureAgentRBAC(ctx, &tc, systemNS); err != nil {
		logger.Error(err, "ensure agent RBAC")
		r.setCondition(&tc, ConditionDegraded, metav1.ConditionTrue, "RBACError", err.Error())
		if uerr := r.Status().Update(ctx, &tc); uerr != nil && !apierrors.IsConflict(uerr) {
			logger.Error(uerr, "update Degraded status after RBAC error")
		}
		return ctrl.Result{}, err
	}

	webhookHash, webhookProblem := r.alertWebhookSecret(ctx, &tc, systemNS)
	ds, err := r.ensureAgentDaemonSet(ctx, &tc, systemNS, webhookHash)
	if err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{RequeueAfter: time.Second}, nil
		}
		logger.Error(err, "ensure agent DaemonSet")
		r.setCondition(&tc, ConditionDegraded, metav1.ConditionTrue, "DaemonSetError", err.Error())
		if uerr := r.Status().Update(ctx, &tc); uerr != nil && !apierrors.IsConflict(uerr) {
			logger.Error(uerr, "update Degraded status after DaemonSet error")
		}
		return ctrl.Result{}, err
	}

	if err := r.cleanupStaleAgentObjects(ctx, tc.Name, systemNS); err != nil {
		logger.Error(err, "cleanup stale agent objects")
	}

	tc.Status.DesiredAgents = ds.Status.DesiredNumberScheduled
	tc.Status.ReadyAgents = ds.Status.NumberReady
	tc.Status.ActiveSessions = r.countActiveSessions(ctx)
	tc.Status.ObservedGeneration = tc.Generation

	r.applyFleetPartitionStatus(ctx, &tc, logger)

	if tc.Spec.BTFMode == podtracev1alpha1.BTFModeEmbedded {
		logger.Info("spec.btfMode=embedded is deprecated and does nothing; agent uses host BTF (auto). Use btfMode=file with spec.btfSource")
	}
	blobProblem := r.btfBlobProblem(ctx, &tc, systemNS)
	message := reconciledMessageFor(&tc, blobProblem)
	if webhookProblem != "" {
		message += "; " + webhookProblem
	}
	r.setCondition(&tc, ConditionReconciled, metav1.ConditionTrue, "Reconciled", message)
	r.setCondition(&tc, ConditionReady,
		conditionStatusFromBool(tc.Status.ReadyAgents == tc.Status.DesiredAgents && tc.Status.DesiredAgents > 0),
		"AgentFleetReady",
		fmt.Sprintf("%d/%d agents Ready", tc.Status.ReadyAgents, tc.Status.DesiredAgents),
	)
	r.setCondition(&tc, ConditionDegraded, metav1.ConditionFalse, "Reconciled", "")

	if err := r.Status().Update(ctx, &tc); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{RequeueAfter: time.Second}, nil
		}
		return ctrl.Result{}, fmt.Errorf("update status: %w", err)
	}
	if blobProblem != "" || webhookProblem != "" {
		return ctrl.Result{RequeueAfter: btfBlobRecheckInterval}, nil
	}
	return ctrl.Result{}, nil
}

// AnnotationAlertWebhookHash on the agent pod template carries a hash of the
// alert webhook URL read from webhookURLSecretRef, so changing the Secret
// rolls the agents.
const AnnotationAlertWebhookHash = "podtrace.io/alert-webhook-hash"

// alertWebhookSecret reads spec.agent.alerting.webhookURLSecretRef.
func (r *TracerConfigReconciler) alertWebhookSecret(ctx context.Context, tc *podtracev1alpha1.TracerConfig, systemNS string) (hash, problem string) {
	a := tc.Spec.Agent.Alerting
	if a == nil || !a.Enabled || a.WebhookURLSecretRef == nil || a.WebhookURLSecretRef.Name == "" {
		return "", ""
	}
	reader := client.Reader(r.Client)
	if r.APIReader != nil {
		reader = r.APIReader
	}
	ref := a.WebhookURLSecretRef
	var secret corev1.Secret
	err := reader.Get(ctx, types.NamespacedName{Namespace: systemNS, Name: ref.Name}, &secret)
	if apierrors.IsNotFound(err) {
		return "", fmt.Sprintf("alert webhook Secret %s/%s does not exist, so agents run without the webhook", systemNS, ref.Name)
	}
	if err != nil {
		return "", ""
	}
	value := secret.Data[ref.Key]
	if len(value) == 0 {
		return "", fmt.Sprintf("alert webhook Secret %s/%s has no key %q, so agents run without the webhook", systemNS, ref.Name, ref.Key)
	}
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:8]), ""
}

// secretToTracerConfigs enqueues the TracerConfigs whose alert webhook Secret
// changed.
func (r *TracerConfigReconciler) secretToTracerConfigs(ctx context.Context, obj client.Object) []reconcile.Request {
	var configs podtracev1alpha1.TracerConfigList
	if err := r.List(ctx, &configs); err != nil {
		return nil
	}
	var out []reconcile.Request
	for i := range configs.Items {
		tc := &configs.Items[i]
		a := tc.Spec.Agent.Alerting
		if a == nil || a.WebhookURLSecretRef == nil || a.WebhookURLSecretRef.Name != obj.GetName() {
			continue
		}
		if r.systemNamespaceFor(tc) != obj.GetNamespace() {
			continue
		}
		out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{Name: tc.Name}})
	}
	return out
}

const btfBlobRecheckInterval = 15 * time.Second

// SetupWithManager registers the reconciler, declaring owned resources
// so controller-runtime requeues the TracerConfig whenever an owned
// resource's status changes.
func (r *TracerConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("tracerconfig").
		For(&podtracev1alpha1.TracerConfig{}, builder.WithPredicates(predicate.Or(
			predicate.GenerationChangedPredicate{},
			predicate.LabelChangedPredicate{},
		))).
		Owns(&appsv1.DaemonSet{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&rbacv1.ClusterRole{}).
		Owns(&rbacv1.ClusterRoleBinding{}).
		Owns(&rbacv1.Role{}).
		Owns(&rbacv1.RoleBinding{}).
		Watches(&podtracev1alpha1.PodTraceSession{},
			handler.EnqueueRequestsFromMapFunc(r.enqueueAllTracerConfigs),
			builder.WithPredicates(sessionStateChangedPredicate())).
		Watches(&podtracev1alpha1.TracerConfig{},
			handler.EnqueueRequestsFromMapFunc(r.enqueueAllTracerConfigs),
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.secretToTracerConfigs)).
		Watches(&corev1.Node{},
			handler.EnqueueRequestsFromMapFunc(r.enqueueAllTracerConfigs),
			builder.WithPredicates(nodeSchedulingChangedPredicate())).
		WithOptions(defaultControllerOptions()).
		Complete(r)
}

// enqueueAllTracerConfigs requeues every TracerConfig in the cluster.
func (r *TracerConfigReconciler) enqueueAllTracerConfigs(ctx context.Context, _ client.Object) []reconcile.Request {
	var configs podtracev1alpha1.TracerConfigList
	if err := r.List(ctx, &configs); err != nil {
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: DefaultTracerConfigName}}}
	}
	requests := make([]reconcile.Request, 0, len(configs.Items))
	for i := range configs.Items {
		requests = append(requests, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: configs.Items[i].Name},
		})
	}
	return requests
}

// sessionStateChangedPredicate admits only the session events that can
// change a TracerConfig's active-session count: creation, deletion, and a
// state transition.
func sessionStateChangedPredicate() predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldSession, okOld := e.ObjectOld.(*podtracev1alpha1.PodTraceSession)
			newSession, okNew := e.ObjectNew.(*podtracev1alpha1.PodTraceSession)
			if !okOld || !okNew {
				return true
			}
			return oldSession.Status.State != newSession.Status.State ||
				oldSession.DeletionTimestamp.IsZero() != newSession.DeletionTimestamp.IsZero()
		},
	}
}

// nodeSchedulingChangedPredicate admits only the Node transitions that can
// change which fleet targets a node: creation, deletion, and edits to labels
// or taints.
func nodeSchedulingChangedPredicate() predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldNode, okOld := e.ObjectOld.(*corev1.Node)
			newNode, okNew := e.ObjectNew.(*corev1.Node)
			if !okOld || !okNew {
				return true
			}
			return !maps.Equal(oldNode.Labels, newNode.Labels) ||
				!slices.Equal(oldNode.Spec.Taints, newNode.Spec.Taints)
		},
	}
}

// applyFleetPartitionStatus resolves which nodes this fleet shares with
// other fleets and records the answer on status + the Conflict condition.
func (r *TracerConfigReconciler) applyFleetPartitionStatus(ctx context.Context, tc *podtracev1alpha1.TracerConfig, logger logr.Logger) {
	var configs podtracev1alpha1.TracerConfigList
	if err := r.List(ctx, &configs); err != nil {
		logger.Info("list TracerConfigs for overlap detection failed; skipping", "error", err.Error())
		r.setCondition(tc, ConditionConflict, metav1.ConditionUnknown, "PartitionUnresolved", err.Error())
		return
	}

	var nodes corev1.NodeList
	if err := r.List(ctx, &nodes); err != nil {
		logger.Info("list Nodes for overlap detection failed; skipping. "+
			"The operator ClusterRole needs nodes get/list/watch — upgrade the chart if this persists",
			"error", err.Error())
		r.setCondition(tc, ConditionConflict, metav1.ConditionUnknown, "NodesUnreadable", err.Error())
		return
	}

	partition := fleet.ComputePartition(configs.Items, nodes.Items)
	for i := range configs.Items {
		name := configs.Items[i].Name
		tracerConfigMatchedNodes.WithLabelValues(name).Set(float64(len(partition.Matched[name])))
		tracerConfigContestedNodes.WithLabelValues(name).Set(float64(len(partition.Contested[name])))
	}

	tc.Status.MatchedNodes = safeconv.IntToInt32(len(partition.Matched[tc.Name]))
	tc.Status.ContestedNodes = safeconv.IntToInt32(len(partition.Contested[tc.Name]))

	if message := partition.ConflictMessage(tc.Name); message != "" {
		logger.Info("agent fleets overlap",
			"contestedNodes", tc.Status.ContestedNodes, "rivals", partition.Rivals[tc.Name])
		r.setCondition(tc, ConditionConflict, metav1.ConditionTrue, "OverlappingNodes", message)
		return
	}
	r.setCondition(tc, ConditionConflict, metav1.ConditionFalse, "ExclusiveNodes",
		fmt.Sprintf("no other TracerConfig targets any of this fleet's %d node(s)", tc.Status.MatchedNodes))
}

func (r *TracerConfigReconciler) systemNamespaceFor(tc *podtracev1alpha1.TracerConfig) string {
	if tc.Spec.SystemNamespace != "" {
		return tc.Spec.SystemNamespace
	}
	return r.SystemNamespace
}

// countActiveSessions reports how many PodTraceSessions are not yet terminal
// (Pending or Running), populating status.activeSessions, which was declared
// (and printed as the "Sessions" column) but never set.
func (r *TracerConfigReconciler) countActiveSessions(ctx context.Context) int32 {
	var sessions podtracev1alpha1.PodTraceSessionList
	if err := r.List(ctx, &sessions); err != nil {
		return 0
	}
	var active int32
	for i := range sessions.Items {
		switch sessions.Items[i].Status.State {
		case podtracev1alpha1.SessionStateCompleted, podtracev1alpha1.SessionStateFailed:
		default:
			active++
		}
	}
	return active
}

// ensureAgentRBAC creates / updates this fleet's agent SA, ClusterRole,
// ClusterRoleBinding, and the namespaced Role/RoleBinding that let the agent
// read exporter bundles.
func (r *TracerConfigReconciler) ensureAgentRBAC(ctx context.Context, tc *podtracev1alpha1.TracerConfig, systemNS string) error {
	agentLabels := agentObjectLabels(tc.Name)

	sa := &corev1.ServiceAccount{
		ObjectMeta: ManagedObjectMeta(AgentServiceAccountName(tc.Name), systemNS, ComponentAgent, agentLabels),
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, sa, func() error {
		sa.Labels = mergeLabels(sa.Labels, agentLabels)
		return controllerutil.SetControllerReference(tc, sa, r.Scheme)
	}); err != nil {
		return fmt.Errorf("ServiceAccount: %w", err)
	}

	cr := &rbacv1.ClusterRole{
		ObjectMeta: ManagedObjectMeta(AgentClusterRoleName(tc.Name), "", ComponentAgent, agentLabels),
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, cr, func() error {
		cr.Labels = mergeLabels(cr.Labels, agentLabels)
		cr.Rules = agentClusterRoleRules(systemNS)
		return controllerutil.SetControllerReference(tc, cr, r.Scheme)
	}); err != nil {
		return fmt.Errorf("ClusterRole: %w", err)
	}

	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: ManagedObjectMeta(AgentClusterRoleBindingName(tc.Name), "", ComponentAgent, agentLabels),
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, crb, func() error {
		crb.Labels = mergeLabels(crb.Labels, agentLabels)
		crb.RoleRef = rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     AgentClusterRoleName(tc.Name),
		}
		crb.Subjects = []rbacv1.Subject{{
			Kind:      rbacv1.ServiceAccountKind,
			Name:      AgentServiceAccountName(tc.Name),
			Namespace: systemNS,
		}}
		return controllerutil.SetControllerReference(tc, crb, r.Scheme)
	}); err != nil {
		return fmt.Errorf("ClusterRoleBinding: %w", err)
	}

	role := &rbacv1.Role{
		ObjectMeta: ManagedObjectMeta(AgentBundleRoleName(tc.Name), systemNS, ComponentAgent, agentLabels),
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, role, func() error {
		role.Labels = mergeLabels(role.Labels, agentLabels)
		role.Rules = []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"configmaps", "secrets"},
			Verbs:     []string{"get", "list", "watch"},
		}}
		return controllerutil.SetControllerReference(tc, role, r.Scheme)
	}); err != nil {
		return fmt.Errorf("agent bundle Role: %w", err)
	}

	rb := &rbacv1.RoleBinding{
		ObjectMeta: ManagedObjectMeta(AgentBundleRoleBindingName(tc.Name), systemNS, ComponentAgent, agentLabels),
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, rb, func() error {
		rb.Labels = mergeLabels(rb.Labels, agentLabels)
		rb.RoleRef = rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     AgentBundleRoleName(tc.Name),
		}
		rb.Subjects = []rbacv1.Subject{{
			Kind:      rbacv1.ServiceAccountKind,
			Name:      AgentServiceAccountName(tc.Name),
			Namespace: systemNS,
		}}
		return controllerutil.SetControllerReference(tc, rb, r.Scheme)
	}); err != nil {
		return fmt.Errorf("agent bundle RoleBinding: %w", err)
	}
	return nil
}

// agentObjectLabels is the label set every agent-owned object carries.
// reconciledMessageFor renders the Reconciled condition's message, calling out
// configuration the operator accepted but did not act on.
// btfBlobProblem reports why the blob a TracerConfig names cannot be loaded, or
// "" when there is nothing to say.
func (r *TracerConfigReconciler) btfBlobProblem(ctx context.Context, tc *podtracev1alpha1.TracerConfig, systemNS string) string {
	if tc == nil || tc.Spec.BTFMode != podtracev1alpha1.BTFModeFile {
		return ""
	}
	src := tc.Spec.BTFSource
	if src == nil || src.ConfigMap == nil || src.ConfigMap.Name == "" {
		return ""
	}

	key := src.ConfigMap.Key
	if key == "" {
		key = podtracev1alpha1.DefaultBTFConfigMapKey
	}

	var cm corev1.ConfigMap
	err := r.Get(ctx, types.NamespacedName{Namespace: systemNS, Name: src.ConfigMap.Name}, &cm)
	if apierrors.IsNotFound(err) {
		return fmt.Sprintf("ConfigMap %s/%s does not exist, so no agent can start",
			systemNS, src.ConfigMap.Name)
	}
	if err != nil {
		return ""
	}
	if _, ok := cm.BinaryData[key]; ok {
		return ""
	}
	if _, ok := cm.Data[key]; ok {
		return ""
	}
	return fmt.Sprintf("ConfigMap %s/%s has no key %q", systemNS, src.ConfigMap.Name, key)
}

func reconciledMessageFor(tc *podtracev1alpha1.TracerConfig, blobProblem string) string {
	msg := "agent infrastructure reconciled"
	if tc == nil {
		return msg
	}
	switch tc.Spec.BTFMode {
	case podtracev1alpha1.BTFModeEmbedded:
		msg += "; spec.btfMode=embedded is deprecated and was ignored, the agent " +
			"resolves BTF from the host as it does for \"auto\" -- use btfMode=file " +
			"with spec.btfSource to supply a blob"
	case podtracev1alpha1.BTFModeFile:
		if env, _, _ := btfFileWiring(tc); len(env) > 0 {
			if blobProblem != "" {
				msg += "; spec.btfMode=file names a blob that cannot be loaded: " + blobProblem
				break
			}
			msg += "; spec.btfMode=file, the agent loads BTF from " + btfSourceDescription(tc.Spec.BTFSource)
		} else {
			msg += "; spec.btfMode=file but spec.btfSource names no usable blob, so the " +
				"agent resolves BTF from the host as it does for \"auto\" -- on a node " +
				"without host BTF that means stub types and no working CO-RE"
		}
	}
	return msg
}

// btfSourceDescription names where a supplied blob comes from, so the
// condition says what was acted on rather than only that something was.
func btfSourceDescription(src *podtracev1alpha1.BTFSource) string {
	switch {
	case src == nil:
		return "an unset source"
	case src.ConfigMap != nil:
		key := src.ConfigMap.Key
		if key == "" {
			key = podtracev1alpha1.DefaultBTFConfigMapKey
		}
		return "ConfigMap " + src.ConfigMap.Name + " key " + key
	case src.HostPath != "":
		return "host path " + src.HostPath
	default:
		return "an unset source"
	}
}

func agentObjectLabels(tracerConfigName string) map[string]string {
	return map[string]string{
		LabelManagedBy:    ManagedByValue,
		LabelComponent:    ComponentAgent,
		LabelTracerConfig: tracerConfigName,
	}
}

// validateTracerConfigName rejects names that cannot round-trip through the
// podtrace.io/tracer-config label on the agent DaemonSet's pod selector.
func validateTracerConfigName(name string) error {
	if len(name) > podtracev1alpha1.MaxTracerConfigNameLength {
		return fmt.Errorf(
			"metadata.name is %d characters; TracerConfig names are limited to %d because the name becomes the value of the %s label on the agent DaemonSet's immutable pod selector, and Kubernetes caps label values at %d characters",
			len(name), podtracev1alpha1.MaxTracerConfigNameLength,
			LabelTracerConfig, podtracev1alpha1.MaxTracerConfigNameLength)
	}
	return nil
}

// cleanupStaleAgentObjects deletes this fleet's agent DaemonSet (and its
// namespaced RBAC companions) left behind in OTHER namespaces after a
// spec.systemNamespace change.
func (r *TracerConfigReconciler) cleanupStaleAgentObjects(ctx context.Context, tracerConfigName, currentNS string) error {
	for _, selector := range staleAgentSelectors(tracerConfigName) {
		if err := r.deleteAgentObjectsOutsideNamespace(ctx, selector, currentNS); err != nil {
			return err
		}
	}
	return nil
}

// staleAgentSelectors lists the label selectors that identify objects this
// fleet is responsible for cleaning up.
func staleAgentSelectors(tracerConfigName string) []client.ListOption {
	selectors := []client.ListOption{client.MatchingLabels{
		LabelManagedBy:    ManagedByValue,
		LabelComponent:    ComponentAgent,
		LabelTracerConfig: tracerConfigName,
	}}
	if tracerConfigName != DefaultTracerConfigName {
		return selectors
	}

	managedBy, err := labels.NewRequirement(LabelManagedBy, selection.Equals, []string{ManagedByValue})
	if err != nil {
		return selectors
	}
	component, err := labels.NewRequirement(LabelComponent, selection.Equals, []string{ComponentAgent})
	if err != nil {
		return selectors
	}
	unlabelled, err := labels.NewRequirement(LabelTracerConfig, selection.DoesNotExist, nil)
	if err != nil {
		return selectors
	}
	return append(selectors, client.MatchingLabelsSelector{
		Selector: labels.NewSelector().Add(*managedBy, *component, *unlabelled),
	})
}

// deleteAgentObjectsOutsideNamespace deletes every agent object matching
// selector that does not live in keepNS.
func (r *TracerConfigReconciler) deleteAgentObjectsOutsideNamespace(ctx context.Context, selector client.ListOption, keepNS string) error {
	lists := []struct {
		kind string
		list client.ObjectList
		each func(client.ObjectList) []client.Object
	}{
		{"DaemonSet", &appsv1.DaemonSetList{}, func(l client.ObjectList) []client.Object {
			items := l.(*appsv1.DaemonSetList).Items
			out := make([]client.Object, 0, len(items))
			for i := range items {
				out = append(out, &items[i])
			}
			return out
		}},
		{"ServiceAccount", &corev1.ServiceAccountList{}, func(l client.ObjectList) []client.Object {
			items := l.(*corev1.ServiceAccountList).Items
			out := make([]client.Object, 0, len(items))
			for i := range items {
				out = append(out, &items[i])
			}
			return out
		}},
		{"Role", &rbacv1.RoleList{}, func(l client.ObjectList) []client.Object {
			items := l.(*rbacv1.RoleList).Items
			out := make([]client.Object, 0, len(items))
			for i := range items {
				out = append(out, &items[i])
			}
			return out
		}},
		{"RoleBinding", &rbacv1.RoleBindingList{}, func(l client.ObjectList) []client.Object {
			items := l.(*rbacv1.RoleBindingList).Items
			out := make([]client.Object, 0, len(items))
			for i := range items {
				out = append(out, &items[i])
			}
			return out
		}},
	}

	for _, entry := range lists {
		if err := r.List(ctx, entry.list, selector); err != nil {
			return fmt.Errorf("list agent %ss: %w", entry.kind, err)
		}
		for _, obj := range entry.each(entry.list) {
			if obj.GetNamespace() == keepNS {
				continue
			}
			if err := r.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("delete stale agent %s %s/%s: %w",
					entry.kind, obj.GetNamespace(), obj.GetName(), err)
			}
		}
	}
	return nil
}

// ensureAgentDaemonSet creates / updates the DaemonSet, returning its
// current status so Reconcile can roll it up.
func (r *TracerConfigReconciler) ensureAgentDaemonSet(ctx context.Context, tc *podtracev1alpha1.TracerConfig, systemNS, webhookHash string) (*appsv1.DaemonSet, error) {
	ds := &appsv1.DaemonSet{
		ObjectMeta: ManagedObjectMeta(AgentDaemonSetName(tc.Name), systemNS, ComponentAgent, agentObjectLabels(tc.Name)),
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, ds, func() error {
		ds.Labels = mergeLabels(ds.Labels, agentObjectLabels(tc.Name))
		ds.Spec = buildAgentDaemonSetSpec(tc, systemNS)
		if webhookHash != "" {
			ds.Spec.Template.Annotations = mergeLabels(ds.Spec.Template.Annotations,
				map[string]string{AnnotationAlertWebhookHash: webhookHash})
		}
		return controllerutil.SetControllerReference(tc, ds, r.Scheme)
	}); err != nil {
		return nil, err
	}
	return ds, nil
}

func agentClusterRoleRules(systemNS string) []rbacv1.PolicyRule {
	_ = systemNS
	return []rbacv1.PolicyRule{
		{
			APIGroups: []string{"podtrace.io"},
			Resources: []string{"podtraces"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"podtrace.io"},
			Resources: []string{"podtraces/status"},
			Verbs:     []string{"get", "update", "patch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"events"},
			Verbs:     []string{"create", "patch"},
		},
		{
			APIGroups: []string{"discovery.k8s.io"},
			Resources: []string{"endpointslices"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"services"},
			Verbs:     []string{"get", "list", "watch"},
		},
	}
}

// setCondition applies one Condition to the TracerConfig status, keyed
// by Type.
func (r *TracerConfigReconciler) setCondition(tc *podtracev1alpha1.TracerConfig, condType string, status metav1.ConditionStatus, reason, message string) {
	tc.Status.Conditions = upsertCondition(tc.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
		ObservedGeneration: tc.Generation,
	})
}
