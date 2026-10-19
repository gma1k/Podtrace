package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/ebpf/probes"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/operator"
	"github.com/gma1k/podtrace/internal/podworkload"
	"github.com/gma1k/podtrace/internal/sysfs"
	bundlepkg "github.com/gma1k/podtrace/pkg/exporter/bundle"
	"github.com/gma1k/podtrace/pkg/tracer"
)

// AgentReconciler is the single controller the agent runs.
type AgentReconciler struct {
	client.Client
	NodeName        string
	SystemNamespace string
	Router          *Router
	Metrics         *Metrics

	ControllerName string

	TargetsCh chan tracer.TargetSet

	ExporterBuilder func(payload *BundlePayload, crKey CRKey) (tracer.Exporter, error)

	CgroupResolver func(pods []*corev1.Pod) (map[uint64]struct{}, error)

	PodAttributor func(pods []*corev1.Pod) []PodCgroupEntry

	Enricher *PodEnricher

	CategoryGate func(categories []string) error

	MetricsPlane MetricsPlaneConfig

	WorkloadMetrics metricProducer

	Delivery *deliveryHealth

	exporterCacheMu sync.Mutex
	exporterCache   map[CRKey]cachedExporter
	pendingClose    []tracer.Exporter
}

const exporterCloseTimeout = 15 * time.Second

type cachedExporter struct {
	bundleRV string
	exporter tracer.Exporter
	buildErr error
}

// SetupWithManager registers the reconciler onto the manager with all
// four watched sources.
func (r *AgentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.ExporterBuilder == nil {
		metrics := r.Metrics
		pushers := newMetricPusherPool(r.WorkloadMetrics, r.NodeName)
		r.ExporterBuilder = func(b *BundlePayload, key CRKey) (tracer.Exporter, error) {
			return BuildExporter(b, key, withMetrics(metrics), withMetricPushers(pushers), withDeliveryHealth(r.Delivery))
		}
	}
	if r.CgroupResolver == nil {
		r.CgroupResolver = resolveCgroupIDs
	}
	if r.PodAttributor == nil {
		r.PodAttributor = scanPodCgroups
	}
	r.exporterCache = map[CRKey]cachedExporter{}

	name := r.ControllerName
	if name == "" {
		name = "agent"
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		For(&podtracev1alpha1.PodTrace{}).
		Watches(&corev1.Pod{},
			handler.EnqueueRequestsFromMapFunc(r.enqueueAllPodTraces),
			builder.WithPredicates(podChangePredicates()),
		).
		Watches(&corev1.ConfigMap{},
			handler.EnqueueRequestsFromMapFunc(r.enqueueOnBundleChange),
		).
		Watches(&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.enqueueOnBundleChange),
		).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Complete(r)
}

// Reconcile rebuilds the full router rule set.
func (r *AgentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := ctrllog.FromContext(ctx).WithName("agent").WithValues("nudged_by", req.String())

	if r.Metrics != nil {
		r.Metrics.ReconcileTotal.Inc()
	}

	var ptList podtracev1alpha1.PodTraceList
	if err := r.List(ctx, &ptList); err != nil {
		return ctrl.Result{}, fmt.Errorf("list PodTrace: %w", err)
	}
	var pods corev1.PodList
	if err := r.List(ctx, &pods); err != nil {
		return ctrl.Result{}, fmt.Errorf("list Pods: %w", err)
	}
	localPods := make([]*corev1.Pod, 0, len(pods.Items))
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Spec.NodeName == r.NodeName {
			localPods = append(localPods, p)
		}
	}

	rules := make([]CRRule, 0, len(ptList.Items))
	activeKeys := make(map[CRKey]struct{}, len(ptList.Items))

	for i := range ptList.Items {
		pt := &ptList.Items[i]
		if pt.Spec.Paused {
			continue
		}
		key := CRKey{Namespace: pt.Namespace, Name: pt.Name}

		bundle, err := LoadBundle(ctx, r.Client, r.SystemNamespace, pt.UID)
		if err != nil {
			if apierrors.IsNotFound(err) {
				logger.V(1).Info("bundle not yet synced", "cr", key)
				continue
			}
			logger.Error(err, "load bundle", "cr", key)
			rules = append(rules, CRRule{
				Key:        key,
				Filters:    filtersToSet(pt.Spec.Filters),
				Categories: filterCategories(pt.Spec.Filters),
				Err:        fmt.Errorf("load bundle: %w", err),
			})
			activeKeys[key] = struct{}{}
			continue
		}

		matched, err := MatchPodTraceAgainstPods(pt, localPods, bundle.TargetNamespaces)
		if err != nil {
			logger.Error(err, "match pods", "cr", key)
			rules = append(rules, CRRule{
				Key:        key,
				Categories: filterCategories(pt.Spec.Filters),
				Err:        fmt.Errorf("match pods: %w", err),
			})
			activeKeys[key] = struct{}{}
			continue
		}
		if len(matched) == 0 {
			r.releaseExporter(key)
			continue
		}

		policy := policySnapshotFromBundle(bundle)

		cgroupIDs, err := r.CgroupResolver(matched)
		if err != nil {
			logger.Error(err, "resolve cgroup IDs", "cr", key)
			rules = append(rules, CRRule{
				Key:         key,
				Filters:     filtersToSet(pt.Spec.Filters),
				Categories:  filterCategories(pt.Spec.Filters),
				Policy:      policy,
				MatchedPods: lenToInt32(len(matched)),
				Err:         fmt.Errorf("resolve cgroup IDs: %w", err),
			})
			activeKeys[key] = struct{}{}
			continue
		}

		exporter, err := r.obtainExporter(key, bundle)
		r.Metrics.ObserveExporterInit(key, err)
		if exporter != nil && err != nil {
			logger.V(1).Info("exporter built with a non-fatal error", "cr", key, "error", err)
		}
		if exporter == nil && err != nil {
			logger.V(1).Info("build exporter (tombstoned on CR)", "cr", key, "error", err)
			rules = append(rules, CRRule{
				Key:            key,
				CgroupIDs:      cgroupIDs,
				Filters:        filtersToSet(pt.Spec.Filters),
				Categories:     filterCategories(pt.Spec.Filters),
				Policy:         policy,
				BundleRevision: bundle.ResourceVer,
				MatchedPods:    lenToInt32(len(matched)),
				Err:            fmt.Errorf("build exporter: %w", err),
			})
			activeKeys[key] = struct{}{}
			continue
		}

		rules = append(rules, CRRule{
			Key:            key,
			CgroupIDs:      cgroupIDs,
			Filters:        filtersToSet(pt.Spec.Filters),
			Categories:     filterCategories(pt.Spec.Filters),
			Policy:         policy,
			Exporter:       exporter,
			BundleRevision: bundle.ResourceVer,
			MatchedPods:    lenToInt32(len(matched)),
		})
		activeKeys[key] = struct{}{}
	}

	r.reapStaleExporters(activeKeys)

	var podEntries []PodCgroupEntry
	if r.PodAttributor != nil {
		podEntries = r.PodAttributor(localPods)
	}
	if r.Enricher != nil {
		r.Enricher.Snapshot(podEntries)
	}

	drain := r.Router.Publish(rules)

	drain.Wait()
	r.closeDisplacedExporters()

	if r.CategoryGate != nil {
		categories := unionCategories(unionCategoriesFromRules(rules), r.MetricsPlane)
		if err := r.CategoryGate(categories); err != nil {
			logger.V(1).Info("category gate apply failed",
				"error", err, "categories", categories)
		}
	}

	targets := buildTargetSet(rules, localPods, podEntries)
	targets = expandTargetsForMetricsPlane(targets, podEntries, r.MetricsPlane)
	select {
	case r.TargetsCh <- targets:
	default:
		select {
		case <-r.TargetsCh:
		default:
		}
		select {
		case r.TargetsCh <- targets:
		default:
		}
	}

	if r.Metrics != nil {
		r.Metrics.RefreshFromRouter(r.Router)
		r.Metrics.RefreshFromEnricher(r.Enricher)
	}

	return ctrl.Result{}, nil
}

func (r *AgentReconciler) enqueueAllPodTraces(ctx context.Context, _ client.Object) []reconcile.Request {
	var list podtracev1alpha1.PodTraceList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}
	out := make([]reconcile.Request, 0, len(list.Items)+1)
	for _, pt := range list.Items {
		out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{
			Namespace: pt.Namespace,
			Name:      pt.Name,
		}})
	}
	if r.MetricsPlane.Enabled {
		out = append(out, metricsPlaneRequest)
	}
	return out
}

// enqueueOnBundleChange handles the ConfigMap and Secret bundle watches:
// only bundle objects (with our managed-by + exporter-bundle labels)
// produce reconcile requests, and each such event enqueues every
// PodTrace.
func (r *AgentReconciler) enqueueOnBundleChange(ctx context.Context, obj client.Object) []reconcile.Request {
	if obj.GetLabels()[operator.LabelManagedBy] != operator.ManagedByValue {
		return nil
	}
	if obj.GetLabels()[operator.LabelComponent] != operator.ComponentBundle {
		return nil
	}
	return r.enqueueAllPodTraces(ctx, obj)
}

// obtainExporter returns the cached Exporter for this CR if the
// bundle ResourceVersion is unchanged, otherwise builds a new one and
// closes the stale entry.
func (r *AgentReconciler) obtainExporter(key CRKey, bundle *BundlePayload) (tracer.Exporter, error) {
	r.exporterCacheMu.Lock()
	defer r.exporterCacheMu.Unlock()

	if entry, ok := r.exporterCache[key]; ok {
		if entry.bundleRV == bundle.ResourceVer {
			return entry.exporter, entry.buildErr
		}
		if entry.exporter != nil {
			r.pendingClose = append(r.pendingClose, entry.exporter)
		}
		delete(r.exporterCache, key)
	}
	exporter, err := r.ExporterBuilder(bundle, key)
	if exporter == nil && err != nil {
		return nil, err
	}
	r.exporterCache[key] = cachedExporter{
		bundleRV: bundle.ResourceVer,
		exporter: exporter,
		buildErr: err,
	}
	return exporter, err
}

// releaseExporter closes and removes the cached exporter for key.
func (r *AgentReconciler) releaseExporter(key CRKey) {
	r.exporterCacheMu.Lock()
	defer r.exporterCacheMu.Unlock()
	entry, ok := r.exporterCache[key]
	delete(r.exporterCache, key)
	if ok && entry.exporter != nil {
		r.pendingClose = append(r.pendingClose, entry.exporter)
	}
}

// closeDisplacedExporters drains the pendingClose accumulator and closes
// each exporter on a background goroutine with a bounded context.
func (r *AgentReconciler) closeDisplacedExporters() {
	r.exporterCacheMu.Lock()
	displaced := r.pendingClose
	r.pendingClose = nil
	r.exporterCacheMu.Unlock()
	if len(displaced) == 0 {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), exporterCloseTimeout)
		defer cancel()
		for _, e := range displaced {
			_ = e.Close(ctx)
		}
	}()
}

// reapStaleExporters closes exporters whose CR keys did not appear in
// the active set this reconcile. Prevents leak when a CR is deleted.
func (r *AgentReconciler) reapStaleExporters(active map[CRKey]struct{}) {
	r.exporterCacheMu.Lock()
	var stale []CRKey
	for k := range r.exporterCache {
		if _, ok := active[k]; !ok {
			stale = append(stale, k)
		}
	}
	r.exporterCacheMu.Unlock()
	for _, k := range stale {
		r.releaseExporter(k)
	}
}

// resolveCgroupIDs maps each matched pod's cgroup path to its inode
// number — the value the kernel stamps on every event.
func resolveCgroupIDs(pods []*corev1.Pod) (map[uint64]struct{}, error) {
	entries := scanPodCgroups(pods)
	out := make(map[uint64]struct{}, len(entries))
	for _, e := range entries {
		out[e.CgroupID] = struct{}{}
	}
	if len(pods) > 0 && len(out) == 0 {
		return out, fmt.Errorf("no cgroups resolved for %d matched pod(s)", len(pods))
	}
	return out, nil
}

// scanPodCgroups walks the kubepods hierarchy once and emits one
// PodCgroupEntry per (cgroup inode, pod, container) tuple.
func scanPodCgroups(pods []*corev1.Pod) []PodCgroupEntry {
	root := discoverKubepodsRoot()
	if root == "" {
		return nil
	}
	out := make([]PodCgroupEntry, 0, len(pods))
	for _, p := range pods {
		path := cgroupPathForPod(p, root)
		if path == "" {
			continue
		}
		if id, err := cgroupIDFromPath(path); err == nil {
			out = append(out, PodCgroupEntry{
				CgroupID:   id,
				CgroupPath: path,
				Pod:        p,
			})
		}
		dirEntries, err := os.ReadDir(path)
		if err != nil {
			continue
		}
		statuses := containerStatusIndex(p)
		for _, e := range dirEntries {
			if !e.IsDir() {
				continue
			}
			child := filepath.Join(path, e.Name())
			id, err := cgroupIDFromPath(child)
			if err != nil {
				continue
			}
			containerName, containerID := identifyContainerCgroup(e.Name(), statuses)
			out = append(out, PodCgroupEntry{
				CgroupID:      id,
				CgroupPath:    child,
				Pod:           p,
				ContainerName: containerName,
				ContainerID:   containerID,
				ContainerPID:  mainPIDFromCgroupProcs(child),
			})
		}
	}
	return out
}

// containerStatusIndex builds a containerID-prefix to container-name
// lookup table from pod.status.containerStatuses.
func containerStatusIndex(p *corev1.Pod) map[string]string {
	out := map[string]string{}
	add := func(name, rawID string) {
		if name == "" || rawID == "" {
			return
		}
		if i := strings.Index(rawID, "://"); i >= 0 {
			rawID = rawID[i+3:]
		}
		if rawID == "" {
			return
		}
		out[rawID] = name
	}
	for _, cs := range p.Status.ContainerStatuses {
		add(cs.Name, cs.ContainerID)
	}
	for _, cs := range p.Status.InitContainerStatuses {
		add(cs.Name, cs.ContainerID)
	}
	for _, cs := range p.Status.EphemeralContainerStatuses {
		add(cs.Name, cs.ContainerID)
	}
	return out
}

// identifyContainerCgroup matches a container cgroup dir (e.g.
// "cri-containerd-<id>.scope", "crio-<id>.scope", "docker-<id>.scope")
// against the pod's containerStatuses index.
func identifyContainerCgroup(dir string, statuses map[string]string) (name, id string) {
	if len(statuses) == 0 {
		return "", ""
	}
	trimmed := strings.TrimSuffix(dir, ".scope")
	for _, prefix := range []string{"cri-containerd-", "crio-", "docker-", "containerd-"} {
		if strings.HasPrefix(trimmed, prefix) {
			trimmed = strings.TrimPrefix(trimmed, prefix)
			break
		}
	}
	if trimmed == "" {
		return "", ""
	}
	if cname, ok := statuses[trimmed]; ok {
		return cname, trimmed
	}
	bestName, bestID := "", ""
	for cid, cname := range statuses {
		if !strings.HasPrefix(cid, trimmed) && !strings.HasPrefix(trimmed, cid) {
			continue
		}
		if len(cid) > len(bestID) || (len(cid) == len(bestID) && cid < bestID) {
			bestName, bestID = cname, cid
		}
	}
	return bestName, bestID
}

var processStartTimeOf = probes.ProcessStartTime

// mainPIDFromCgroupProcs returns the container's main host PID, or 0 if
// none/unreadable. The main process is the earliest started one: the lowest
// PID is not reliable once PIDs wrap or an exec probe / kubectl exec child
// lands in the cgroup with a smaller number, and picking such a short-lived
// child would point uprobe targets at the wrong binary.
func mainPIDFromCgroupProcs(cgroupDir string) uint32 {
	rel, ok := sysfs.CgroupRelative(cgroupDir)
	if !ok {
		return 0
	}
	data, err := sysfs.CgroupReadFile(filepath.Join(rel, "cgroup.procs"))
	if err != nil {
		return 0
	}
	var main uint32
	var mainStarted uint64
	mainTimed := false
	for _, f := range strings.Fields(string(data)) {
		parsed, err := strconv.ParseUint(f, 10, 32)
		if err != nil || parsed == 0 {
			continue
		}
		pid := uint32(parsed)
		started, timed := processStartTimeOf(pid)
		switch {
		case main == 0:
		case timed && !mainTimed:
		case timed && mainTimed && (started < mainStarted || (started == mainStarted && pid < main)):
		case !timed && !mainTimed && pid < main:
		default:
			continue
		}
		main, mainStarted, mainTimed = pid, started, timed
	}
	return main
}

var kubepodsRootOverride string

// discoverKubepodsRoot returns the first kubepods root that exists on this
// node.
func discoverKubepodsRoot() string {
	if kubepodsRootOverride != "" {
		if _, err := os.Stat(kubepodsRootOverride); err != nil {
			return ""
		}
		return kubepodsRootOverride
	}
	return probes.KubepodsRoot()
}

// cgroupPathForPod composes the per-pod cgroup directory under a
// discovered root.
func cgroupPathForPod(p *corev1.Pod, root string) string {
	if root == "" {
		return ""
	}
	uidDash := string(p.UID)
	uidUnder := strings.ReplaceAll(uidDash, "-", "_")
	qos := strings.ToLower(string(p.Status.QOSClass))
	if qos == "" {
		qos = "besteffort"
	}

	leaf := filepath.Base(root)
	prefix := strings.TrimSuffix(leaf, ".slice")

	candidates := []string{
		filepath.Join(root,
			prefix+"-"+qos+".slice",
			prefix+"-"+qos+"-pod"+uidUnder+".slice",
		),
		filepath.Join(root,
			prefix+"-pod"+uidUnder+".slice",
		),
		filepath.Join(root, qos, "pod"+uidDash),
		filepath.Join(root, "pod"+uidDash),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// cgroupIDFromPath returns the inode of a cgroup path — the ID the
// kernel exposes on eBPF events.
func cgroupIDFromPath(path string) (uint64, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return cgroupIDFromInfo(path, st)
}

// cgroupIDFromInfo reads the inode out of a stat result.
func cgroupIDFromInfo(path string, st os.FileInfo) (uint64, error) {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys == nil {
		return 0, fmt.Errorf("unsupported stat type for %s", path)
	}
	return sys.Ino, nil
}

// buildTargetSet turns the active rule set into a tracer.TargetSet,
// using the pre-computed pod-cgroup attribution so that container,
// owner-kind, and owner-name fields are populated alongside the
// pod-level identifiers.
func buildTargetSet(rules []CRRule, pods []*corev1.Pod, podEntries []PodCgroupEntry) tracer.TargetSet {
	byCgroup := make(map[uint64]PodCgroupEntry, len(podEntries))
	for _, e := range podEntries {
		if existing, ok := byCgroup[e.CgroupID]; !ok || (existing.ContainerName == "" && e.ContainerName != "") {
			byCgroup[e.CgroupID] = e
		}
	}

	seen := map[uint64]struct{}{}
	var out tracer.TargetSet

	for _, rule := range rules {
		for id := range rule.CgroupIDs {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			if entry, ok := byCgroup[id]; ok {
				kind, name := podworkload.Of(entry.Pod)
				out = append(out, tracer.Target{
					PodName:       entry.Pod.Name,
					Namespace:     entry.Pod.Namespace,
					ContainerID:   entry.ContainerID,
					ContainerName: entry.ContainerName,
					ContainerPID:  entry.ContainerPID,
					CgroupPath:    entry.CgroupPath,
					Labels:        copyMap(entry.Pod.Labels),
					PodIP:         entry.Pod.Status.PodIP,
					OwnerKind:     kind,
					OwnerName:     name,
				})
				continue
			}
			fallbackLegacyTarget(&out, pods, id)
		}
	}
	return out
}

// fallbackLegacyTarget reproduces the pre-enrichment buildTargetSet
// walk for callers that did not populate PodAttributor.
func fallbackLegacyTarget(out *tracer.TargetSet, pods []*corev1.Pod, id uint64) {
	root := discoverKubepodsRoot()
	for _, p := range pods {
		path := cgroupPathForPod(p, root)
		if path == "" {
			continue
		}
		pid, err := cgroupIDFromPath(path)
		if err != nil || pid != id {
			continue
		}
		*out = append(*out, tracer.Target{
			PodName:    p.Name,
			Namespace:  p.Namespace,
			CgroupPath: path,
			Labels:     copyMap(p.Labels),
			PodIP:      p.Status.PodIP,
		})
		return
	}
}

// policySnapshotFromBundle lifts the policy fields off a BundlePayload
// into the PolicySnapshot the router and exporters consume.
func policySnapshotFromBundle(b *BundlePayload) PolicySnapshot {
	out := PolicySnapshot{
		Hash:       bundlePolicyHash(b),
		Generation: bundlePolicyGeneration(b),
	}
	if b == nil {
		return out
	}
	if b.Sample != nil {
		pct := int32(*b.Sample*100 + 0.5)
		out.EffectiveSamplePercent = &pct
	}
	if len(b.Filters) > 0 {
		filters := make([]string, 0, len(b.Filters))
		for _, f := range b.Filters {
			filters = append(filters, string(f))
		}
		out.Filters = filters
	}
	if !b.Thresholds.IsZero() {
		t := PolicyThresholds{}
		if b.Thresholds.ErrorRatePercent != nil {
			v := *b.Thresholds.ErrorRatePercent
			t.ErrorRatePercent = &v
		}
		if b.Thresholds.RTTSpikeMs != nil {
			v := *b.Thresholds.RTTSpikeMs
			t.RTTSpikeMs = &v
		}
		if b.Thresholds.FilesystemLatencyMs != nil {
			v := *b.Thresholds.FilesystemLatencyMs
			t.FilesystemLatencyMs = &v
		}
		out.Thresholds = &t
	}
	return out
}

// bundlePolicyHash returns a stable hash over the policy fields of a
// BundlePayload, equivalent to the operator-stamped policy_hash key.
func bundlePolicyHash(b *BundlePayload) string {
	if b == nil {
		return ""
	}
	return bundlepkg.PolicyHash(b)
}

func bundlePolicyGeneration(b *BundlePayload) int64 {
	if b == nil {
		return 0
	}
	return b.PolicyGeneration
}

// unionCategoriesFromRules returns the sorted, deduplicated union of
// CRD-filter category strings (dns/net/fs/cpu/proc/crypto) across every active
// CRRule.
func unionCategoriesFromRules(rules []CRRule) []string {
	seen := make(map[string]struct{}, len(rules))
	for _, r := range rules {
		if r.Err != nil {
			continue
		}
		if len(r.Categories) == 0 {
			for _, c := range knownFilterCategories() {
				seen[c] = struct{}{}
			}
			break
		}
		for _, c := range r.Categories {
			seen[c] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// filterCategories renders the CR's spec.filters as plain category
// strings, preserving order.
func filterCategories(in []podtracev1alpha1.EventFilter) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, f := range in {
		out = append(out, string(f))
	}
	return out
}

// knownFilterCategories returns the canonical list of CRD filter
// category strings, in stable order.
func knownFilterCategories() []string {
	return []string{
		string(podtracev1alpha1.FilterDNS),
		string(podtracev1alpha1.FilterNet),
		string(podtracev1alpha1.FilterFS),
		string(podtracev1alpha1.FilterCPU),
		string(podtracev1alpha1.FilterProc),
		string(podtracev1alpha1.FilterCrypto),
		string(podtracev1alpha1.FilterUSDT),
	}
}

// filtersToSet converts the CRD's EventFilter list into the
// EventType-keyed set the router needs.
func filtersToSet(in []podtracev1alpha1.EventFilter) map[events.EventType]struct{} {
	out := map[events.EventType]struct{}{}
	for _, f := range in {
		for _, et := range filterToEventTypes(f) {
			out[et] = struct{}{}
		}
	}
	return out
}

// filterToEventTypes expands a high-level filter category into the set
// of low-level EventType values the tracer produces for that category.
func filterToEventTypes(f podtracev1alpha1.EventFilter) []events.EventType {
	switch f {
	case podtracev1alpha1.FilterDNS:
		return []events.EventType{events.EventDNS, events.EventDNSQuery}
	case podtracev1alpha1.FilterNet:
		return []events.EventType{
			events.EventConnect, events.EventTCPSend, events.EventTCPRecv,
			events.EventUDPSend, events.EventUDPRecv, events.EventTCPState,
			events.EventTCPRetrans, events.EventNetDevError, events.EventTCPRTT,
			events.EventConnectResult,
			events.EventFastCGIReq, events.EventFastCGIResp,
			events.EventHTTPReq, events.EventHTTPResp,
			events.EventGRPCMethod, events.EventHTTP3,
		}
	case podtracev1alpha1.FilterFS:
		return []events.EventType{
			events.EventOpen, events.EventClose, events.EventRead,
			events.EventWrite, events.EventFsync,
			events.EventUnlink, events.EventRename,
		}
	case podtracev1alpha1.FilterCPU:
		return []events.EventType{events.EventSchedSwitch, events.EventLockContention}
	case podtracev1alpha1.FilterProc:
		return []events.EventType{events.EventExec, events.EventFork, events.EventOOMKill}
	case podtracev1alpha1.FilterCrypto:
		return []events.EventType{events.EventAFALG}
	case podtracev1alpha1.FilterUSDT:
		return []events.EventType{events.EventUSDT}
	default:
		return nil
	}
}

// copyMap returns a defensive shallow copy of a string map.
func copyMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// podChangePredicates filters Pod watches down to events that actually
// affect matching or cgroup attribution: label changes (selector
// matching), phase changes (Running-ness), PodIP assignment (event
// enrichment), container restarts (each restart creates a new cgroup
// inode that must be re-resolved), and deletions.
func podChangePredicates() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc:  func(e event.CreateEvent) bool { return true },
		DeleteFunc:  func(e event.DeleteEvent) bool { return true },
		GenericFunc: func(e event.GenericEvent) bool { return false },
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldP, ok1 := e.ObjectOld.(*corev1.Pod)
			newP, ok2 := e.ObjectNew.(*corev1.Pod)
			if !ok1 || !ok2 {
				return false
			}
			if oldP.Status.Phase != newP.Status.Phase {
				return true
			}
			if !labelsEqual(oldP.Labels, newP.Labels) {
				return true
			}
			if oldP.Status.PodIP != newP.Status.PodIP {
				return true
			}
			if !containerIdentitiesEqual(oldP, newP) {
				return true
			}
			return false
		},
	}
}

// containerIdentitiesEqual reports whether every container in the pod
// kept its container ID and restart count across the update.
func containerIdentitiesEqual(oldP, newP *corev1.Pod) bool {
	digest := func(p *corev1.Pod) map[string]string {
		out := make(map[string]string,
			len(p.Status.ContainerStatuses)+len(p.Status.InitContainerStatuses)+len(p.Status.EphemeralContainerStatuses))
		add := func(statuses []corev1.ContainerStatus) {
			for _, cs := range statuses {
				out[cs.Name] = fmt.Sprintf("%s/%d", cs.ContainerID, cs.RestartCount)
			}
		}
		add(p.Status.ContainerStatuses)
		add(p.Status.InitContainerStatuses)
		add(p.Status.EphemeralContainerStatuses)
		return out
	}
	return labelsEqual(digest(oldP), digest(newP))
}

func labelsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
