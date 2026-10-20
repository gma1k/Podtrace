package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/diagnose/stacktrace"
	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/ebpf/oncpu"
	"github.com/gma1k/podtrace/internal/ebpf/probes"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/inspect"
	"github.com/gma1k/podtrace/internal/profiling"
	"github.com/gma1k/podtrace/internal/tracing"
	"github.com/gma1k/podtrace/internal/workloadmetrics"
	"github.com/gma1k/podtrace/pkg/tracer"
)

// attachMetricsObserver bridges probes.AttachObserver into the
// per-program metric.
type attachMetricsObserver struct {
	metrics *Metrics
}

func (a *attachMetricsObserver) OnAttachFailure(program, symbol string, mandatory bool, err error) {
	if a == nil || a.metrics == nil {
		return
	}
	a.metrics.RecordProgramAttachFailure(program, tracer.ClassifyBackendError(err))
}

// Options configure a single agent run. Defaults are applied by
// DefaultOptions.
type Options struct {
	NodeName string

	SystemNamespace string

	TracerConfigName string

	MetricsAddr string
	HealthAddr  string

	InspectAddr string

	StatusReportInterval time.Duration

	BackendFactory func() (tracer.TracerBackend, error)

	RestConfig *rest.Config
}

// DefaultOptions returns production defaults.
func DefaultOptions() Options {
	return Options{
		MetricsAddr: ":9090",
		HealthAddr:  ":9091",
		InspectAddr: ":9092",
	}
}

// Run boots the per-node agent and blocks until ctx is cancelled.
// Returns nil on clean shutdown, otherwise the first terminal error.
func Run(ctx context.Context, opts Options) error {
	if err := opts.validate(); err != nil {
		return err
	}
	ctrl.SetLogger(zap.New(zap.UseDevMode(false)))
	logger := ctrllog.Log.WithName("agent").
		WithValues("node", opts.NodeName, "tracerConfig", opts.TracerConfigName)

	if alertManager, mErr := alerting.NewManager(); mErr != nil {
		logger.Error(mErr, "failed to create alert manager; resource alerts disabled")
	} else if alertManager != nil {
		alerting.SetGlobalManager(alertManager)
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), config.ShutdownTimeout)
			defer cancel()
			_ = alertManager.Shutdown(shutdownCtx)
		}()
		logger.Info("alert manager initialized", "enabled", alertManager.IsEnabled())
	}

	scheme, err := newAgentScheme()
	if err != nil {
		return err
	}

	restConfig := opts.RestConfig
	if restConfig == nil {
		restConfig = ctrl.GetConfigOrDie()
	}

	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme:         scheme,
		LeaderElection: false,
		Cache: cache.Options{
			ByObject: map[client.Object]cache.ByObject{
				&corev1.Pod{}: {
					Field: fields.OneTermEqualSelector("spec.nodeName", opts.NodeName),
				},
				&corev1.ConfigMap{}: {
					Namespaces: map[string]cache.Config{opts.SystemNamespace: {}},
				},
				&corev1.Secret{}: {
					Namespaces: map[string]cache.Config{opts.SystemNamespace: {}},
				},
				&discoveryv1.EndpointSlice{}: {
					Transform: trimEndpointSlice,
				},
				&corev1.Service{}: {
					Transform: trimService,
				},
			},
		},
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
	if err != nil {
		return fmt.Errorf("build manager: %w", err)
	}

	if config.AlertingEnabled && config.AlertEventsEnabled {
		if am := alerting.GetGlobalManager(); am != nil {
			am.EnsureEnabledWithSender(newAlertEventSender(mgr.GetClient()))
			logger.Info("kubernetes-event alert sink enabled (flight recorder trigger source)")
		}
	}

	stats := newPerCRStats()
	enricher := NewPodEnricher()
	router := NewRouter(stats).WithEnricher(enricher)
	probeSrv := NewProbeServer(opts.HealthAddr, StallWindowFor(opts.StatusReportInterval))
	metrics := NewMetrics()
	metrics.SetIdentity(opts.NodeName, opts.TracerConfigName)

	probes.SetAttachObserver(&attachMetricsObserver{metrics: metrics})

	backend, backendErr := buildBackend(opts, logger)
	followRestartedContainers(backend, router, enricher)
	if backendErr != nil {
		reason := tracer.ClassifyBackendError(backendErr)
		logger.Error(backendErr, "tracer backend unavailable — running in degraded noop mode",
			"reason", reason)
		metrics.BackendDegraded.WithLabelValues(reason).Set(1)
		probeSrv.MarkDegraded(reason)
	}

	var peers *PeerResolver
	if config.WorkloadMetricsEnabled {
		if err := RegisterPeerIndex(ctx, mgr); err != nil {
			logger.Error(err, "service-map peer index unavailable; edges will not be recorded")
		} else {
			peers = NewPeerResolver(clusterPeerLookup(mgr.GetCache()))
		}
	}

	exporters, metricsSink, profiler, expErr := buildExporters(router, metrics, enricher, peers, logger)
	if expErr != nil {
		return expErr
	}
	engine, err := tracer.NewEngine(backend, exporters, tracer.Config{
		Observer: metrics.EngineObserver(),
	})
	if err != nil {
		return fmt.Errorf("build tracer engine: %w", err)
	}

	targetsCh := make(chan tracer.TargetSet, 8)

	delivery := newDeliveryHealth()
	reconciler := &AgentReconciler{
		Client:          mgr.GetClient(),
		NodeName:        opts.NodeName,
		SystemNamespace: opts.SystemNamespace,
		Router:          router,
		TargetsCh:       targetsCh,
		Metrics:         metrics,
		Enricher:        enricher,
		CategoryGate:    makeCategoryGate(backend),
		MetricsPlane: NodeCoverage(config.WorkloadMetricsEnabled, config.ContinuousProfilingEnabled,
			config.WorkloadMetricsExcludedNamespaces),
		WorkloadMetrics: workloadMetricProducer(metricsSink),
		Delivery:        delivery,
	}
	if err := reconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup reconciler: %w", err)
	}

	writer := &StatusWriter{
		Client:        mgr.GetClient(),
		NodeName:      opts.NodeName,
		Interval:      opts.StatusReportInterval,
		Router:        router,
		Ready:         probeSrv.IsReady,
		Heartbeat:     probeSrv.Heartbeat,
		KernelDropped: metrics.KernelDroppedTotal,
		BackendErr:    backendErr,
		Delivery:      delivery,
	}

	inspections := startInspectionEngine(metrics, metricsSink,
		enricherPodResolver(enricher), newAlertEventSender(mgr.GetClient()), logger)

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error { return mgr.Start(gctx) })
	g.Go(func() error { return engine.Run(gctx, targetsCh) })
	g.Go(func() error { return writer.Run(gctx) })
	g.Go(func() error { return probeSrv.Run(gctx) })
	for _, serve := range httpServers(opts, metrics, profiler, inspections, logger) {
		g.Go(func() error { return serve(gctx) })
	}
	g.Go(func() error { return reapWorkloadMetrics(gctx, metricsSink, logger) })
	g.Go(func() error { return drainKernelMetrics(gctx, backend, metricsSink, router, metrics, logger) })
	g.Go(func() error { return drainOnCPUSamples(gctx, backend, profiler, metrics, logger) })
	g.Go(func() error { return refreshMetrics(gctx, metricsRefreshInterval, metrics, router, enricher) })

	g.Go(func() error { return runInspections(gctx, inspections, logger) })

	g.Go(func() error {
		if err := cacheSyncError(mgr.GetCache().WaitForCacheSync(gctx), gctx.Err()); err != nil {
			return err
		}
		probeSrv.MarkReady()
		logger.Info("agent ready")
		return nil
	})

	err = g.Wait()
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// cacheSyncError decides whether a cache that stopped syncing is a
// failure.
func cacheSyncError(synced bool, ctxErr error) error {
	if synced || ctxErr != nil {
		return nil
	}
	return errors.New("informer cache sync failed")
}

func (o *Options) validate() error {
	if o.NodeName == "" {
		return errors.New("agent: NodeName is required (set $NODE_NAME via downward API)")
	}
	if o.SystemNamespace == "" {
		return errors.New("agent: SystemNamespace is required")
	}
	if o.TracerConfigName == "" {
		o.TracerConfigName = "default"
	}
	return nil
}

func newAgentScheme() (*runtime.Scheme, error) {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(podtracev1alpha1.AddToScheme(s))
	return s, nil
}

// buildBackend returns the TracerBackend for the agent.
func buildBackend(opts Options, logger logr.Logger) (tracer.TracerBackend, error) {
	if opts.BackendFactory == nil {
		logger.Info("no BackendFactory supplied — using noop backend (library/test mode; production binaries always set this)")
		return newNoopBackend(), nil
	}
	backend, err := opts.BackendFactory()
	if err != nil {
		return newNoopBackend(), err
	}
	logger.Info("tracer backend ready", "backend", fmt.Sprintf("%T", backend))
	return backend, nil
}

func newMetricsServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

// httpServers returns the agent's HTTP listeners: one for /metrics and one
// for /issues and /profile, or a single one serving all three when both
// addresses are the same.
func httpServers(opts Options, metrics *Metrics, profiler *profiling.ContinuousProfiler, inspections *inspect.Engine, logger logr.Logger) []func(context.Context) error {
	if opts.InspectAddr == opts.MetricsAddr {
		return []func(context.Context) error{func(ctx context.Context) error {
			return serveHTTP(ctx, "metrics and inspection", opts.MetricsAddr, combinedMux(metrics, profiler, inspections), logger)
		}}
	}
	return []func(context.Context) error{
		func(ctx context.Context) error { return serveMetrics(ctx, opts.MetricsAddr, metrics, logger) },
		func(ctx context.Context) error {
			return serveInspect(ctx, opts.InspectAddr, profiler, inspections, logger)
		},
	}
}

// serveMetrics exposes the agent's Prometheus registry on the
// metrics-addr port. Short-circuit when the address is empty — useful
// in tests.
func serveMetrics(ctx context.Context, addr string, metrics *Metrics, logger logr.Logger) error {
	return serveHTTP(ctx, "metrics", addr, metricsMux(metrics), logger)
}

// serveInspect exposes /issues and /profile on the inspect-addr port.
func serveInspect(ctx context.Context, addr string, profiler *profiling.ContinuousProfiler, inspections *inspect.Engine, logger logr.Logger) error {
	mux := http.NewServeMux()
	registerInspectHandlers(mux, profiler, inspections)
	return serveHTTP(ctx, "inspection", addr, mux, logger)
}

func metricsMux(metrics *Metrics) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/metrics", metrics.Handler())
	return mux
}

func combinedMux(metrics *Metrics, profiler *profiling.ContinuousProfiler, inspections *inspect.Engine) *http.ServeMux {
	mux := metricsMux(metrics)
	registerInspectHandlers(mux, profiler, inspections)
	return mux
}

func registerInspectHandlers(mux *http.ServeMux, profiler *profiling.ContinuousProfiler, inspections *inspect.Engine) {
	mux.HandleFunc("/issues", issuesHandler(inspections))
	if profiler != nil {
		mux.HandleFunc("/profile", profileHandler(profiler))
	}
}

func serveHTTP(ctx context.Context, name, addr string, handler http.Handler, logger logr.Logger) error {
	if addr == "" || addr == "0" {
		return nil
	}
	ln, err := listenMetrics("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	srv := newMetricsServer(handler)
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	logger.Info("starting "+name+" server", "addr", addr)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// workloadMetricProducer wraps the plane in the Prometheus-to-OTLP
// producer the metric pusher reads.
func workloadMetricProducer(sink *workloadmetrics.Sink) metricProducer {
	if sink == nil {
		return nil
	}
	return workloadmetrics.NewProducer(sink)
}

func peerLookup(r *PeerResolver) func(string, uint16) (workloadmetrics.PeerIdentity, bool) {
	if r == nil {
		return nil
	}
	return r.Resolve
}

// buildExporters assembles the engine's fan-out list.
func buildExporters(router *Router, metrics *Metrics, enricher *PodEnricher, peers *PeerResolver, logger logr.Logger) ([]tracer.Exporter, *workloadmetrics.Sink, *profiling.ContinuousProfiler, error) {
	exporters := []tracer.Exporter{router}

	var profiler *profiling.ContinuousProfiler
	if config.ContinuousProfilingEnabled {
		profiler = profiling.NewContinuousProfiler(func() profiling.FrameResolver { return stacktrace.NewResolver() },
			enricherLookup(enricher))
		exporters = append(exporters, profiler)
		logger.Info("continuous profiling enabled",
			"source", "sched_switch user stacks until the on-CPU sampler starts",
			"endpoint", "/profile")
	}

	if !config.WorkloadMetricsEnabled {
		return exporters, nil, profiler, nil
	}

	sink, err := workloadmetrics.New(metrics.Registerer(), workloadmetrics.Options{
		SeriesBudget:         config.WorkloadMetricsBudget,
		NativeHistograms:     config.WorkloadMetricsNativeHistograms,
		IncludePodLabel:      config.WorkloadMetricsPodLabel,
		IncludeProcessLabel:  config.WorkloadMetricsProcessLabel,
		Lookup:               enricherLookup(enricher),
		TraceContext:         tracing.NewContextEnricher().Enrich,
		ResolvePeer:          peerLookup(peers),
		SemanticConventions:  config.WorkloadMetricsSemanticConv,
		AttributeCardinality: config.WorkloadMetricsAttributeLimit,
		KernelAggregation:    config.WorkloadMetricsKernelAggregation,
		DNSPacketCapture:     config.DNSPacketCaptureEnabled(),
		ExcludeNamespaces:    config.WorkloadMetricsExcludedNamespaces,
		OnBudgetExhausted: func(budget int) {
			logger.Error(nil, "continuous metrics series budget exhausted; new series are being refused",
				"seriesBudget", budget,
				"remedy", "raise TracerConfig.spec.agent.metrics.seriesBudget or add excludeNamespaces",
				"metric", "podtrace_workload_metrics_series_dropped_total")
		},
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("build workload metrics plane: %w", err)
	}

	logger.Info("continuous workload metrics enabled",
		"seriesBudget", config.WorkloadMetricsBudget,
		"nativeHistograms", config.WorkloadMetricsNativeHistograms,
		"kernelAggregation", config.WorkloadMetricsKernelAggregation)
	logDNSCoverage(logger, config.DNSPacketCaptureEnabled())
	return append(exporters, sink), sink, profiler, nil
}

// logDNSCoverage says, once, what DNS the plane cannot see.
func logDNSCoverage(logger logr.Logger, packetCapture bool) {
	if packetCapture {
		return
	}
	logger.Info("DNS packet capture is off: DNS lookups are read from libc's getaddrinfo, "+
		"gethostbyname and gethostbyname2 only, so a program that resolves on its own, "+
		"such as busybox or Go's pure-Go resolver, is not seen",
		"remedy", "leave TracerConfig.spec.agent.dnsPacketCapture on to count every query on the wire")
}

// drainKernelMetrics folds the kernel's aggregation map into the sink on an
// interval, which is what makes the plane cost O(series) instead of O(events).
func drainKernelMetrics(ctx context.Context, backend tracer.TracerBackend, sink *workloadmetrics.Sink, router *Router, metrics *Metrics, logger logr.Logger) error {
	if sink == nil || !config.WorkloadMetricsKernelAggregation {
		return nil
	}
	aggregator, ok := backend.(tracer.KernelAggregator)
	if !ok {
		logger.Info("kernel aggregation requested but the backend does not support it; " +
			"metrics continue on the event path")
		return nil
	}
	if err := aggregator.SetKernelAggregationMode(kernelagg.ModeOn); err != nil {
		logger.Info("kernel aggregation unavailable on this backend; metrics continue on the event path",
			"reason", err.Error())
		return nil
	}

	modeFor := func(hasRules bool) kernelagg.Mode {
		if hasRules {
			return kernelagg.ModeOn
		}
		return kernelagg.ModeBypass
	}
	applyMode := func(hasRules bool) {
		mode := modeFor(hasRules)
		if err := aggregator.SetKernelAggregationMode(mode); err != nil {
			logger.Error(err, "could not set kernel aggregation mode", "mode", mode.String())
			return
		}
		logger.V(1).Info("kernel aggregation mode set", "mode", mode.String())
	}
	if router != nil {
		router.OnRulesChanged(applyMode)
		applyMode(router.HasRules())
	} else {
		applyMode(false)
	}
	logger.Info("kernel metric aggregation enabled",
		"drainInterval", config.WorkloadMetricsDrainInterval)

	ticker := time.NewTicker(config.WorkloadMetricsDrainInterval)
	defer ticker.Stop()
	drain := func() {
		rows, err := aggregator.DrainKernelMetrics()
		if err != nil {
			logger.Error(err, "draining the kernel aggregation map failed")
			metrics.RecordKernelDrainFailure()
			return
		}
		applied := sink.IngestKernel(rows)
		metrics.RecordKernelDrain(len(rows), applied)
		metrics.RecordKernelDrainTime(time.Now(), config.WorkloadMetricsDrainInterval)
		if len(rows) > 0 {
			logger.V(1).Info("drained kernel metric rows", "rows", len(rows), "applied", applied)
		}
	}
	for {
		select {
		case <-ctx.Done():
			drain()
			_ = aggregator.SetKernelAggregationMode(kernelagg.ModeOff)
			return nil
		case <-ticker.C:
			drain()
		}
	}
}

var onCPUDrainInterval = 5 * time.Second

// drainOnCPUSamples starts the fixed-rate on-CPU sampler and feeds what it
// counts to the continuous profiler. Where it cannot start, the profiler keeps
// the sched_switch stacks it already reads, and says so in its profile.
func drainOnCPUSamples(ctx context.Context, backend tracer.TracerBackend, profiler *profiling.ContinuousProfiler, metrics *Metrics, logger logr.Logger) error {
	if profiler == nil {
		return nil
	}
	sampler, ok := backend.(tracer.OnCPUSampler)
	if !ok {
		logger.Info("the backend cannot run the on-CPU sampler; continuous profiling stays on sched_switch stacks")
		return nil
	}
	cpus, err := sampler.StartOnCPUSampler()
	if err != nil {
		logger.Info("on-CPU sampler unavailable; continuous profiling stays on sched_switch stacks",
			"reason", err.Error())
		metrics.RecordOnCPUSampler(0)
		return nil
	}
	metrics.RecordOnCPUSampler(cpus)
	logger.Info("on-CPU sampler started", "cpus", cpus, "hz", oncpu.SampleHz,
		"drainInterval", onCPUDrainInterval)

	ticker := time.NewTicker(onCPUDrainInterval)
	defer ticker.Stop()
	drain := func() {
		d, err := sampler.DrainOnCPUSamples()
		if err != nil {
			logger.Error(err, "draining the on-CPU sampler failed")
			metrics.RecordOnCPUDrainFailure()
			return
		}
		profiler.IngestOnCPU(d)
		metrics.RecordOnCPUDrain(d)
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			drain()
		}
	}
}

// reapWorkloadMetrics periodically drops series whose workload stopped
// being observed, so the per-node budget is spent on what is running
// rather than on what used to run.
func reapWorkloadMetrics(ctx context.Context, sink *workloadmetrics.Sink, logger logr.Logger) error {
	if sink == nil {
		return nil
	}
	ticker := time.NewTicker(config.WorkloadMetricsReapInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if n := sink.Reap(config.WorkloadMetricsSeriesTTL); n > 0 {
				logger.V(1).Info("reaped idle workload metric series",
					"removed", n, "idleFor", config.WorkloadMetricsSeriesTTL)
			}
		}
	}
}

// followRestartedContainers gives the router and the enricher the backend's
// record of container cgroups created under targeted pods, when it keeps one.
func followRestartedContainers(backend tracer.TracerBackend, router *Router, enricher *PodEnricher) {
	r, ok := backend.(interface {
		InheritedCgroupParent(uint64) (uint64, bool)
	})
	if !ok {
		return
	}
	router.FollowRestartedContainers(r.InheritedCgroupParent)
	enricher.FollowRestartedContainers(r.InheritedCgroupParent)
}

func enricherLookup(e *PodEnricher) func(uint64) (events.K8sMetadata, bool) {
	if e == nil {
		return nil
	}
	return e.Lookup
}

// makeCategoryGate returns a closure suitable for
// AgentReconciler.CategoryGate.
func makeCategoryGate(backend tracer.TracerBackend) func(categories []string) error {
	if backend == nil {
		return nil
	}
	gate, ok := backend.(tracer.CategoryGateable)
	if !ok {
		return nil
	}
	return gate.SetEnabledCategories
}

// NoopBackend is the default TracerBackend when none is injected.
type NoopBackend struct {
	mu       sync.Mutex
	eventCh  chan<- *events.Event
	attached map[string]struct{}
}

func newNoopBackend() *NoopBackend {
	return &NoopBackend{attached: map[string]struct{}{}}
}

func NewNoopBackend() *NoopBackend {
	return newNoopBackend()
}

func (b *NoopBackend) AttachToCgroup(path string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.attached[path] = struct{}{}
	return nil
}

func (b *NoopBackend) SetCgroups(targets []tracer.CgroupTarget) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.attached = make(map[string]struct{}, len(targets))
	for _, t := range targets {
		if t.CgroupPath == "" {
			continue
		}
		b.attached[t.CgroupPath] = struct{}{}
	}
	return nil
}

func (b *NoopBackend) SetContainerID(_ string) error { return nil }

func (b *NoopBackend) Start(_ context.Context, ch chan<- *events.Event) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.eventCh = ch
	return nil
}

func (b *NoopBackend) Stop() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.eventCh = nil
	return nil
}

// Inject lets tests push synthetic events through the backend's
// channel.
func (b *NoopBackend) Inject(ev *events.Event) bool {
	b.mu.Lock()
	ch := b.eventCh
	b.mu.Unlock()
	if ch == nil {
		return false
	}
	ch <- ev
	return true
}

// listenMetrics and hostname are net.Listen and os.Hostname, replaceable so
// the failure paths that depend on them can be exercised.
var (
	listenMetrics = net.Listen
	hostname      = os.Hostname
)

func ResolveNodeName() string {
	if n := strings.TrimSpace(os.Getenv("NODE_NAME")); n != "" {
		return n
	}
	if h, err := hostname(); err == nil && h != "" {
		return h
	}
	return ""
}

// profileHandler serves the continuous CPU profile: hot functions as JSON by
// default, or whole stacks for a flame graph with ?format=folded or
// ?format=pprof. ?namespace= and ?workload= keep one workload, and
// ?requests=slow keeps only the stacks of the slowest requests.
func profileHandler(profiler *profiling.ContinuousProfiler) http.HandlerFunc {
	return newProfileGate(profileQueueWait).limit(renderProfile(profiler))
}

const profileQueueWait = 5 * time.Second

const profileRetryAfter = "5"

type profileGate struct {
	slot chan struct{}
	wait time.Duration
}

func newProfileGate(wait time.Duration) *profileGate {
	return &profileGate{slot: make(chan struct{}, 1), wait: wait}
}

func (g *profileGate) limit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		timer := time.NewTimer(g.wait)
		defer timer.Stop()
		select {
		case g.slot <- struct{}{}:
		case <-r.Context().Done():
			return
		case <-timer.C:
			w.Header().Set("Retry-After", profileRetryAfter)
			http.Error(w, "another profile is being rendered; retry shortly", http.StatusTooManyRequests)
			return
		}
		defer func() { <-g.slot }()
		next(w, r)
	}
}

func renderProfile(profiler *profiling.ContinuousProfiler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), config.ProfileSnapshotTimeout)
		defer cancel()

		q := r.URL.Query()
		sel := profiling.StackSelection{Namespace: q.Get("namespace"), Workload: q.Get("workload")}
		switch q.Get("requests") {
		case "", "all":
		case "slow":
			sel.SlowRequests = true
		default:
			http.Error(w, "requests must be all or slow", http.StatusBadRequest)
			return
		}

		switch q.Get("format") {
		case "", "json":
			if sel.SlowRequests {
				http.Error(w, "requests=slow needs format=folded or format=pprof; the JSON already carries slowRequests", http.StatusBadRequest)
				return
			}
			profiles := []profiling.WorkloadProfile{}
			for _, wp := range profiler.Snapshot(ctx) {
				if (sel.Namespace == "" || sel.Namespace == wp.Namespace) && (sel.Workload == "" || sel.Workload == wp.Workload) {
					profiles = append(profiles, wp)
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(struct {
				Source   profiling.ProfileSource     `json:"source"`
				Profiles []profiling.WorkloadProfile `json:"profiles"`
				Dropped  uint64                      `json:"droppedSamples"`
				Unjoined uint64                      `json:"unjoinedRequestSamples"`
			}{
				Source:   profiler.Source(),
				Profiles: profiles,
				Dropped:  profiler.Dropped(),
				Unjoined: profiler.Unjoined(),
			})
		case "folded":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_ = profiling.WriteFolded(w, profiler.Stacks(ctx, sel))
		case "pprof":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", `attachment; filename="profile.pb.gz"`)
			_ = profiling.WritePprof(w, profiler.Stacks(ctx, sel), profiler.Source() == profiling.SourceOnCPU)
		default:
			http.Error(w, "format must be json, folded or pprof", http.StatusBadRequest)
		}
	}
}
