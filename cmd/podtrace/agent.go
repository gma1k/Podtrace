package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/gma1k/podtrace/internal/agent"
	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/ebpf"
	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/ebpf/oncpu"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/pkg/tracer"
)

const (
	backendModeReal = "real"
	backendModeNoop = "noop"
)

// agentOptions holds flags for `podtrace agent`. Defaults mirror
// agent.DefaultOptions; the toAgentOptions translation keeps the Cobra
// surface authoritative for flag names.
type agentOptions struct {
	systemNamespace      string
	tracerConfigName     string
	nodeName             string
	metricsAddr          string
	healthAddr           string
	inspectAddr          string
	statusReportInterval time.Duration
	backendMode          string
}

func newAgentCmd() *cobra.Command {
	opts := &agentOptions{}

	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Run podtrace as a per-node agent driven by PodTrace CRDs (DaemonSet mode)",
		Long: `Agent mode runs podtrace as a long-lived per-node DaemonSet process that
watches PodTrace custom resources and feeds matching pods into the local
tracer. Multiple PodTrace CRs targeting the same node are merged into a
single tracer instance (one set of cgroups, union of filters, per-CR
exporter routing).`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := ctrl.SetupSignalHandler()
			resolved, err := toAgentOptions(opts)
			if err != nil {
				return err
			}
			return agent.Run(ctx, resolved)
		},
	}

	cmd.Flags().StringVar(&opts.systemNamespace, "system-namespace", "podtrace-system",
		"Namespace where exporter bundles live (maintained by the operator)")
	cmd.Flags().StringVar(&opts.tracerConfigName, "tracer-config", "default",
		"Name of the cluster-scoped TracerConfig resource to observe")
	cmd.Flags().StringVar(&opts.nodeName, "node-name", "",
		"Name of the node this agent runs on (defaults to $NODE_NAME or hostname)")
	cmd.Flags().StringVar(&opts.metricsAddr, "metrics-addr", ":9090",
		"Address for the Prometheus metrics endpoint")
	cmd.Flags().StringVar(&opts.healthAddr, "health-addr", ":9091",
		"Address for liveness/readiness probes")
	cmd.Flags().StringVar(&opts.inspectAddr, "inspect-addr", ":9092",
		"Address for /issues and /profile; the same as --metrics-addr serves them alongside /metrics")
	cmd.Flags().DurationVar(&opts.statusReportInterval, "status-report-interval", 0,
		"How often to patch PodTrace.status.nodeStatus (default: 30s)")
	cmd.Flags().StringVar(&opts.backendMode, "backend", backendModeReal,
		"Tracer backend mode: 'real' loads the eBPF program (production); 'noop' skips kernel attachment and exercises only the control plane (dev/kind smoke tests)")

	return cmd
}

// toAgentOptions translates the Cobra flag struct into agent.Options
// and resolves $NODE_NAME / hostname fallbacks.
func toAgentOptions(c *agentOptions) (agent.Options, error) {
	node := c.nodeName
	if node == "" {
		node = agent.ResolveNodeName()
	}
	if node == "" {
		return agent.Options{}, errors.New("node name: set --node-name, export NODE_NAME, or run where /etc/hostname is readable")
	}
	factory, err := selectBackendFactory(c.backendMode)
	if err != nil {
		return agent.Options{}, err
	}
	return agent.Options{
		NodeName:             node,
		SystemNamespace:      c.systemNamespace,
		TracerConfigName:     c.tracerConfigName,
		MetricsAddr:          c.metricsAddr,
		HealthAddr:           c.healthAddr,
		InspectAddr:          c.inspectAddr,
		StatusReportInterval: c.statusReportInterval,
		BackendFactory:       factory,
	}, nil
}

// selectBackendFactory returns the TracerBackend factory the CLI will
// inject into agent.Options.
func selectBackendFactory(mode string) (func() (tracer.TracerBackend, error), error) {
	switch mode {
	case backendModeReal, "":
		return agentBackendFactory, nil
	case backendModeNoop:
		return noopBackendFactory, nil
	default:
		return nil, fmt.Errorf("invalid --backend %q (must be %q or %q)", mode, backendModeReal, backendModeNoop)
	}
}

func agentBackendFactory() (tracer.TracerBackend, error) {
	tr, err := ebpf.NewTracer(ebpf.WithInitialCategories(
		agent.StartupCategories(agent.NodeCoverage(config.WorkloadMetricsEnabled,
			config.ContinuousProfilingEnabled, config.WorkloadMetricsExcludedNamespaces)),
	))
	if err != nil {
		return nil, err
	}
	if deny, ok := tr.(interface{ SetDenyWhenNoTargets(bool) }); ok {
		deny.SetDenyWhenNoTargets(true)
	}
	return &ebpfBackendAdapter{tr: tr}, nil
}

// ebpfBackendAdapter narrows the internal eBPF tracer interface
// (path-list cgroup contract) to the pkg/tracer.TracerBackend contract
// (CgroupTarget snapshot).
type ebpfBackendAdapter struct {
	tr ebpf.TracerInterface
}

func (a *ebpfBackendAdapter) SetCgroups(targets []tracer.CgroupTarget) error {
	paths := make([]string, 0, len(targets))
	owners := make(map[string]ebpf.CgroupOwner, len(targets))
	for _, t := range targets {
		if t.CgroupPath == "" {
			continue
		}
		paths = append(paths, t.CgroupPath)
		if t.PodName != "" && t.Namespace != "" {
			owners[t.CgroupPath] = ebpf.CgroupOwner{PodName: t.PodName, Namespace: t.Namespace}
		}
	}
	setTracerCgroupOwners(a.tr, owners)
	return a.tr.SetCgroups(paths)
}

func (a *ebpfBackendAdapter) AttachToCgroup(path string) error {
	return a.tr.AttachToCgroup(path)
}

func (a *ebpfBackendAdapter) SetContainerID(id string) error {
	return a.tr.SetContainerID(id)
}

// SetContainerTargets implements the optional pkg/tracer.ContainerUprobeReconciler
// interface: it hands the eBPF tracer the full set of currently-targeted
// containers so it can attach newly-seen containers' uprobes and detach
// departed ones.
func (a *ebpfBackendAdapter) SetContainerTargets(targets []tracer.ContainerUprobeTarget) error {
	conv := make([]ebpf.ContainerProbeTarget, 0, len(targets))
	for _, t := range targets {
		ct := ebpf.ContainerProbeTarget{ID: t.ContainerID}
		if t.PID != 0 {
			ct.PIDs = []uint32{t.PID}
		}
		conv = append(conv, ct)
	}
	return a.tr.SetContainerTargets(conv)
}

func (a *ebpfBackendAdapter) Start(ctx context.Context, ch chan<- *events.Event) error {
	return a.tr.Start(ctx, ch)
}

func (a *ebpfBackendAdapter) Stop() error {
	return a.tr.Stop()
}

// SetEnabledCategories implements the optional pkg/tracer.CategoryGateable
// interface by delegating to the eBPF tracer's runtime probe-group gate.
func (a *ebpfBackendAdapter) SetEnabledCategories(categories []string) error {
	type categoryGateable interface {
		SetEnabledCategories([]string) error
	}
	g, ok := a.tr.(categoryGateable)
	if !ok {
		return nil
	}
	return g.SetEnabledCategories(categories)
}

// InheritedCgroupParent exposes the tracer's record of container cgroups the
// kernel started tracing because they were created under a targeted pod.
func (a *ebpfBackendAdapter) InheritedCgroupParent(id uint64) (uint64, bool) {
	r, ok := a.tr.(interface {
		InheritedCgroupParent(uint64) (uint64, bool)
	})
	if !ok {
		return 0, false
	}
	return r.InheritedCgroupParent(id)
}

func noopBackendFactory() (tracer.TracerBackend, error) {
	return agent.NewNoopBackend(), nil
}

// kernelAggCapable is the slice of the eBPF tracer the metrics plane needs.
// Declared here rather than imported so the adapter stays a narrowing layer.
type kernelAggCapable interface {
	SetKernelAggregationMode(mode kernelagg.Mode) error
	DrainKernelMetrics() ([]kernelagg.Row, error)
}

// ErrNoKernelAggregation reports a backend that cannot fold metrics in the
// kernel, a noop backend, or one built without the aggregation maps.
var ErrNoKernelAggregation = errors.New("backend does not support kernel aggregation")

func (a *ebpfBackendAdapter) SetKernelAggregationMode(mode kernelagg.Mode) error {
	agg, ok := a.tr.(kernelAggCapable)
	if !ok {
		return ErrNoKernelAggregation
	}
	return agg.SetKernelAggregationMode(mode)
}

func (a *ebpfBackendAdapter) DrainKernelMetrics() ([]kernelagg.Row, error) {
	agg, ok := a.tr.(kernelAggCapable)
	if !ok {
		return nil, ErrNoKernelAggregation
	}
	return agg.DrainKernelMetrics()
}

// onCPUCapable is the slice of the eBPF tracer the continuous profiler's
// on-CPU source needs.
type onCPUCapable interface {
	StartOnCPUSampler() (int, error)
	DrainOnCPUSamples() (oncpu.Drained, error)
}

// ErrNoOnCPUSampler reports a backend that cannot run the on-CPU sampler.
var ErrNoOnCPUSampler = errors.New("backend does not support the on-CPU sampler")

func (a *ebpfBackendAdapter) StartOnCPUSampler() (int, error) {
	s, ok := a.tr.(onCPUCapable)
	if !ok {
		return 0, ErrNoOnCPUSampler
	}
	return s.StartOnCPUSampler()
}

func (a *ebpfBackendAdapter) DrainOnCPUSamples() (oncpu.Drained, error) {
	s, ok := a.tr.(onCPUCapable)
	if !ok {
		return oncpu.Drained{}, ErrNoOnCPUSampler
	}
	return s.DrainOnCPUSamples()
}
