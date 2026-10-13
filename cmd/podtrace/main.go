package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"k8s.io/klog/v2"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"strconv"

	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/diagnose"
	diagnosereport "github.com/gma1k/podtrace/internal/diagnose/report"
	"github.com/gma1k/podtrace/internal/ebpf"
	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	tracerpkg "github.com/gma1k/podtrace/internal/ebpf/tracer"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/kubernetes"
	"github.com/gma1k/podtrace/internal/kubernetes/nodespawn"
	"github.com/gma1k/podtrace/internal/logger"
	"github.com/gma1k/podtrace/internal/metricsexporter"
	"github.com/gma1k/podtrace/internal/profiling"
	"github.com/gma1k/podtrace/internal/system"
	"github.com/gma1k/podtrace/internal/tracing"
	"github.com/gma1k/podtrace/internal/validation"
)

var (
	namespace             string
	namespacesCSV         string
	podsCSV               string
	podSelector           string
	allInNamespace        bool
	diagnoseDuration      string
	enableMetrics         bool
	enableTracing         bool
	enableSynthesizeSpans bool
	exportFormat          string
	eventFilter           string
	containerName         string
	errorRateThreshold    float64
	rttSpikeThreshold     float64
	fsSlowThreshold       float64
	logLevel              string
	tracingOTLPEndpoint   string
	tracingJaegerEndpoint string
	tracingSplunkEndpoint string
	tracingSplunkToken    string
	tracingSampleRate     float64
	showVersion           bool
	enableProfiling       bool

	localMode             bool
	spawnImage            string
	spawnNamespace        string
	spawnServiceAccount   string
	dynamicSpawn          bool
	keepSpawnPodOnFailure bool
	spawnBTFFile          string
	preresolvedPods       []string

	exporterFromFile       string
	summaryFile            string
	terminationMessagePath string
	sessionDeadline        string
	sessionTrigger         diagnosereport.Trigger
	reportTo               string

	resolverFactory func() (kubernetes.PodResolverInterface, error)
	tracerFactory   func() (ebpf.TracerInterface, error)
	exitFunc        func(int)
)

func init() {
	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return kubernetes.NewPodResolver()
	}
	tracerFactory = func() (ebpf.TracerInterface, error) {
		return ebpf.NewTracer()
	}
	exitFunc = os.Exit

	klogFlags := flag.NewFlagSet("klog", flag.ContinueOnError)
	klog.InitFlags(klogFlags)
	_ = klogFlags.Set("logtostderr", "false")
	_ = klogFlags.Set("alsologtostderr", "false")
	_ = klogFlags.Set("stderrthreshold", "FATAL")
	_ = klogFlags.Set("v", "0")
	klog.SetOutput(io.Discard)
}

func main() {
	var rootCmd = &cobra.Command{
		Use:   "podtrace [flags] [pod-name]",
		Short: "eBPF-based troubleshooting tool for Kubernetes pods",
		Long:  `Podtrace attaches eBPF program to a Kubernetes pod's container and prints high-level, human-readable events that help diagnose application issues.`,
		Example: `  # Standalone:
  podtrace -n production my-pod

  # As a kubectl plugin (after kubectl krew install podtrace):
  kubectl podtrace -n production my-pod

  # Bounded diagnose with JSON export:
  podtrace -n production my-pod --diagnose 30s --export json > report.json

  # Multi-pod via label selector:
  podtrace -n production --pod-selector app=api`,
		Args:         cobra.MaximumNArgs(1),
		RunE:         runPodtrace,
		SilenceUsage: true,
	}

	rootCmd.AddCommand(newDiagnoseEnvCmd())
	rootCmd.AddCommand(newAgentCmd())
	rootCmd.AddCommand(newOperatorCmd())
	rootCmd.AddCommand(newReportUploaderCmd())
	rootCmd.AddCommand(newScheduleCmd())
	rootCmd.AddCommand(newWatchCmd())
	rootCmd.AddCommand(newMigrateStorageCmd())
	rootCmd.AddCommand(newStatusCmd())

	rootCmd.Flags().StringVarP(&namespace, "namespace", "n", config.DefaultNamespace, "Kubernetes namespace (defaults to the current kubeconfig context's namespace)")
	rootCmd.Flags().StringVar(&namespacesCSV, "namespaces", "", "Comma-separated namespaces for multi-pod tracing (e.g., default,prod)")
	rootCmd.Flags().StringVar(&podsCSV, "pods", "", "Comma-separated pod references to trace (pod or namespace/pod)")
	rootCmd.Flags().StringVar(&podSelector, "pod-selector", "", "Kubernetes label selector for target pods (e.g., app=api,team=payments)")
	rootCmd.Flags().BoolVar(&allInNamespace, "all-in-namespace", false, "Trace all pods in --namespace (or all --namespaces)")
	rootCmd.Flags().StringVar(&diagnoseDuration, "diagnose", "", "Run in diagnose mode for the specified duration (e.g., 10s, 5m)")
	rootCmd.Flags().BoolVar(&enableMetrics, "metrics", false, "Enable Prometheus metrics server")
	rootCmd.Flags().StringVar(&exportFormat, "export", "", "Export format for diagnose report (json, csv)")
	rootCmd.Flags().StringVar(&eventFilter, "filter", "", "Filter events by type (dns,net,fs,cpu,proc,crypto,usdt)")
	rootCmd.Flags().StringVar(&containerName, "container", "", "Container name to trace (default: all containers of the pod)")
	rootCmd.Flags().Float64Var(&errorRateThreshold, "error-threshold", config.DefaultErrorRateThreshold, "Error rate threshold percentage for issue detection")
	rootCmd.Flags().Float64Var(&rttSpikeThreshold, "rtt-threshold", config.DefaultRTTThreshold, "RTT spike threshold in milliseconds")
	rootCmd.Flags().Float64Var(&fsSlowThreshold, "fs-threshold", config.DefaultFSSlowThreshold, "File system slow operation threshold in milliseconds")
	rootCmd.Flags().StringVar(&logLevel, "log-level", "", "Set log level (debug, info, warn, error, fatal). Overrides PODTRACE_LOG_LEVEL environment variable")
	rootCmd.Flags().BoolVar(&enableTracing, "tracing", config.DefaultTracingEnabled, "Enable distributed tracing")
	rootCmd.Flags().StringVar(&tracingOTLPEndpoint, "tracing-otlp-endpoint", config.DefaultOTLPEndpoint, "OpenTelemetry OTLP endpoint")
	rootCmd.Flags().StringVar(&tracingJaegerEndpoint, "tracing-jaeger-endpoint", "", "Jaeger endpoint (opt-in; OTLP is the default exporter)")
	rootCmd.Flags().StringVar(&tracingSplunkEndpoint, "tracing-splunk-endpoint", "", "Splunk HEC endpoint (opt-in; requires --tracing-splunk-token)")
	rootCmd.Flags().StringVar(&tracingSplunkToken, "tracing-splunk-token", "", "Splunk HEC token")
	rootCmd.Flags().Float64Var(&tracingSampleRate, "tracing-sample-rate", config.DefaultTracingSampleRate, "Tracing sample rate (0.0-1.0)")
	rootCmd.Flags().BoolVar(&enableSynthesizeSpans, "tracing-synthesize-spans", config.DefaultSynthesizeSpans, "Mint spans for correlated L7 traffic (HTTP/gRPC) that carries no inbound W3C/B3 trace context (per-pod root spans)")
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", false, "Print version information")
	rootCmd.Flags().BoolVar(&enableProfiling, "profiling", false, "Enable performance profiling: pprof endpoint discovery on the target pod, auto-trigger on latency spikes, and CPU/memory correlation in reports")
	rootCmd.Flags().BoolVar(&localMode, "local", false, "Run eBPF on this workstation instead of spawning a privileged pod on the target node. Use for kind/minikube/docker-desktop where the workstation IS the kubelet host.")
	rootCmd.Flags().StringVar(&spawnImage, "image", "", "Container image used when spawning on the target node (overrides PODTRACE_IMAGE and the linker default)")
	rootCmd.Flags().StringVar(&spawnNamespace, "spawn-namespace", "", "Namespace for the ephemeral spawn pod (defaults to the target pod's namespace; overridable via PODTRACE_SPAWN_NAMESPACE)")
	rootCmd.Flags().BoolVar(&dynamicSpawn, "dynamic-spawn", false, "Continuously poll target selection and spawn additional pods on newly-matched nodes (incompatible with --diagnose; covers new nodes only, not new pods on already-covered nodes)")
	rootCmd.Flags().BoolVar(&keepSpawnPodOnFailure, "keep-spawn-pod", false, "On failure, leave the spawn pod in place so its logs and state can be inspected (the reaper still cleans it up on the next podtrace invocation)")
	rootCmd.Flags().StringVar(&spawnBTFFile, "btf-file", "", "Absolute path on the node to a BTF blob, for a kernel built without CONFIG_DEBUG_INFO_BTF. The CLI's equivalent of TracerConfig btfMode=file; see docs/crd-tracerconfig.md for how to produce one. Unnecessary when /sys/kernel/btf/vmlinux exists, which is nearly always")
	rootCmd.Flags().StringVar(&spawnServiceAccount, "service-account", "", "ServiceAccount the spawn pod runs as. Only required when --dynamic-spawn watches selector changes from inside the pod; otherwise the workstation pre-resolves everything and the spawn pod needs no RBAC.")
	rootCmd.Flags().StringSliceVar(&preresolvedPods, "preresolved-pod", nil, "internal: workstation pre-resolved target as ns/name/containerID/containerName, lets the spawn pod skip its own K8s lookup")
	_ = rootCmd.Flags().MarkHidden("preresolved-pod")
	rootCmd.Flags().StringVar(&exporterFromFile, "exporter-from-file", "", "Load exporter config from a YAML file (set by the operator for session Jobs)")
	_ = rootCmd.Flags().MarkHidden("exporter-from-file")
	rootCmd.Flags().StringVar(&summaryFile, "summary-file", "", "Write a JSON summary of diagnose results to this path when diagnose completes")
	rootCmd.Flags().StringVar(&terminationMessagePath, "termination-message-path", "", "Write a compact summary JSON to this path so Kubernetes surfaces it in pod status")
	rootCmd.Flags().StringVar(&sessionDeadline, "session-deadline", "", "When the session Job running this diagnose is killed (RFC 3339); collection stops early enough to write the report before it")
	_ = rootCmd.Flags().MarkHidden("session-deadline")
	rootCmd.Flags().StringVar(&sessionTrigger.IssueID, "trigger-issue", "", "internal: id of the issue that started this session; the report opens with it")
	rootCmd.Flags().StringVar(&sessionTrigger.Severity, "trigger-severity", "", "internal: severity of the issue that started this session")
	rootCmd.Flags().StringVar(&sessionTrigger.Pod, "trigger-pod", "", "internal: pod the issue that started this session was raised on")
	rootCmd.Flags().StringVar(&sessionTrigger.At, "trigger-at", "", "internal: when the issue that started this session fired")
	rootCmd.Flags().StringVar(&sessionTrigger.Reason, "trigger-reason", "", "internal: what the agent measured when the issue fired")
	for _, name := range []string{"trigger-issue", "trigger-severity", "trigger-pod", "trigger-at", "trigger-reason"} {
		_ = rootCmd.Flags().MarkHidden(name)
	}
	rootCmd.Flags().StringVar(&reportTo, "report-to", "", "Upload the full diagnose report to a sink: kind/namespace/name (kind is configmap|secret)")

	registerTargetFlags(rootCmd.Flags())

	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if logLevel != "" {
			logger.SetLevel(logLevel)
		}
	}

	err := rootCmd.Execute()
	logger.Sync()
	if err != nil {
		code := 1
		var exitErr *nodespawn.ExitError
		if errors.As(err, &exitErr) && exitErr.Code != 0 {
			code = exitErr.Code
		}
		exitFunc(code)
	}
}

// applyTracingFlags copies the --tracing-* flag values into the process-
// global config knobs.
func applyTracingFlags(cmd *cobra.Command) error {
	if config.TracingEnabled {
		enableTracing = true
	}
	if !enableTracing {
		return nil
	}
	config.TracingEnabled = true
	flags := cmd.Flags()
	if flags.Changed("tracing-otlp-endpoint") && tracingOTLPEndpoint != "" {
		config.OTLPEndpoint = tracingOTLPEndpoint
	}
	if flags.Changed("tracing-jaeger-endpoint") && tracingJaegerEndpoint != "" {
		config.JaegerEndpoint = tracingJaegerEndpoint
	}
	if flags.Changed("tracing-splunk-endpoint") && tracingSplunkEndpoint != "" {
		config.SplunkEndpoint = tracingSplunkEndpoint
	}
	if tracingSplunkToken != "" {
		config.SplunkToken = tracingSplunkToken
	}
	if flags.Changed("tracing-sample-rate") {
		if tracingSampleRate < 0.0 || tracingSampleRate > 1.0 {
			return fmt.Errorf("--tracing-sample-rate must be between 0.0 and 1.0, got %v", tracingSampleRate)
		}
		config.TracingSampleRate = tracingSampleRate
	}
	if flags.Changed("tracing-synthesize-spans") {
		config.SynthesizeSpans = enableSynthesizeSpans
	}
	return nil
}

const secondSignalGracePeriod = 3 * time.Second

func runPodtrace(cmd *cobra.Command, args []string) error {
	if showVersion {
		fmt.Println(config.GetVersion())
		return nil
	}

	if !cmd.Flags().Changed("namespace") {
		if ctxNamespace, ok := kubernetes.NamespaceFromContext(); ok {
			namespace = ctxNamespace
		}
	}

	if watchAppName != "" && len(watchLabels) > 0 {
		return fmt.Errorf("--app and --label are mutually exclusive")
	}
	if watchAppName != "" || len(watchLabels) > 0 {
		if podSelector != "" {
			return fmt.Errorf("--app/--label and --pod-selector are mutually exclusive; use one")
		}
		if len(watchLabels) > 1 {
			return fmt.Errorf("multiple --label selectors target an application; use 'podtrace watch --application' (a managed ApplicationTrace), not the ephemeral command")
		}
		if watchAppName != "" {
			podSelector = appNameLabel + "=" + watchAppName
		} else {
			podSelector = watchLabels[0]
		}
	}

	if exporterFromFile != "" {
		if err := applyExporterFromFile(exporterFromFile); err != nil {
			return fmt.Errorf("load --exporter-from-file: %w", err)
		}
	}

	if err := applyTracingFlags(cmd); err != nil {
		return err
	}

	alertManager, err := alerting.NewManager()
	if err != nil {
		logger.Warn("Failed to create alert manager", zap.Error(err))
	} else if alertManager != nil {
		alerting.SetGlobalManager(alertManager)
		defer func() {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), config.ShutdownTimeout)
			defer shutdownCancel()
			_ = alertManager.Shutdown(shutdownCtx)
		}()
	}

	var metricsServer *metricsexporter.Server
	if enableMetrics {
		metricsServer = metricsexporter.StartServer()
		defer metricsServer.Shutdown()
	}

	tracingManager, err := tracing.NewManager()
	if err != nil {
		logger.Warn("Failed to create tracing manager", zap.Error(err))
	} else if tracingManager != nil && enableTracing {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := tracingManager.Start(ctx); err != nil {
			logger.Warn("Failed to start tracing manager", zap.Error(err))
		} else {
			defer func() {
				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), config.ShutdownTimeout)
				defer shutdownCancel()
				_ = tracingManager.Shutdown(shutdownCtx)
			}()
		}
	}

	var argPodName string
	if len(args) > 0 {
		argPodName = strings.TrimSpace(args[0])
		if err := validation.ValidatePodName(argPodName); err != nil {
			return fmt.Errorf("invalid pod name: %w", err)
		}
	}

	if err := validation.ValidateNamespace(namespace); err != nil {
		return fmt.Errorf("invalid namespace: %w", err)
	}
	namespaces := parseCSV(namespacesCSV)
	for _, ns := range namespaces {
		if err := validation.ValidateNamespace(ns); err != nil {
			return fmt.Errorf("invalid namespace in --namespaces: %w", err)
		}
	}
	pods := parseCSV(podsCSV)
	if argPodName != "" {
		pods = append([]string{argPodName}, pods...)
	}
	if len(pods) == 0 && podSelector == "" && !allInNamespace && len(preresolvedPods) == 0 {
		return fmt.Errorf("target pod selection is required: pass <pod-name>, --pods, --pod-selector, or --all-in-namespace")
	}
	for _, p := range pods {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		name := p
		if strings.Contains(p, "/") {
			parts := strings.SplitN(p, "/", 2)
			if err := validation.ValidateNamespace(parts[0]); err != nil {
				return fmt.Errorf("invalid namespace in --pods entry %q: %w", p, err)
			}
			name = parts[1]
		}
		if err := validation.ValidatePodName(name); err != nil {
			return fmt.Errorf("invalid pod name in --pods entry %q: %w", p, err)
		}
	}

	if err := validation.ValidateContainerName(containerName); err != nil {
		return fmt.Errorf("invalid container name: %w", err)
	}

	if err := validation.ValidateExportFormat(exportFormat); err != nil {
		return fmt.Errorf("invalid export format: %w", err)
	}

	if diagnoseDuration != "" {
		if _, err := time.ParseDuration(diagnoseDuration); err != nil {
			return fmt.Errorf("invalid --diagnose duration %q: %w", diagnoseDuration, err)
		}
	}

	if err := validation.ValidateEventFilter(eventFilter); err != nil {
		return fmt.Errorf("invalid event filter: %w", err)
	}

	if err := validation.ValidateErrorRateThreshold(errorRateThreshold); err != nil {
		return fmt.Errorf("invalid error threshold: %w", err)
	}
	if err := validation.ValidateRTTThreshold(rttSpikeThreshold); err != nil {
		return fmt.Errorf("invalid RTT threshold: %w", err)
	}
	if err := validation.ValidateFSThreshold(fsSlowThreshold); err != nil {
		return fmt.Errorf("invalid file system threshold: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	handlerDone := make(chan struct{})
	defer close(handlerDone)
	defer signal.Stop(sigChan)
	go func() {
		select {
		case <-sigChan:
			cancel()
		case <-handlerDone:
			return
		}
		select {
		case <-sigChan:
			_, _ = fmt.Fprintln(os.Stderr, "second interrupt — finishing up (up to 3s) then exiting")
			select {
			case <-handlerDone:
			case <-time.After(secondSignalGracePeriod):
			}
			logger.Sync()
			exitFunc(130)
		case <-handlerDone:
		}
	}()

	resolver, err := resolverFactory()
	if err != nil {
		return fmt.Errorf("failed to create pod resolver: %w", err)
	}

	resolveCtx, resolveCancel := context.WithTimeout(ctx, config.DefaultPodResolveTimeout)
	defer resolveCancel()
	selectionDefaultNamespace := namespace
	selectionNamespaces := namespaces
	if watchAllNamespaces {
		selectionDefaultNamespace = ""
		selectionNamespaces = nil
	}
	selection := kubernetes.TargetSelection{
		DefaultNamespace: selectionDefaultNamespace,
		Namespaces:       selectionNamespaces,
		PodSelector:      podSelector,
		AllInNamespace:   allInNamespace,
		Pods:             pods,
		ContainerName:    containerName,
	}

	if handled, err := maybeSpawnOnNode(ctx, cmd, resolver, selection); handled {
		return err
	}

	targetInfos := make([]*kubernetes.PodInfo, 0, 8)
	var targetRegistry *kubernetes.TargetRegistry

	_, hasClientset := resolver.(kubernetes.ClientsetProvider)
	useDynamicTargets := hasClientset && (len(selection.Pods) > 1 || selection.PodSelector != "" || selection.AllInNamespace || len(selection.Namespaces) > 1)
	usePreResolved := len(preresolvedPods) > 0

	if usePreResolved {
		infos, skipped, parseErr := kubernetes.BuildPodInfosFromPreResolved(preresolvedPods)
		if parseErr != nil {
			return parseErr
		}
		for _, s := range skipped {
			logger.Warn("Skipping pre-resolved target whose cgroup was not found on this node "+
				"(pod likely rescheduled, restarted, or runs on a different node)",
				zap.String("namespace", s.Ref.Namespace),
				zap.String("pod", s.Ref.PodName),
				zap.String("container_id", s.Ref.ContainerID),
				zap.Error(s.Cause))
		}
		if len(infos) == 0 && len(skipped) > 0 {
			parts := make([]string, len(skipped))
			for i, s := range skipped {
				parts[i] = fmt.Sprintf("%s/%s: %v", s.Ref.Namespace, s.Ref.PodName, s.Cause)
			}
			return fmt.Errorf("no pre-resolved targets resolvable on this node:\n  - %s",
				strings.Join(parts, "\n  - "))
		}
		targetInfos = append(targetInfos, infos...)
	} else if useDynamicTargets {
		clientset := resolver.(kubernetes.ClientsetProvider).GetClientset()
		targetRegistry = kubernetes.NewTargetRegistry(clientset, selection)
		if err := targetRegistry.Start(ctx); err != nil {
			return fmt.Errorf("failed to start target registry: %w", err)
		}
		targetInfos = targetRegistry.Snapshot()
		if len(targetInfos) == 0 {
			return fmt.Errorf("target selection matched zero running pods")
		}
	} else {
		for _, podRef := range selection.Pods {
			podNs, podName := parsePodRef(podRef, namespace)
			info, err := resolver.ResolvePod(resolveCtx, podName, podNs, containerName)
			if err != nil {
				return fmt.Errorf("failed to resolve pod %s/%s: %w", podNs, podName, err)
			}
			targetInfos = append(targetInfos, info)
		}
	}
	if len(targetInfos) == 0 {
		return fmt.Errorf("target selection resolved zero pods")
	}
	podInfo := targetInfos[0]
	sourceIndex := newSourcePodIndex(targetInfos)

	if len(targetInfos) > 1 {
		logger.Info("Tracing multiple target pods on this node",
			zap.Int("total_targets", len(targetInfos)))
	}

	for _, p := range targetInfos {
		logger.Info("Resolved target pod",
			zap.String("namespace", p.Namespace),
			zap.String("pod", p.PodName),
			zap.Int("containers", len(podContainerTargets(p))),
			zap.String("container_id", p.ContainerID),
			zap.String("cgroup_path", p.CgroupPath))
		if os.Getenv("PODTRACE_ALLOW_BROAD_CGROUP") == "1" {
			continue
		}
		for _, c := range podContainerTargets(p) {
			if c.CgroupPath == "" {
				continue
			}
			short := c.ID
			if len(short) > 12 {
				short = short[:12]
			}
			if !strings.Contains(c.CgroupPath, c.ID) && (short == "" || !strings.Contains(c.CgroupPath, short)) {
				return fmt.Errorf(
					"resolved cgroup path %q does not contain container id %q; refusing to run.\n\n"+
						"This safety check prevents accidentally tracing the wrong container.\n\n"+
						"Common causes and fixes:\n"+
						"  • OpenShift/OKD: CRI-O may use a cgroup path that omits the container ID.\n"+
						"  • Talos Linux: custom cgroup layout may not embed the container ID.\n"+
						"  • Custom kubelet --cgroup-parent may produce parent-level slice paths.\n\n"+
						"To bypass this check: set PODTRACE_ALLOW_BROAD_CGROUP=1\n"+
						"To inspect the path:  ls /sys/fs/cgroup/**/*%s* 2>/dev/null || true",
					c.CgroupPath, short, short)
			}
		}
	}

	if err := system.CheckRequirements(); err != nil {
		return err
	}
	if err := system.CheckKernelLockdown(); err != nil {
		return err
	}
	system.CheckSELinux()

	if diagnoseDuration != "" && config.CriticalPathEnabled {
		config.RequestStamping = true
	}
	tracer, err := tracerFactory()
	if err != nil {
		return fmt.Errorf("failed to create tracer: %w", err)
	}
	defer func() { _ = tracer.Stop() }()
	if diagnoseDuration != "" {
		countFastFilesystemOps(tracer)
		countProcessCPU(tracer)
	}

	cgroupPaths, containerIDs := targetAttachSets(targetInfos)
	if err := attachTracerToCgroups(tracer, cgroupPaths); err != nil {
		return fmt.Errorf("failed to attach to cgroups: %w", err)
	}
	if err := setTracerContainerIDs(tracer, containerIDs); err != nil {
		return fmt.Errorf("failed to set container IDs: %w", err)
	}
	sourceIndex.followRestartedContainers(tracer)
	if targetRegistry != nil {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case snapshot := <-targetRegistry.Updates():
					if len(snapshot) == 0 {
						logger.Warn("Target registry currently empty; retaining previous cgroup filters")
						continue
					}
					nextCgroups, nextContainerIDs := targetAttachSets(snapshot)
					if err := attachTracerToCgroups(tracer, nextCgroups); err != nil {
						logger.Warn("Failed to apply dynamic cgroup target update", zap.Error(err))
						continue
					}
					if err := setTracerContainerIDs(tracer, nextContainerIDs); err != nil {
						logger.Warn("Failed to apply dynamic container uprobe target update", zap.Error(err))
					}
					sourceIndex.Replace(snapshot)
					logger.Info("Updated dynamic target set",
						zap.Int("pods", len(snapshot)),
						zap.Int("containers", len(nextContainerIDs)))
				}
			}
		}()
	}

	var enricher *kubernetes.ContextEnricher
	enrichmentEnabled := config.K8sEnrichmentEnabled()
	if enrichmentEnabled {
		if clientsetProvider, ok := resolver.(kubernetes.ClientsetProvider); ok {
			clientset := clientsetProvider.GetClientset()
			if clientset != nil {
				enricher = kubernetes.NewContextEnricher(clientset, podInfo)
				enricher.Start(ctx)
				defer enricher.Stop()
			}
		}
	}

	eventChan := make(chan *events.Event, config.EventChannelBufferSize)

	tracingActive := tracingManager != nil && enableTracing
	var profilingPodIPs []string
	for _, ti := range targetInfos {
		if ti != nil && ti.PodIP != "" {
			profilingPodIPs = append(profilingPodIPs, ti.PodIP)
		}
	}
	profilingActive := (enableProfiling || config.ProfilingEnabled) &&
		len(profilingPodIPs) > 0
	auxiliaryConsumers := 0
	for _, active := range []bool{enableMetrics, tracingActive, profilingActive} {
		if active {
			auxiliaryConsumers++
		}
	}
	reportChan := eventChan
	var auxiliaryChans []chan *events.Event
	if auxiliaryConsumers > 0 {
		reportChan, auxiliaryChans = teeEvents(ctx, eventChan, auxiliaryConsumers)
	}
	nextAuxiliary := 0
	takeAuxiliary := func() chan *events.Event {
		c := auxiliaryChans[nextAuxiliary]
		nextAuxiliary++
		return c
	}

	if enableMetrics {
		metricsChan := takeAuxiliary()
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Error("Panic in metrics event handler",
						zap.Any("panic", r),
						zap.ByteString("stack", debug.Stack()))
				}
			}()
			for {
				select {
				case <-ctx.Done():
					return
				case event, ok := <-metricsChan:
					if !ok {
						return
					}
					if enricher != nil {
						enriched := enricher.EnrichEvent(ctx, event)
						if enriched != nil && enriched.KubernetesContext != nil {
							k8sCtx := buildK8sContextMap(enriched, sourceIndex.Resolve(event))
							metricsexporter.HandleEventWithContext(event, k8sCtx)
						} else {
							metricsexporter.HandleEvent(event)
						}
					} else {
						metricsexporter.HandleEvent(event)
					}
				}
			}
		}()
	}

	if tracingActive {
		tracingChan := takeAuxiliary()
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Error("Panic in tracing event handler",
						zap.Any("panic", r),
						zap.ByteString("stack", debug.Stack()))
				}
			}()
			for {
				select {
				case <-ctx.Done():
					return
				case event, ok := <-tracingChan:
					if !ok {
						return
					}
					var k8sCtx interface{}
					if enricher != nil {
						enriched := enricher.EnrichEvent(ctx, event)
						if enriched != nil && enriched.KubernetesContext != nil {
							k8sCtx = buildK8sContextMap(enriched, sourceIndex.Resolve(event))
						}
					}
					tracingManager.ProcessEvent(event, k8sCtx)
				}
			}
		}()
	}

	var profilingReporter profiling.Reporter
	if enableProfiling || config.ProfilingEnabled {
		config.ProfilingEnabled = true
		ports := parsePprofPorts(config.ProfilingPprofPorts)
		if profilingActive {
			var controller tracerpkg.ProfilingController
			if len(profilingPodIPs) == 1 {
				h := profiling.NewHandler(profilingPodIPs[0], ports)
				profilingReporter, controller = h, h
				go h.Run(ctx, takeAuxiliary())
			} else {
				m := profiling.NewMultiHandler(profilingPodIPs, ports)
				profilingReporter, controller = m, m
				logger.Info("Profiling every target pod on this node",
					zap.Int("pods", m.Len()))
				go m.Run(ctx, takeAuxiliary())
			}
			if setter, ok := tracer.(tracerpkg.ProfilingControllerSetter); ok {
				setter.SetProfilingController(controller)
			}
		} else {
			logger.Warn("Profiling requested but no target pod IP is available; skipping pprof discovery")
		}
	}

	enrichedChan := reportChan

	filteredChan := enrichedChan
	if eventFilter != "" {
		filteredChan = make(chan *events.Event, config.EventChannelBufferSize)
		go filterEvents(ctx, enrichedChan, filteredChan, eventFilter)
	}

	if enableMetrics {
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					metricsexporter.RecordChannelDepths(len(eventChan), len(filteredChan))
				}
			}
		}()
	}

	if config.RequestStamping {
		stampRequests(tracer)
	}

	if err := tracer.Start(ctx, eventChan); err != nil {
		return fmt.Errorf("failed to start tracer: %w", err)
	}

	if diagnoseDuration != "" {
		return runDiagnoseModeWithSource(ctx, filteredChan, diagnoseDuration, podInfo, enricher, nil, sourceIndex.Resolve, profilingReporter)
	}

	return runNormalModeWithSource(ctx, filteredChan, podInfo, enricher, nil, sourceIndex.Resolve, profilingReporter)
}

func runNormalMode(ctx context.Context, eventChan <-chan *events.Event, podInfo *kubernetes.PodInfo, enricher *kubernetes.ContextEnricher, eventsCorrelator *kubernetes.EventsCorrelator) error {
	return runNormalModeWithSource(ctx, eventChan, podInfo, enricher, eventsCorrelator, nil, nil)
}

func runNormalModeWithSource(ctx context.Context, eventChan <-chan *events.Event, podInfo *kubernetes.PodInfo, enricher *kubernetes.ContextEnricher, _ *kubernetes.EventsCorrelator, resolveSource func(*events.Event) *kubernetes.PodInfo, profilingReporter profiling.Reporter) error {
	logger.Info("Tracing started",
		zap.Duration("update_interval", config.DefaultRealtimeUpdateInterval))

	var diagnostician *diagnose.Diagnostician
	if podInfo != nil && enricher != nil {
		diagnostician = diagnose.NewDiagnosticianWithK8sAndThresholds(podInfo.PodName, podInfo.Namespace, errorRateThreshold, rttSpikeThreshold, fsSlowThreshold)
	} else {
		diagnostician = diagnose.NewDiagnosticianWithThresholds(errorRateThreshold, rttSpikeThreshold, fsSlowThreshold)
	}
	ticker := time.NewTicker(config.DefaultRealtimeUpdateInterval)
	defer ticker.Stop()

	hasPrintedReport := false

	for {
		select {
		case event := <-eventChan:
			attachSourcePod(event, resolveSource)
			var k8sCtx map[string]interface{}
			if enricher != nil {
				enriched := enricher.EnrichEvent(ctx, event)
				if enriched != nil && enriched.KubernetesContext != nil {
					k8sCtx = buildK8sContextMap(enriched, resolveSourcePod(resolveSource, event))
					diagnostician.AddEventWithContext(event, k8sCtx)
				} else {
					diagnostician.AddEvent(event)
				}
			} else {
				diagnostician.AddEvent(event)
			}

		case <-ticker.C:
			diagnostician.Finish()

			if hasPrintedReport {
				fmt.Print("\033[2J\033[H")
			}

			report := diagnostician.GenerateReport()
			fmt.Println("=== Real-time Diagnostic Report (updating every 5s) ===")
			fmt.Println("Press Ctrl+C to stop and see final report.")
			fmt.Println()
			fmt.Println(report)
			hasPrintedReport = true

		case <-ctx.Done():
			diagnostician.Finish()
			if hasPrintedReport {
				fmt.Print("\033[2J\033[H")
			}
			fmt.Println("\n=== Final Diagnostic Report ===")
			fmt.Println()
			finalDuration := diagnostician.EndTime().Sub(diagnostician.StartTime())
			report := generateDiagnoseReport(diagnostician)
			if profilingReporter != nil {
				report += profilingReporter.GenerateSection(diagnostician.GetEvents(), finalDuration)
			}
			fmt.Println(report)
			return nil
		}
	}
}

func runDiagnoseMode(ctx context.Context, eventChan <-chan *events.Event, durationStr string, podInfo *kubernetes.PodInfo, enricher *kubernetes.ContextEnricher, eventsCorrelator *kubernetes.EventsCorrelator) error {
	return runDiagnoseModeWithSource(ctx, eventChan, durationStr, podInfo, enricher, eventsCorrelator, nil, nil)
}

func runDiagnoseModeWithSource(ctx context.Context, eventChan <-chan *events.Event, durationStr string, podInfo *kubernetes.PodInfo, enricher *kubernetes.ContextEnricher, _ *kubernetes.EventsCorrelator, resolveSource func(*events.Event) *kubernetes.PodInfo, profilingReporter profiling.Reporter) error {
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		return fmt.Errorf("invalid duration: %w", err)
	}

	if err := validation.ValidateDiagnoseDuration(duration); err != nil {
		return err
	}

	deadline, err := parseSessionDeadline(sessionDeadline)
	if err != nil {
		return err
	}
	requested := duration
	duration, shortened := collectionWindow(requested, deadline, time.Now())
	if shortened {
		logger.Warn("Collecting for less than the requested duration: the session's deadline leaves no more time",
			zap.Duration("requested", requested), zap.Duration("collecting", duration))
	}

	logger.Info("Running diagnose mode", zap.Duration("duration", duration))

	var diagnostician *diagnose.Diagnostician
	if podInfo != nil && enricher != nil {
		diagnostician = diagnose.NewDiagnosticianWithK8sAndThresholds(podInfo.PodName, podInfo.Namespace, errorRateThreshold, rttSpikeThreshold, fsSlowThreshold)
	} else {
		diagnostician = diagnose.NewDiagnosticianWithThresholds(errorRateThreshold, rttSpikeThreshold, fsSlowThreshold)
	}
	timeout := time.After(duration)
	batchTicker := time.NewTicker(config.BatchProcessingInterval)
	defer batchTicker.Stop()
	eventBatch := make([]*events.Event, 0, config.EventBatchSize)
	// flushBatch feeds every pending event to the diagnostician (and the
	// tracing manager). The terminal paths MUST flush too: finishing the
	// run with a partially-filled batch systematically undercounted the
	// tail of every diagnose run.
	flushBatch := func() {
		if len(eventBatch) == 0 {
			return
		}
		for _, e := range eventBatch {
			var k8sCtx map[string]interface{}
			if enricher != nil {
				enriched := enricher.EnrichEvent(ctx, e)
				if enriched != nil && enriched.KubernetesContext != nil {
					k8sCtx = buildK8sContextMap(enriched, resolveSourcePod(resolveSource, e))
					diagnostician.AddEventWithContext(e, k8sCtx)
				} else {
					diagnostician.AddEvent(e)
				}
			} else {
				diagnostician.AddEvent(e)
			}
		}
		eventBatch = eventBatch[:0]
	}

	for {
		select {
		case event := <-eventChan:
			attachSourcePod(event, resolveSource)
			eventBatch = append(eventBatch, event)
			if len(eventBatch) >= config.EventBatchSize {
				flushBatch()
			}
		case <-batchTicker.C:
			flushBatch()
		case <-timeout:
			flushBatch()
			diagnostician.Finish()
			report := generateDiagnoseReport(diagnostician)
			if shortened {
				report = shortenedCollectionNote(requested, duration) + report
			}
			if profilingReporter != nil {
				report += profilingReporter.GenerateSection(diagnostician.GetEvents(), duration)
			}
			finalizeDiagnoseOutputs(ctx, report, diagnostician)
			if exportFormat != "" {
				return exportReport(report, exportFormat, diagnostician)
			}
			fmt.Println(report)
			return nil
		case <-ctx.Done():
			flushBatch()
			diagnostician.Finish()
			report := generateDiagnoseReport(diagnostician)
			if profilingReporter != nil {
				report += profilingReporter.GenerateSection(diagnostician.GetEvents(), duration)
			}
			finalizeDiagnoseOutputs(ctx, report, diagnostician)
			if exportFormat != "" {
				return exportReport(report, exportFormat, diagnostician)
			}
			fmt.Println("\n=== Final Diagnostic Report ===")
			fmt.Println()
			fmt.Println(report)
			return nil
		}
	}
}

func filterEvents(ctx context.Context, in <-chan *events.Event, out chan<- *events.Event, filter string) {
	defer close(out)
	filters := strings.Split(strings.ToLower(filter), ",")
	filterMap := make(map[string]bool, len(filters))
	for _, f := range filters {
		f = strings.TrimSpace(f)
		if f != "" {
			filterMap[f] = true
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-in:
			if !ok {
				return
			}
			if event == nil {
				continue
			}
			shouldInclude := false
			switch {
			case event.Type == events.EventRequestDone:
				shouldInclude = true
			case filterMap["dns"] && event.Type == events.EventDNS:
				shouldInclude = true
			case filterMap["net"] && (event.Type == events.EventConnect || event.Type == events.EventTCPSend || event.Type == events.EventTCPRecv ||
				event.Type == events.EventFastCGIReq || event.Type == events.EventFastCGIResp ||
				event.Type == events.EventHTTPReq || event.Type == events.EventHTTPResp ||
				event.Type == events.EventGRPCMethod || event.Type == events.EventHTTP3 ||
				event.Type == events.EventTLSHandshake):
				shouldInclude = true
			case filterMap["fs"] && (event.Type == events.EventRead || event.Type == events.EventWrite || event.Type == events.EventFsync):
				shouldInclude = true
			case filterMap["cpu"] && event.Type == events.EventSchedSwitch:
				shouldInclude = true
			case filterMap["proc"] && (event.Type == events.EventExec || event.Type == events.EventFork || event.Type == events.EventOpen || event.Type == events.EventClose):
				shouldInclude = true
			case filterMap["crypto"] && event.Type == events.EventAFALG:
				shouldInclude = true
			case filterMap["usdt"] && event.Type == events.EventUSDT:
				shouldInclude = true
			}
			if shouldInclude {
				select {
				case <-ctx.Done():
					return
				case out <- event:
				default:
					logger.Warn("Filtered event channel full, dropping event",
						zap.String("event_type", event.TypeString()),
						zap.Uint32("pid", event.PID))
					metricsexporter.RecordFilteredEventDrop()
				}
			}
		}
	}
}

func exportReport(_ string, format string, d *diagnose.Diagnostician) error {
	format = strings.ToLower(strings.TrimSpace(format))
	switch format {
	case "json":
		data := d.ExportJSON()
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(data)
	case "csv":
		return d.ExportCSV(os.Stdout)
	default:
		return fmt.Errorf("unsupported export format: %s", format)
	}
}

// podContainerTargets returns the pod's traced containers, synthesizing a
// single-entry list from the legacy singular fields when the list is empty.
func podContainerTargets(p *kubernetes.PodInfo) []kubernetes.ContainerTarget {
	if p == nil {
		return nil
	}
	if len(p.Containers) > 0 {
		return p.Containers
	}
	return []kubernetes.ContainerTarget{{Name: p.ContainerName, ID: p.ContainerID, CgroupPath: p.CgroupPath}}
}

// targetAttachSets flattens every traced container of every target pod into
// the cgroup-path and container-ID attach lists.
func targetAttachSets(infos []*kubernetes.PodInfo) (cgroupPaths, containerIDs []string) {
	for _, p := range infos {
		for _, c := range podContainerTargets(p) {
			if c.CgroupPath != "" {
				cgroupPaths = append(cgroupPaths, c.CgroupPath)
			}
			if c.ID != "" {
				containerIDs = append(containerIDs, c.ID)
			}
		}
	}
	return cgroupPaths, containerIDs
}

type sourcePodIndex struct {
	mu       sync.RWMutex
	byCG     map[uint64]*kubernetes.PodInfo
	byNSP    map[string]*kubernetes.PodInfo
	byParent map[uint64]*kubernetes.PodInfo
	parentOf func(uint64) (uint64, bool)
}

func newSourcePodIndex(targets []*kubernetes.PodInfo) *sourcePodIndex {
	s := &sourcePodIndex{
		byCG:  make(map[uint64]*kubernetes.PodInfo),
		byNSP: make(map[string]*kubernetes.PodInfo),
	}
	s.Replace(targets)
	return s
}

func (s *sourcePodIndex) Replace(targets []*kubernetes.PodInfo) {
	nextByCG := make(map[uint64]*kubernetes.PodInfo, len(targets))
	nextByNSP := make(map[string]*kubernetes.PodInfo, len(targets))
	nextByParent := make(map[uint64]*kubernetes.PodInfo, len(targets))
	for _, t := range targets {
		if t == nil {
			continue
		}
		cp := *t
		nextByNSP[t.Namespace+"/"+t.PodName] = &cp
		for _, c := range podContainerTargets(t) {
			if c.CgroupPath == "" {
				continue
			}
			cgid, err := cgroupIDFromPath(c.CgroupPath)
			if err != nil || cgid == 0 {
				continue
			}
			cc := *t
			cc.ContainerName = c.Name
			cc.ContainerID = c.ID
			cc.CgroupPath = c.CgroupPath
			nextByCG[cgid] = &cc
			if pid, err := cgroupIDFromPath(filepath.Dir(c.CgroupPath)); err == nil && pid != 0 {
				pod := *t
				pod.ContainerName, pod.ContainerID, pod.CgroupPath = "", "", ""
				nextByParent[pid] = &pod
			}
		}
	}
	s.mu.Lock()
	s.byCG = nextByCG
	s.byNSP = nextByNSP
	s.byParent = nextByParent
	s.mu.Unlock()
}

type inheritedCgroupResolver interface {
	InheritedCgroupParent(id uint64) (uint64, bool)
}

// followRestartedContainers lets the index attribute a restarted container
// to its pod from its first event, before the pod watch reports it.
func (s *sourcePodIndex) followRestartedContainers(t any) {
	r, ok := t.(inheritedCgroupResolver)
	if !ok || s == nil {
		return
	}
	s.mu.Lock()
	s.parentOf = r.InheritedCgroupParent
	s.mu.Unlock()
}

func (s *sourcePodIndex) Resolve(event *events.Event) *kubernetes.PodInfo {
	if s == nil || event == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if p, ok := s.byCG[event.CgroupID]; ok {
		return p
	}
	if s.parentOf != nil {
		if parent, ok := s.parentOf(event.CgroupID); ok {
			return s.byParent[parent]
		}
	}
	return nil
}

func cgroupIDFromPath(path string) (uint64, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys == nil {
		return 0, fmt.Errorf("unsupported stat type for cgroup path")
	}
	return sys.Ino, nil
}

func attachTracerToCgroups(tr ebpf.TracerInterface, cgroupPaths []string) error {
	if multi, ok := tr.(interface {
		AttachToCgroups(cgroupPaths []string) error
	}); ok {
		return multi.AttachToCgroups(cgroupPaths)
	}
	if len(cgroupPaths) == 0 {
		return fmt.Errorf("no cgroup paths provided")
	}
	return tr.AttachToCgroup(cgroupPaths[0])
}

func setTracerContainerIDs(tr ebpf.TracerInterface, containerIDs []string) error {
	if multi, ok := tr.(interface {
		SetContainerIDs(containerIDs []string) error
	}); ok {
		return multi.SetContainerIDs(containerIDs)
	}
	if len(containerIDs) == 0 {
		return fmt.Errorf("no container IDs provided")
	}
	return tr.SetContainerID(containerIDs[0])
}

func resolveSourcePod(resolve func(*events.Event) *kubernetes.PodInfo, e *events.Event) *kubernetes.PodInfo {
	if resolve == nil {
		return nil
	}
	return resolve(e)
}

// attachSourcePod stamps the resolved source-pod identity onto the event's
// K8s metadata when it isn't already set.
func attachSourcePod(e *events.Event, resolve func(*events.Event) *kubernetes.PodInfo) {
	if e == nil || e.K8s != nil || resolve == nil {
		return
	}
	if src := resolve(e); src != nil && src.PodName != "" {
		e.K8s = &events.K8sMetadata{
			Namespace:     src.Namespace,
			PodName:       src.PodName,
			ContainerName: src.ContainerName,
		}
	}
}

// generateDiagnoseReport renders the diagnostic report.
var fastFilesystemOps func() ([]kernelagg.Row, error)

type fastFilesystemCounter interface {
	CountFastFilesystemOps() error
	DrainFastFilesystemOps() ([]kernelagg.Row, error)
}

func countFastFilesystemOps(t any) {
	c, ok := t.(fastFilesystemCounter)
	if !ok {
		return
	}
	if err := c.CountFastFilesystemOps(); err != nil {
		logger.Warn("Fast filesystem operations will not be counted; the report counts only those of 1ms or more", zap.Error(err))
		return
	}
	fastFilesystemOps = c.DrainFastFilesystemOps
}

// takeFastFilesystemOps drains the kernel's counts into the diagnostician,
// once: a later report would otherwise lose the counts it already drained.
func takeFastFilesystemOps(agg *diagnose.Diagnostician) {
	drain := fastFilesystemOps
	if drain == nil {
		return
	}
	fastFilesystemOps = nil
	rows, err := drain()
	if err != nil {
		logger.Warn("Could not read the kernel's filesystem counts; the report counts only operations of 1ms or more", zap.Error(err))
		return
	}
	agg.AddFastFilesystemOps(rows)
}

var processCPU func() (map[uint32]uint64, error)

type processCPUCounter interface {
	CountProcessCPU() error
	DrainProcessCPU() (map[uint32]uint64, error)
}

func countProcessCPU(t any) {
	c, ok := t.(processCPUCounter)
	if !ok {
		return
	}
	if err := c.CountProcessCPU(); err != nil {
		logger.Warn("Per-process CPU time will come from /proc only; processes that exit before the report get none", zap.Error(err))
		return
	}
	processCPU = c.DrainProcessCPU
}

// takeProcessCPU drains the kernel's per-process CPU time into the
// diagnostician, once: a later report would otherwise lose what it drained.
func takeProcessCPU(agg *diagnose.Diagnostician) {
	drain := processCPU
	if drain == nil {
		return
	}
	processCPU = nil
	times, err := drain()
	if err != nil {
		logger.Warn("Could not read the kernel's per-process CPU time; the report falls back to /proc", zap.Error(err))
		return
	}
	agg.AddProcessCPU(times)
}

func generateDiagnoseReport(agg *diagnose.Diagnostician) string {
	takeFastFilesystemOps(agg)
	takeProcessCPU(agg)
	return diagnosereport.GenerateTriggerSection(sessionTrigger, agg) + diagnosisByPod(agg) +
		diagnosereport.GenerateCriticalPathSection(agg.CriticalPath(), eventFilter)
}

// requestStamper is the tracer's switch for stamping every event with the
// request it was made for, which the report's critical path groups by.
type requestStamper interface {
	StampRequests() error
}

func stampRequests(t any) {
	s, ok := t.(requestStamper)
	if !ok {
		return
	}
	if err := s.StampRequests(); err != nil {
		logger.Warn("Request stamping unavailable; the report will have no critical path", zap.Error(err))
	}
}

func diagnosisByPod(agg *diagnose.Diagnostician) string {
	allEvents := agg.GetEvents()
	contexts := agg.EventContexts()

	type podBucket struct {
		namespace string
		podName   string
		events    []*events.Event
		contexts  []map[string]interface{}
	}
	order := make([]string, 0, 4)
	buckets := make(map[string]*podBucket)
	for i, e := range allEvents {
		var ns, pod string
		if e.K8s != nil {
			ns, pod = e.K8s.Namespace, e.K8s.PodName
		}
		key := ns + "/" + pod
		b := buckets[key]
		if b == nil {
			b = &podBucket{namespace: ns, podName: pod}
			buckets[key] = b
			order = append(order, key)
		}
		b.events = append(b.events, e)
		if i < len(contexts) {
			b.contexts = append(b.contexts, contexts[i])
		} else {
			b.contexts = append(b.contexts, nil)
		}
	}

	if len(order) <= 1 {
		return agg.GenerateReport()
	}

	sort.Strings(order)
	var sb strings.Builder
	for _, key := range order {
		b := buckets[key]
		child := diagnose.NewDiagnosticianWithK8sAndThresholds(
			b.podName, b.namespace, errorRateThreshold, rttSpikeThreshold, fsSlowThreshold)
		child.SetTimeWindow(agg.StartTime(), agg.EndTime())
		child.AddFastFilesystemOps(agg.FastFilesystemRows())
		child.AddProcessCPU(agg.ProcessCPU())
		for i, e := range b.events {
			child.AddEventWithContext(e, b.contexts[i])
		}
		label := key
		if b.podName == "" {
			label = "(unattributed source)"
		}
		fmt.Fprintf(&sb, "\n================ Diagnosis: %s ================\n\n", label)
		sb.WriteString(child.GenerateReport())
	}
	return sb.String()
}

func buildK8sContextMap(enriched *kubernetes.EnrichedEvent, source *kubernetes.PodInfo) map[string]interface{} {
	if enriched == nil || enriched.KubernetesContext == nil {
		return nil
	}
	sourceNamespace := enriched.KubernetesContext.SourceNamespace
	if source != nil && source.Namespace != "" {
		sourceNamespace = source.Namespace
	}
	ctx := map[string]interface{}{
		"namespace":         sourceNamespace,
		"target_pod":        enriched.KubernetesContext.TargetPodName,
		"target_service":    enriched.KubernetesContext.ServiceName,
		"target_namespace":  enriched.KubernetesContext.TargetNamespace,
		"target_labels":     enriched.KubernetesContext.TargetLabels,
		"service_namespace": enriched.KubernetesContext.ServiceNamespace,
		"is_external":       enriched.KubernetesContext.IsExternal,
	}
	if source != nil {
		ctx["source_pod"] = source.PodName
		ctx["source_namespace"] = source.Namespace
		ctx["source_labels"] = source.Labels
		ctx["source_workload_kind"] = source.OwnerKind
		ctx["source_workload_name"] = source.OwnerName
	}
	if enriched.KubernetesContext.TargetLabels != nil {
		if v := detectServiceMesh(enriched.KubernetesContext.TargetLabels); v != "" {
			ctx["target_mesh"] = v
		}
	}
	if source != nil && source.Labels != nil {
		if v := detectServiceMesh(source.Labels); v != "" {
			ctx["source_mesh"] = v
		}
	}
	return ctx
}

func detectServiceMesh(labels map[string]string) string {
	if labels == nil {
		return ""
	}
	if _, ok := labels["sidecar.istio.io/status"]; ok {
		return "istio"
	}
	if _, ok := labels["istio.io/rev"]; ok {
		return "istio"
	}
	if _, ok := labels["linkerd.io/proxy-version"]; ok {
		return "linkerd"
	}
	if _, ok := labels["kuma.io/sidecar-injected"]; ok {
		return "kuma"
	}
	return ""
}

func parseCSV(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// parsePprofPorts parses a comma-separated list of port numbers from a config
// string (e.g. "6060,8080,9090") and returns valid port integers.
func parsePprofPorts(csv string) []int {
	parts := parseCSV(csv)
	ports := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err == nil && n > 0 && n <= 65535 {
			ports = append(ports, n)
		}
	}
	if len(ports) == 0 {
		return []int{6060, 8080, 8081, 9090, 2345}
	}
	return ports
}

func parsePodRef(podRef, defaultNamespace string) (namespace, podName string) {
	podRef = strings.TrimSpace(podRef)
	if strings.Contains(podRef, "/") {
		parts := strings.SplitN(podRef, "/", 2)
		return parts[0], parts[1]
	}
	return defaultNamespace, podRef
}

func interruptChan() <-chan os.Signal {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	return sigChan
}
