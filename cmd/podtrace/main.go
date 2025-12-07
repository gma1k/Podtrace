package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/diagnose"
	"github.com/podtrace/podtrace/internal/ebpf"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/kubernetes"
	"github.com/podtrace/podtrace/internal/logger"
	"github.com/podtrace/podtrace/internal/metricsexporter"
	"github.com/podtrace/podtrace/internal/tracing"
	"github.com/podtrace/podtrace/internal/validation"
)

var (
	namespace             string
	diagnoseDuration      string
	enableMetrics         bool
	enableTracing         bool
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
}

func main() {
	var rootCmd = &cobra.Command{
		Use:          "./bin/podtrace -n <namespace> <pod-name> --diagnose 10s",
		Short:        "eBPF-based troubleshooting tool for Kubernetes pods",
		Long:         `podtrace attaches eBPF program to a Kubernetes pod's container and prints high-level, human-readable events that help diagnose application issues.`,
		Args:         cobra.ExactArgs(1),
		RunE:         runPodtrace,
		SilenceUsage: true,
	}

	rootCmd.Flags().StringVarP(&namespace, "namespace", "n", config.DefaultNamespace, "Kubernetes namespace")
	rootCmd.Flags().StringVar(&diagnoseDuration, "diagnose", "", "Run in diagnose mode for the specified duration (e.g., 10s, 5m)")
	rootCmd.Flags().BoolVar(&enableMetrics, "metrics", false, "Enable Prometheus metrics server")
	rootCmd.Flags().StringVar(&exportFormat, "export", "", "Export format for diagnose report (json, csv)")
	rootCmd.Flags().StringVar(&eventFilter, "filter", "", "Filter events by type (dns,net,fs,cpu)")
	rootCmd.Flags().StringVar(&containerName, "container", "", "Container name to trace (default: first container)")
	rootCmd.Flags().Float64Var(&errorRateThreshold, "error-threshold", config.DefaultErrorRateThreshold, "Error rate threshold percentage for issue detection")
	rootCmd.Flags().Float64Var(&rttSpikeThreshold, "rtt-threshold", config.DefaultRTTThreshold, "RTT spike threshold in milliseconds")
	rootCmd.Flags().Float64Var(&fsSlowThreshold, "fs-threshold", config.DefaultFSSlowThreshold, "File system slow operation threshold in milliseconds")
	rootCmd.Flags().StringVar(&logLevel, "log-level", "", "Set log level (debug, info, warn, error, fatal). Overrides PODTRACE_LOG_LEVEL environment variable")
	rootCmd.Flags().BoolVar(&enableTracing, "tracing", config.DefaultTracingEnabled, "Enable distributed tracing")
	rootCmd.Flags().StringVar(&tracingOTLPEndpoint, "tracing-otlp-endpoint", config.DefaultOTLPEndpoint, "OpenTelemetry OTLP endpoint")
	rootCmd.Flags().StringVar(&tracingJaegerEndpoint, "tracing-jaeger-endpoint", config.DefaultJaegerEndpoint, "Jaeger endpoint")
	rootCmd.Flags().StringVar(&tracingSplunkEndpoint, "tracing-splunk-endpoint", config.DefaultSplunkEndpoint, "Splunk HEC endpoint")
	rootCmd.Flags().StringVar(&tracingSplunkToken, "tracing-splunk-token", "", "Splunk HEC token")
	rootCmd.Flags().Float64Var(&tracingSampleRate, "tracing-sample-rate", config.DefaultTracingSampleRate, "Tracing sample rate (0.0-1.0)")

	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if logLevel != "" {
			logger.SetLevel(logLevel)
		}
	}

	if err := rootCmd.Execute(); err != nil {
		logger.Error("Command execution failed", zap.Error(err))
		exitFunc(1)
	}
	defer logger.Sync()
}

func runPodtrace(cmd *cobra.Command, args []string) error {
	if enableTracing {
		config.TracingEnabled = true
		if tracingOTLPEndpoint != "" {
			config.OTLPEndpoint = tracingOTLPEndpoint
		}
		if tracingJaegerEndpoint != "" {
			config.JaegerEndpoint = tracingJaegerEndpoint
		}
		if tracingSplunkEndpoint != "" {
			config.SplunkEndpoint = tracingSplunkEndpoint
		}
		if tracingSplunkToken != "" {
			config.SplunkToken = tracingSplunkToken
		}
		if tracingSampleRate >= 0.0 && tracingSampleRate <= 1.0 {
			config.TracingSampleRate = tracingSampleRate
		}
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
				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer shutdownCancel()
				_ = tracingManager.Shutdown(shutdownCtx)
			}()
		}
	}

	podName := args[0]

	if err := validation.ValidatePodName(podName); err != nil {
		return fmt.Errorf("invalid pod name: %w", err)
	}

	if err := validation.ValidateNamespace(namespace); err != nil {
		return fmt.Errorf("invalid namespace: %w", err)
	}

	if err := validation.ValidateContainerName(containerName); err != nil {
		return fmt.Errorf("invalid container name: %w", err)
	}

	if err := validation.ValidateExportFormat(exportFormat); err != nil {
		return fmt.Errorf("invalid export format: %w", err)
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

	resolver, err := resolverFactory()
	if err != nil {
		return fmt.Errorf("failed to create pod resolver: %w", err)
	}

	resolveCtx, resolveCancel := context.WithTimeout(context.Background(), config.DefaultPodResolveTimeout)
	defer resolveCancel()
	podInfo, err := resolver.ResolvePod(resolveCtx, podName, namespace, containerName)
	if err != nil {
		return fmt.Errorf("failed to resolve pod: %w", err)
	}

	logger.Info("Resolved pod",
		zap.String("namespace", namespace),
		zap.String("pod", podName),
		zap.String("container_id", podInfo.ContainerID),
		zap.String("cgroup_path", podInfo.CgroupPath))

	tracer, err := tracerFactory()
	if err != nil {
		return fmt.Errorf("failed to create tracer: %w", err)
	}
	defer func() { _ = tracer.Stop() }()

	if err := tracer.AttachToCgroup(podInfo.CgroupPath); err != nil {
		return fmt.Errorf("failed to attach to cgroup: %w", err)
	}
	if err := tracer.SetContainerID(podInfo.ContainerID); err != nil {
		return fmt.Errorf("failed to set container ID: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var enricher *kubernetes.ContextEnricher
	var eventsCorrelator *kubernetes.EventsCorrelator
	enrichmentEnabled := os.Getenv("PODTRACE_K8S_ENRICHMENT_ENABLED") != "false"
	if enrichmentEnabled {
		if clientsetProvider, ok := resolver.(kubernetes.ClientsetProvider); ok {
			clientset := clientsetProvider.GetClientset()
			if clientset != nil {
				enricher = kubernetes.NewContextEnricher(clientset, podInfo)
				eventsCorrelator = kubernetes.NewEventsCorrelator(clientset, podName, namespace)
				if err := eventsCorrelator.Start(ctx); err != nil {
					logger.Warn("Failed to start Kubernetes events correlator", zap.Error(err))
				} else {
					defer eventsCorrelator.Stop()
				}
			}
		}
	}

	eventChan := make(chan *events.Event, config.EventChannelBufferSize)
	if enableMetrics {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Error("Panic in metrics event handler", zap.Any("panic", r))
				}
			}()
			for {
				select {
				case <-ctx.Done():
					return
				case event, ok := <-eventChan:
					if !ok {
						return
					}
					if enricher != nil {
						enriched := enricher.EnrichEvent(ctx, event)
						if enriched != nil && enriched.KubernetesContext != nil {
							k8sCtx := map[string]interface{}{
								"namespace":      enriched.KubernetesContext.SourceNamespace,
								"target_pod":     enriched.KubernetesContext.TargetPodName,
								"target_service": enriched.KubernetesContext.ServiceName,
							}
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

	if tracingManager != nil && enableTracing {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Error("Panic in tracing event handler", zap.Any("panic", r))
				}
			}()
			for {
				select {
				case <-ctx.Done():
					return
				case event, ok := <-eventChan:
					if !ok {
						return
					}
					var k8sCtx interface{}
					if enricher != nil {
						enriched := enricher.EnrichEvent(ctx, event)
						if enriched != nil && enriched.KubernetesContext != nil {
							k8sCtx = map[string]interface{}{
								"target_pod":       enriched.KubernetesContext.TargetPodName,
								"target_service":   enriched.KubernetesContext.ServiceName,
								"target_namespace": enriched.KubernetesContext.TargetNamespace,
								"target_labels":    enriched.KubernetesContext.TargetLabels,
							}
						}
					}
					tracingManager.ProcessEvent(event, k8sCtx)
				}
			}
		}()
	}

	enrichedChan := eventChan

	filteredChan := enrichedChan
	if eventFilter != "" {
		filteredChan = make(chan *events.Event, config.EventChannelBufferSize)
		go filterEvents(ctx, enrichedChan, filteredChan, eventFilter)
	}

	if err := tracer.Start(ctx, eventChan); err != nil {
		return fmt.Errorf("failed to start tracer: %w", err)
	}

	if diagnoseDuration != "" {
		return runDiagnoseMode(ctx, filteredChan, diagnoseDuration, podInfo, enricher, eventsCorrelator, tracingManager, enableTracing)
	}

	return runNormalMode(ctx, filteredChan, podInfo, enricher, eventsCorrelator, tracingManager, enableTracing)
}

func runNormalMode(ctx context.Context, eventChan <-chan *events.Event, podInfo *kubernetes.PodInfo, enricher *kubernetes.ContextEnricher, _ *kubernetes.EventsCorrelator, tracingManager *tracing.Manager, enableTracing bool) error {
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
		case <-ctx.Done():
			return ctx.Err()
		case event := <-eventChan:
			var k8sCtx map[string]interface{}
			if enricher != nil {
				enriched := enricher.EnrichEvent(ctx, event)
				if enriched != nil && enriched.KubernetesContext != nil {
					k8sCtx = map[string]interface{}{
						"target_pod":       enriched.KubernetesContext.TargetPodName,
						"target_service":   enriched.KubernetesContext.ServiceName,
						"target_namespace": enriched.KubernetesContext.TargetNamespace,
						"target_labels":    enriched.KubernetesContext.TargetLabels,
					}
					diagnostician.AddEventWithContext(event, k8sCtx)
				} else {
					diagnostician.AddEvent(event)
				}
			} else {
				diagnostician.AddEvent(event)
			}
			if tracingManager != nil && enableTracing {
				var k8sCtxInterface interface{}
				if k8sCtx != nil {
					k8sCtxInterface = k8sCtx
				}
				tracingManager.ProcessEvent(event, k8sCtxInterface)
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

		case <-interruptChan():
			diagnostician.Finish()
			if hasPrintedReport {
				fmt.Print("\033[2J\033[H")
			}
			fmt.Println("=== Final Diagnostic Report ===")
			fmt.Println()
			report := diagnostician.GenerateReport()
			fmt.Println(report)
			return nil
		}
	}
}

func runDiagnoseMode(ctx context.Context, eventChan <-chan *events.Event, durationStr string, podInfo *kubernetes.PodInfo, enricher *kubernetes.ContextEnricher, _ *kubernetes.EventsCorrelator, tracingManager *tracing.Manager, enableTracing bool) error {
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		return fmt.Errorf("invalid duration: %w", err)
	}

	if err := validation.ValidateDiagnoseDuration(duration); err != nil {
		return err
	}

	logger.Info("Running diagnose mode", zap.Duration("duration", duration))

	var diagnostician *diagnose.Diagnostician
	if podInfo != nil && enricher != nil {
		diagnostician = diagnose.NewDiagnosticianWithK8sAndThresholds(podInfo.PodName, podInfo.Namespace, errorRateThreshold, rttSpikeThreshold, fsSlowThreshold)
	} else {
		diagnostician = diagnose.NewDiagnosticianWithThresholds(errorRateThreshold, rttSpikeThreshold, fsSlowThreshold)
	}
	timeout := time.After(duration)

	for {
		select {
		case <-ctx.Done():
			diagnostician.Finish()
			report := diagnostician.GenerateReport()
			if exportFormat != "" {
				return exportReport(report, exportFormat, diagnostician)
			}
			fmt.Println(report)
			return ctx.Err()
		case event := <-eventChan:
			var k8sCtx map[string]interface{}
			if enricher != nil {
				enriched := enricher.EnrichEvent(ctx, event)
				if enriched != nil && enriched.KubernetesContext != nil {
					k8sCtx = map[string]interface{}{
						"target_pod":       enriched.KubernetesContext.TargetPodName,
						"target_service":   enriched.KubernetesContext.ServiceName,
						"target_namespace": enriched.KubernetesContext.TargetNamespace,
						"target_labels":    enriched.KubernetesContext.TargetLabels,
					}
					diagnostician.AddEventWithContext(event, k8sCtx)
				} else {
					diagnostician.AddEvent(event)
				}
			} else {
				diagnostician.AddEvent(event)
			}
			if tracingManager != nil && enableTracing {
				var k8sCtxInterface interface{}
				if k8sCtx != nil {
					k8sCtxInterface = k8sCtx
				}
				tracingManager.ProcessEvent(event, k8sCtxInterface)
			}
		case <-timeout:
			diagnostician.Finish()
			report := diagnostician.GenerateReport()
			if exportFormat != "" {
				return exportReport(report, exportFormat, diagnostician)
			}
			fmt.Println(report)
			return nil
		case <-interruptChan():
			diagnostician.Finish()
			report := diagnostician.GenerateReport()
			if exportFormat != "" {
				return exportReport(report, exportFormat, diagnostician)
			}
			fmt.Println(report)
			return nil
		}
	}
}

func interruptChan() <-chan os.Signal {
	sigChan := make(chan os.Signal, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("Panic in interrupt handler", zap.Any("panic", r))
			}
		}()
		ebpf.WaitForInterrupt()
		sigChan <- os.Interrupt
	}()
	return sigChan
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
			case filterMap["dns"] && event.Type == events.EventDNS:
				shouldInclude = true
			case filterMap["net"] && (event.Type == events.EventConnect || event.Type == events.EventTCPSend || event.Type == events.EventTCPRecv):
				shouldInclude = true
			case filterMap["fs"] && (event.Type == events.EventRead || event.Type == events.EventWrite || event.Type == events.EventFsync):
				shouldInclude = true
			case filterMap["cpu"] && event.Type == events.EventSchedSwitch:
				shouldInclude = true
			case filterMap["proc"] && (event.Type == events.EventExec || event.Type == events.EventFork || event.Type == events.EventOpen || event.Type == events.EventClose):
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
					metricsexporter.RecordRingBufferDrop()
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
