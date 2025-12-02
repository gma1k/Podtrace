package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/podtrace/podtrace/internal/diagnose"
	"github.com/podtrace/podtrace/internal/ebpf"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/kubernetes"
	"github.com/podtrace/podtrace/internal/metricsexporter"
	"github.com/podtrace/podtrace/internal/validation"
)

var (
	namespace          string
	diagnoseDuration   string
	enableMetrics      bool
	exportFormat       string
	eventFilter        string
	containerName      string
	errorRateThreshold float64
	rttSpikeThreshold  float64
	fsSlowThreshold    float64
)

func main() {
	var rootCmd = &cobra.Command{
		Use:          "./bin/podtrace -n <namespace> <pod-name> --diagnose 10s",
		Short:        "eBPF-based troubleshooting tool for Kubernetes pods",
		Long:         `podtrace attaches eBPF program to a Kubernetes pod's container and prints high-level, human-readable events that help diagnose application issues.`,
		Args:         cobra.ExactArgs(1),
		RunE:         runPodtrace,
		SilenceUsage: true,
	}

	rootCmd.Flags().StringVarP(&namespace, "namespace", "n", "default", "Kubernetes namespace")
	rootCmd.Flags().StringVar(&diagnoseDuration, "diagnose", "", "Run in diagnose mode for the specified duration (e.g., 10s, 5m)")
	rootCmd.Flags().BoolVar(&enableMetrics, "metrics", false, "Enable Prometheus metrics server")
	rootCmd.Flags().StringVar(&exportFormat, "export", "", "Export format for diagnose report (json, csv)")
	rootCmd.Flags().StringVar(&eventFilter, "filter", "", "Filter events by type (dns,net,fs,cpu)")
	rootCmd.Flags().StringVar(&containerName, "container", "", "Container name to trace (default: first container)")
	rootCmd.Flags().Float64Var(&errorRateThreshold, "error-threshold", 10.0, "Error rate threshold percentage for issue detection")
	rootCmd.Flags().Float64Var(&rttSpikeThreshold, "rtt-threshold", 100.0, "RTT spike threshold in milliseconds")
	rootCmd.Flags().Float64Var(&fsSlowThreshold, "fs-threshold", 10.0, "File system slow operation threshold in milliseconds")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runPodtrace(cmd *cobra.Command, args []string) error {
	var metricsServer *metricsexporter.Server
	if enableMetrics {
		metricsServer = metricsexporter.StartServer()
		defer metricsServer.Shutdown()
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

	resolver, err := kubernetes.NewPodResolver()
	if err != nil {
		return fmt.Errorf("failed to create pod resolver: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	podInfo, err := resolver.ResolvePod(ctx, podName, namespace, containerName)
	if err != nil {
		return fmt.Errorf("failed to resolve pod: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Resolved pod %s/%s:\n", namespace, podName)
	fmt.Fprintf(os.Stderr, "  Container ID: %s\n", podInfo.ContainerID)
	fmt.Fprintf(os.Stderr, "  Cgroup path: %s\n", podInfo.CgroupPath)
	fmt.Fprintf(os.Stderr, "\n")

	tracer, err := ebpf.NewTracer()
	if err != nil {
		return fmt.Errorf("failed to create tracer: %w", err)
	}
	defer tracer.Stop()

	if err := tracer.AttachToCgroup(podInfo.CgroupPath); err != nil {
		return fmt.Errorf("failed to attach to cgroup: %w", err)
	}
	if err := tracer.SetContainerID(podInfo.ContainerID); err != nil {
		return fmt.Errorf("failed to set container ID: %w", err)
	}

	eventChan := make(chan *events.Event, 100)
	if enableMetrics {
		go metricsexporter.HandleEvents(eventChan)
	}

	filteredChan := eventChan
	if eventFilter != "" {
		filteredChan = make(chan *events.Event, 100)
		go filterEvents(eventChan, filteredChan, eventFilter)
	}

	if err := tracer.Start(eventChan); err != nil {
		return fmt.Errorf("failed to start tracer: %w", err)
	}

	if diagnoseDuration != "" {
		return runDiagnoseMode(filteredChan, diagnoseDuration, podInfo.CgroupPath)
	}

	return runNormalMode(filteredChan)
}

func runNormalMode(eventChan <-chan *events.Event) error {
	fmt.Println("Tracing started. Press Ctrl+C to stop.")
	fmt.Println("Real-time diagnostic updates every 5 seconds...")
	fmt.Println()

	diagnostician := diagnose.NewDiagnosticianWithThresholds(errorRateThreshold, rttSpikeThreshold, fsSlowThreshold)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	hasPrintedReport := false

	for {
		select {
		case event := <-eventChan:
			diagnostician.AddEvent(event)

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

func runDiagnoseMode(eventChan <-chan *events.Event, durationStr string, cgroupPath string) error {
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		return fmt.Errorf("invalid duration: %w", err)
	}

	if err := validation.ValidateDiagnoseDuration(duration); err != nil {
		return err
	}

	fmt.Printf("Running diagnose mode for %v...\n\n", duration)

	diagnostician := diagnose.NewDiagnosticianWithThresholds(errorRateThreshold, rttSpikeThreshold, fsSlowThreshold)
	timeout := time.After(duration)

	for {
		select {
		case event := <-eventChan:
			diagnostician.AddEvent(event)
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
				fmt.Fprintf(os.Stderr, "Panic in interrupt handler: %v\n", r)
			}
		}()
		ebpf.WaitForInterrupt()
		sigChan <- os.Interrupt
	}()
	return sigChan
}

func filterEvents(in <-chan *events.Event, out chan<- *events.Event, filter string) {
	defer close(out)
	filters := strings.Split(strings.ToLower(filter), ",")
	filterMap := make(map[string]bool, len(filters))
	for _, f := range filters {
		f = strings.TrimSpace(f)
		if f != "" {
			filterMap[f] = true
		}
	}

	for event := range in {
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
			case out <- event:
			default:
			}
		}
	}
}

func exportReport(report string, format string, d *diagnose.Diagnostician) error {
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
