package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/podtrace/podtrace/internal/diagnose"
	"github.com/podtrace/podtrace/internal/ebpf"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/kubernetes"
)

var (
	namespace       string
	diagnoseDuration string
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

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runPodtrace(cmd *cobra.Command, args []string) error {
	podName := args[0]

	resolver, err := kubernetes.NewPodResolver()
	if err != nil {
		return fmt.Errorf("failed to create pod resolver: %w", err)
	}

	ctx := context.Background()
	podInfo, err := resolver.ResolvePod(ctx, podName, namespace)
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


	eventChan := make(chan *events.Event, 100)

	if err := tracer.Start(eventChan); err != nil {
		return fmt.Errorf("failed to start tracer: %w", err)
	}

	if diagnoseDuration != "" {
		return runDiagnoseMode(eventChan, diagnoseDuration, podInfo.CgroupPath)
	}

	return runNormalMode(eventChan)
}

func runNormalMode(eventChan <-chan *events.Event) error {
	fmt.Println("Tracing started. Press Ctrl+C to stop.")

	for {
		select {
		case event := <-eventChan:
			msg := event.FormatMessage()
			if msg != "" {
				fmt.Println(msg)
			}
		case <-interruptChan():
			return nil
		}
	}
}

func runDiagnoseMode(eventChan <-chan *events.Event, durationStr string, cgroupPath string) error {
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		return fmt.Errorf("invalid duration: %w", err)
	}

	fmt.Printf("Running diagnose mode for %v...\n\n", duration)

	diagnostician := diagnose.NewDiagnostician()
	timeout := time.After(duration)

	for {
		select {
		case event := <-eventChan:
			diagnostician.AddEvent(event)
		case <-timeout:
			diagnostician.Finish()
			report := diagnostician.GenerateReport()
			fmt.Println(report)
			return nil
		case <-interruptChan():
			diagnostician.Finish()
			report := diagnostician.GenerateReport()
			fmt.Println(report)
			return nil
		}
	}
}

func interruptChan() <-chan os.Signal {
	sigChan := make(chan os.Signal, 1)
	go func() {
		ebpf.WaitForInterrupt()
		sigChan <- os.Interrupt
	}()
	return sigChan
}
