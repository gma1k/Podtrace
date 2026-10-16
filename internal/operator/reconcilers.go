package operator

import (
	"context"
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"
)

// registerReconcilers wires every reconciler onto the manager.
func registerReconcilers(mgr ctrl.Manager, opts Options) error {
	if err := registerExporterConfigIndexers(context.Background(), mgr); err != nil {
		return fmt.Errorf("ExporterConfig indexers: %w", err)
	}

	tcr := &TracerConfigReconciler{
		Client:          mgr.GetClient(),
		APIReader:       mgr.GetAPIReader(),
		Scheme:          mgr.GetScheme(),
		SystemNamespace: opts.SystemNamespace,
	}
	if err := tcr.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("TracerConfigReconciler: %w", err)
	}

	ptsr := &PodTraceSessionReconciler{
		Client:          mgr.GetClient(),
		APIReader:       mgr.GetAPIReader(),
		Scheme:          mgr.GetScheme(),
		SystemNamespace: opts.SystemNamespace,
	}
	if err := ptsr.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("PodTraceSessionReconciler: %w", err)
	}

	ptr := &PodTraceReconciler{
		Client:          mgr.GetClient(),
		APIReader:       mgr.GetAPIReader(),
		Scheme:          mgr.GetScheme(),
		SystemNamespace: opts.SystemNamespace,
	}
	if err := ptr.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("PodTraceReconciler: %w", err)
	}

	ecr := &ExporterConfigReconciler{
		Client:    mgr.GetClient(),
		APIReader: mgr.GetAPIReader(),
		Scheme:    mgr.GetScheme(),
	}
	if err := ecr.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("ExporterConfigReconciler: %w", err)
	}

	pscr := &PodTraceScheduleReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}
	if err := pscr.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("PodTraceScheduleReconciler: %w", err)
	}

	atr := &ApplicationTraceReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}
	if err := atr.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("ApplicationTraceReconciler: %w", err)
	}

	return nil
}
