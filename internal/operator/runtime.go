package operator

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/alerting"
	webhookv1alpha1 "github.com/gma1k/podtrace/internal/webhook/v1alpha1"
)

type Options struct {
	SystemNamespace string

	MetricsBindAddress string

	HealthBindAddress string

	LeaderElection          bool
	LeaderElectionNamespace string
	LeaderElectionID        string

	WebhookPort    int
	WebhookCertDir string

	SyncPeriod time.Duration

	GracefulShutdownTimeout time.Duration

	BootstrapFallbackImage string

	BootstrapTracerConfigName string

	CorrelationInterval time.Duration
}

func DefaultOptions() Options {
	return Options{
		SystemNamespace:         "podtrace-system",
		MetricsBindAddress:      ":8080",
		HealthBindAddress:       ":8081",
		LeaderElection:          true,
		LeaderElectionNamespace: "podtrace-system",
		LeaderElectionID:        "podtrace-operator.podtrace.io",
		WebhookPort:             9443,
		WebhookCertDir:          "/var/run/podtrace/tls",
	}
}

// NewScheme returns a scheme with both client-go's default types and
// the podtrace v1alpha1 API group registered.
func NewScheme() (*runtime.Scheme, error) {
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		return nil, fmt.Errorf("clientgo scheme: %w", err)
	}
	if err := podtracev1alpha1.AddToScheme(s); err != nil {
		return nil, fmt.Errorf("podtrace scheme: %w", err)
	}
	return s, nil
}

func Run(ctx context.Context, opts Options) error {
	if opts.SystemNamespace == "" {
		return errors.New("operator: SystemNamespace is required")
	}

	ctrl.SetLogger(zap.New(zap.UseDevMode(false)))

	scheme, err := NewScheme()
	if err != nil {
		return err
	}

	correlator := &IssueCorrelator{
		SystemNamespace: opts.SystemNamespace,
		Interval:        opts.CorrelationInterval,
		Logger:          ctrl.Log.WithName("issue-correlator"),
	}
	if err := correlator.Register(ctrlmetrics.Registry); err != nil {
		return fmt.Errorf("register issue correlation metrics: %w", err)
	}

	managerOpts := ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress:   opts.MetricsBindAddress,
			ExtraHandlers: map[string]http.Handler{CorrelationsPath: correlator.Handler()},
		},
		HealthProbeBindAddress:  opts.HealthBindAddress,
		LeaderElection:          opts.LeaderElection,
		LeaderElectionID:        leaderElectionID(opts),
		LeaderElectionNamespace: opts.LeaderElectionNamespace,
	}
	if opts.GracefulShutdownTimeout > 0 {
		managerOpts.GracefulShutdownTimeout = &opts.GracefulShutdownTimeout
	}
	if opts.WebhookCertDir != "" {
		managerOpts.WebhookServer = webhook.NewServer(webhook.Options{
			Port:    opts.WebhookPort,
			CertDir: opts.WebhookCertDir,
		})
	}
	managerOpts.Cache.ByObject = map[client.Object]cache.ByObject{
		&corev1.Node{}:   {Transform: stripNodeStatus},
		&corev1.Secret{}: {Transform: stripSecretData},
		&corev1.Event{}:  {Field: alertEventFieldSelector()},

		&discoveryv1.EndpointSlice{}: {Transform: trimEndpointSlice},
	}
	if opts.SyncPeriod > 0 {
		managerOpts.Cache.SyncPeriod = &opts.SyncPeriod
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), managerOpts)
	if err != nil {
		return fmt.Errorf("build manager: %w", err)
	}

	if err := registerReconcilers(mgr, opts); err != nil {
		return fmt.Errorf("register reconcilers: %w", err)
	}

	correlator.Client = mgr.GetClient()
	correlator.Writer = mgr.GetClient()
	if err := mgr.Add(correlator); err != nil {
		return fmt.Errorf("register issue correlation: %w", err)
	}

	if opts.WebhookCertDir != "" {
		if err := registerWebhooks(mgr, opts.SystemNamespace); err != nil {
			return fmt.Errorf("register webhooks: %w", err)
		}
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("add healthz: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("add readyz: %w", err)
	}

	if err := mgr.Add(&BootstrapDefaultTracerConfig{
		Client:           mgr.GetClient(),
		SystemNamespace:  opts.SystemNamespace,
		FallbackImage:    opts.BootstrapFallbackImage,
		TracerConfigName: opts.BootstrapTracerConfigName,
	}); err != nil {
		return fmt.Errorf("register TracerConfig bootstrap: %w", err)
	}

	if err := mgr.Add(&SessionChildReaper{Client: mgr.GetClient()}); err != nil {
		return fmt.Errorf("register session-child reaper: %w", err)
	}

	return mgr.Start(ctx)
}

func alertEventFieldSelector() fields.Selector {
	return fields.OneTermEqualSelector("reason", alerting.EventReasonAlert)
}

func stripSecretData(obj any) (any, error) {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return obj, nil
	}
	secret.Data = nil
	secret.StringData = nil
	secret.ManagedFields = nil
	return secret, nil
}

// stripNodeStatus drops the bulk of a cached Node.
func stripNodeStatus(obj any) (any, error) {
	node, ok := obj.(*corev1.Node)
	if !ok {
		return obj, nil
	}
	node.Status = corev1.NodeStatus{}
	node.ManagedFields = nil
	return node, nil
}

func leaderElectionID(opts Options) string {
	if opts.LeaderElectionID != "" {
		return opts.LeaderElectionID
	}
	return "podtrace-operator.podtrace.io"
}

// registerWebhooks wires the validating webhooks onto the manager.
func registerWebhooks(mgr ctrl.Manager, systemNamespace string) error {
	if err := webhookv1alpha1.SetupPodTraceWebhookWithManager(mgr); err != nil {
		return fmt.Errorf("podtrace webhook: %w", err)
	}
	if err := webhookv1alpha1.SetupPodTraceSessionWebhookWithManager(mgr, systemNamespace); err != nil {
		return fmt.Errorf("podtracesession webhook: %w", err)
	}
	if err := webhookv1alpha1.SetupExporterConfigWebhookWithManager(mgr); err != nil {
		return fmt.Errorf("exporterconfig webhook: %w", err)
	}
	if err := webhookv1alpha1.SetupPodTraceScheduleWebhookWithManager(mgr, systemNamespace); err != nil {
		return fmt.Errorf("podtraceschedule webhook: %w", err)
	}
	if err := webhookv1alpha1.SetupTracerConfigWebhookWithManager(mgr); err != nil {
		return fmt.Errorf("tracerconfig webhook: %w", err)
	}
	if err := webhookv1alpha1.SetupApplicationTraceWebhookWithManager(mgr); err != nil {
		return fmt.Errorf("applicationtrace webhook: %w", err)
	}
	return nil
}
