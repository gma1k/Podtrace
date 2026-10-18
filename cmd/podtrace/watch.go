package main

import (
	"context"
	"errors"
	"fmt"
	corev1 "k8s.io/api/core/v1"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	k8svalidation "k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
	sigsyaml "sigs.k8s.io/yaml"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/kubernetes"
	"github.com/gma1k/podtrace/internal/operator"
	"github.com/gma1k/podtrace/internal/validation"
)

// appNameLabel is the Kubernetes-recommended label that --app targets.
// --label is the escape hatch for any other labelling scheme.
const appNameLabel = "app.kubernetes.io/name"

var (
	watchAppName           string
	watchLabels            []string
	watchAllNamespaces     bool
	watchNamespaceSelector string
	watchExporter          string
	watchName              string
	watchSample            int
	watchKubeconfig        string
	watchPrintOnly         bool
	watchApplication       bool
)

// registerTargetFlags binds the application/label targeting flags.
func registerTargetFlags(fs *pflag.FlagSet) {
	fs.StringVar(&watchAppName, "app", "", "Target an application by name; shorthand for --label "+appNameLabel+"=<NAME>.")
	fs.StringArrayVar(&watchLabels, "label", nil, "Label selector for target pods (e.g. app=api,tier=web). Repeatable: each --label is one workload of the application (with --application). Mutually exclusive with --app.")
	fs.BoolVar(&watchAllNamespaces, "all-namespaces", false, "Match pods in every namespace (default: only --namespace).")
}

// registerWatchOnlyFlags binds the flags that only make sense for the managed
// `watch` subcommand.
func registerWatchOnlyFlags(fs *pflag.FlagSet) {
	fs.StringVar(&watchNamespaceSelector, "namespace-selector", "", "Only match namespaces carrying these labels (e.g. team=payments). Mutually exclusive with --all-namespaces.")
	fs.StringVar(&watchExporter, "exporter", "default", "Name of the ExporterConfig (in the CR's namespace) events are sent to.")
	fs.StringVar(&watchName, "name", "", "Name for the created resource (defaults to the --app value).")
	fs.IntVar(&watchSample, "sample", -1, "Sample percentage 0-100 (default: unset, i.e. the exporter's own default).")
	fs.StringVar(&watchKubeconfig, "kubeconfig", "", "Path to a kubeconfig file (defaults to KUBECONFIG, then ~/.kube/config).")
	fs.BoolVar(&watchPrintOnly, "print-only", false, "Print the rendered manifest instead of creating it.")
	fs.BoolVar(&watchApplication, "application", false, "Create an ApplicationTrace (an application of several workloads) instead of a single PodTrace. Each --app/--label becomes one workload selector.")
}

// newWatchCmd produces the `podtrace watch` subcommand. It is the canonical
// surface for managed, continuous, cluster-wide application tracing; the
// equivalent flags on the root command delegate to runWatch as well.
func newWatchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Create a managed PodTrace that continuously traces an application",
		Long: `Create a PodTrace custom resource that the operator and per-node agents
keep tracing continuously — across all matching namespaces and nodes, surviving
pod restarts and rollouts — until you delete it.

Unlike the default 'podtrace <pod>' command (which attaches eBPF ephemerally and
streams to your terminal), 'watch' is fire-and-forget: it creates the PodTrace and
exits. Events flow to the referenced ExporterConfig, not to this terminal.`,
		Example: `  # Trace an application everywhere, 24/7:
  podtrace watch --app checkout --all-namespaces --exporter otlp-default

  # Arbitrary label selector, scoped to one namespace:
  podtrace watch --label app=api,tier=web -n production --exporter otlp-default

  # Render the manifest without applying it:
  podtrace watch --app checkout --all-namespaces --print-only`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if !cmd.Flags().Changed("namespace") {
				if ctxNamespace, ok := kubernetes.NamespaceFromKubeconfig(watchKubeconfig); ok {
					namespace = ctxNamespace
				}
			}
			return runWatch(ctx, watchOptionsFromFlags())
		},
	}
	registerTargetFlags(cmd.Flags())
	registerWatchOnlyFlags(cmd.Flags())
	cmd.Flags().StringVarP(&namespace, "namespace", "n", config.DefaultNamespace, "Namespace to create the PodTrace in (its ExporterConfig must live here too; defaults to the current kubeconfig context's namespace)")
	cmd.Flags().StringVar(&eventFilter, "filter", "", "Event categories to capture (dns,net,fs,cpu,proc,crypto,usdt); empty = all")
	return cmd
}

// watchOptions is the resolved input to runWatch/buildPodTrace.
type watchOptions struct {
	AppName           string
	Labels            []string
	AllNamespaces     bool
	NamespaceSelector string
	Namespace         string
	Exporter          string
	Name              string
	Filter            string
	SamplePercent     int
	Kubeconfig        string
	PrintOnly         bool
	Application       bool
}

func watchOptionsFromFlags() watchOptions {
	labels := make([]string, 0, len(watchLabels))
	for _, l := range watchLabels {
		if l = strings.TrimSpace(l); l != "" {
			labels = append(labels, l)
		}
	}
	return watchOptions{
		AppName:           strings.TrimSpace(watchAppName),
		Labels:            labels,
		AllNamespaces:     watchAllNamespaces,
		NamespaceSelector: strings.TrimSpace(watchNamespaceSelector),
		Namespace:         namespace,
		Exporter:          strings.TrimSpace(watchExporter),
		Name:              strings.TrimSpace(watchName),
		Filter:            eventFilter,
		SamplePercent:     watchSample,
		Kubeconfig:        watchKubeconfig,
		PrintOnly:         watchPrintOnly,
		Application:       watchApplication,
	}
}

// runWatch builds the PodTrace from opts and either prints it (--print-only)
// or creates it in the cluster after verifying the referenced ExporterConfig
// exists. Client wiring mirrors `schedule trigger` (cmd/podtrace/schedule.go).
func runWatch(ctx context.Context, opts watchOptions) error {
	var obj client.Object
	var kind, name string
	if opts.Application {
		app, err := buildApplicationTrace(opts)
		if err != nil {
			return err
		}
		obj, kind, name = app, "ApplicationTrace", app.Name
	} else {
		pt, err := buildPodTrace(opts)
		if err != nil {
			return err
		}
		obj, kind, name = pt, "PodTrace", pt.Name
	}

	if opts.PrintOnly {
		out, err := marshalManagedYAML(obj, kind)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(out)
		return err
	}

	scheme, err := operator.NewScheme()
	if err != nil {
		return fmt.Errorf("build scheme: %w", err)
	}

	cfg, _, err := kubernetes.ClusterAccess{Kubeconfig: opts.Kubeconfig}.RESTConfig()
	if err != nil {
		return fmt.Errorf("load kubeconfig: %w", err)
	}

	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("build client: %w", err)
	}

	var ec podtracev1alpha1.ExporterConfig
	if err := c.Get(ctx, types.NamespacedName{Namespace: opts.Namespace, Name: opts.Exporter}, &ec); err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf(
				"ExporterConfig %q not found in namespace %q.\n\n"+
					"podtrace watch needs an ExporterConfig to send events to. Either:\n"+
					"  • point at an existing one:  --exporter <name>\n"+
					"      (list them with: kubectl get exporterconfig -n %s)\n"+
					"  • or create one, e.g.:\n"+
					"      kubectl apply -n %s -f - <<'EOF'\n"+
					"      apiVersion: podtrace.io/v1alpha1\n"+
					"      kind: ExporterConfig\n"+
					"      metadata:\n"+
					"        name: %s\n"+
					"      spec:\n"+
					"        type: otlp\n"+
					"        otlp:\n"+
					"          endpoint: otel-collector:4317\n"+
					"      EOF",
				opts.Exporter, opts.Namespace, opts.Namespace, opts.Namespace, opts.Exporter)
		}
		return fmt.Errorf("check ExporterConfig %s/%s: %w", opts.Namespace, opts.Exporter, err)
	}

	if err := c.Create(ctx, obj); err != nil {
		return fmt.Errorf("create %s: %w", kind, err)
	}
	if _, err := fmt.Fprintf(os.Stdout, "podtrace.io/%s %q created in namespace %q\n", kind, name, opts.Namespace); err != nil {
		return fmt.Errorf("write confirmation to stdout: %w", err)
	}
	_, _ = fmt.Fprintf(os.Stdout, "watch status with: kubectl get %s %s -n %s -w\n", strings.ToLower(kind), name, opts.Namespace)
	return nil
}

// targetSelectors parses --app and repeated --label into the workload
// selectors. --app is shorthand for one app.kubernetes.io/name selector;
// each --label is its own selector. The two are mutually exclusive.
func targetSelectors(opts watchOptions) ([]metav1.LabelSelector, error) {
	if opts.AppName == "" && len(opts.Labels) == 0 {
		return nil, errors.New("one of --app or --label is required")
	}
	if opts.AppName != "" && len(opts.Labels) > 0 {
		return nil, errors.New("--app and --label are mutually exclusive")
	}
	if opts.AppName != "" {
		return []metav1.LabelSelector{{MatchLabels: map[string]string{appNameLabel: opts.AppName}}}, nil
	}
	sels := make([]metav1.LabelSelector, 0, len(opts.Labels))
	for _, l := range opts.Labels {
		sel, err := metav1.ParseToLabelSelector(l)
		if err != nil {
			return nil, fmt.Errorf("invalid --label selector %q: %w", l, err)
		}
		sels = append(sels, *sel)
	}
	return sels, nil
}

// commonTargetValidate covers the validation shared by PodTrace and
// ApplicationTrace builders, and returns the resolved namespaceSelector,
// filters, and samplePercent.
func commonTargetValidate(opts watchOptions) (nsSelector *metav1.LabelSelector, filters []podtracev1alpha1.EventFilter, sample *int32, err error) {
	if opts.AllNamespaces && opts.NamespaceSelector != "" {
		return nil, nil, nil, errors.New("--all-namespaces and --namespace-selector are mutually exclusive")
	}
	if opts.Exporter == "" {
		return nil, nil, nil, errors.New("--exporter must not be empty")
	}
	if err := validation.ValidateNamespace(opts.Namespace); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid namespace: %w", err)
	}

	switch {
	case opts.AllNamespaces:
		nsSelector = &metav1.LabelSelector{}
	case opts.NamespaceSelector != "":
		sel, perr := metav1.ParseToLabelSelector(opts.NamespaceSelector)
		if perr != nil {
			return nil, nil, nil, fmt.Errorf("invalid --namespace-selector %q: %w", opts.NamespaceSelector, perr)
		}
		nsSelector = sel
	}

	if opts.Filter != "" {
		if verr := validation.ValidateEventFilter(opts.Filter); verr != nil {
			return nil, nil, nil, verr
		}
		for _, f := range parseCSV(strings.ToLower(opts.Filter)) {
			filters = append(filters, podtracev1alpha1.EventFilter(f))
		}
	}

	if opts.SamplePercent >= 0 {
		if opts.SamplePercent > 100 {
			return nil, nil, nil, fmt.Errorf("--sample must be between 0 and 100, got %d", opts.SamplePercent)
		}
		v := int32(opts.SamplePercent)
		sample = &v
	}
	return nsSelector, filters, sample, nil
}

// buildPodTrace renders a single PodTrace from opts. It is pure (no cluster
// access) so unit tests can exercise selector/namespace/name/filter
// construction directly, mirroring buildManualSession in schedule.go.
func buildPodTrace(opts watchOptions) (*podtracev1alpha1.PodTrace, error) {
	sels, err := targetSelectors(opts)
	if err != nil {
		return nil, err
	}
	if len(sels) > 1 {
		return nil, errors.New("multiple --label selectors target an application of several workloads; use --application (creates an ApplicationTrace)")
	}
	nsSelector, filters, sample, err := commonTargetValidate(opts)
	if err != nil {
		return nil, err
	}
	name, err := deriveWatchName(opts)
	if err != nil {
		return nil, err
	}

	selector := sels[0]
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: opts.Namespace,
			Labels:    map[string]string{"app.kubernetes.io/managed-by": "podtrace-cli"},
		},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:          &selector,
			NamespaceSelector: nsSelector,
			Filters:           filters,
			ExporterRef:       corev1.LocalObjectReference{Name: opts.Exporter},
			SamplePercent:     sample,
		},
	}
	return pt, nil
}

// buildApplicationTrace renders an ApplicationTrace: an application of one or
// more workloads (the union of --app/--label selectors), materialized by the
// operator into a single owned PodTrace using spec.appSelector.
func buildApplicationTrace(opts watchOptions) (*podtracev1alpha1.ApplicationTrace, error) {
	sels, err := targetSelectors(opts)
	if err != nil {
		return nil, err
	}
	nsSelector, filters, sample, err := commonTargetValidate(opts)
	if err != nil {
		return nil, err
	}
	name, err := deriveWatchName(opts)
	if err != nil {
		return nil, err
	}

	app := &podtracev1alpha1.ApplicationTrace{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: opts.Namespace,
			Labels:    map[string]string{"app.kubernetes.io/managed-by": "podtrace-cli"},
		},
		Spec: podtracev1alpha1.ApplicationTraceSpec{
			AppSelector:       podtracev1alpha1.AppSelector{MatchSelectors: sels},
			NamespaceSelector: nsSelector,
			Filters:           filters,
			ExporterRef:       corev1.LocalObjectReference{Name: opts.Exporter},
			SamplePercent:     sample,
		},
	}
	return app, nil
}

// deriveWatchName resolves the created resource's name: explicit --name wins,
// otherwise the --app value is used. --label alone has no natural name, so it
// requires --name. The result must be a valid RFC-1123 DNS label name.
func deriveWatchName(opts watchOptions) (string, error) {
	name := opts.Name
	if name == "" {
		if opts.AppName == "" {
			return "", errors.New("--name is required when targeting with --label (there is no app name to derive the resource name from)")
		}
		name = opts.AppName
	}
	name = strings.ToLower(strings.TrimSpace(name))
	if errs := k8svalidation.IsDNS1123Subdomain(name); len(errs) > 0 {
		return "", fmt.Errorf("invalid resource name %q: %s (override with --name)", name, strings.Join(errs, "; "))
	}
	if len(name) > 63 {
		return "", fmt.Errorf("resource name %q exceeds 63 characters; pass a shorter --name", name)
	}
	return name, nil
}

// marshalManagedYAML renders a PodTrace or ApplicationTrace in the same shape
// `kubectl get -o yaml` would emit (mirrors marshalSessionYAML in
// schedule_yaml.go). It stamps the TypeMeta the in-memory object lacks.
func marshalManagedYAML(obj client.Object, kind string) ([]byte, error) {
	switch o := obj.(type) {
	case *podtracev1alpha1.PodTrace:
		o.APIVersion = podtracev1alpha1.GroupVersion.String()
		o.Kind = kind
	case *podtracev1alpha1.ApplicationTrace:
		o.APIVersion = podtracev1alpha1.GroupVersion.String()
		o.Kind = kind
	}
	return sigsyaml.Marshal(obj)
}
