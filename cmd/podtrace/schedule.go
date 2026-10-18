package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	utilrand "k8s.io/apimachinery/pkg/util/rand"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/kubernetes"
	"github.com/gma1k/podtrace/internal/operator"
)

// newScheduleCmd produces the `podtrace schedule` command tree. The
// only sub-verb today is `trigger`, which materialises a one-off
// PodTraceSession from the named PodTraceSchedule's template.
func newScheduleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "schedule",
		Short: "Manage PodTraceSchedule resources",
		Long: `Operate on PodTraceSchedule resources. The schedule controller fires
a new PodTraceSession on each cron tick; this command exposes
operations that complement that loop (e.g. one-off manual triggers).`,
	}
	cmd.AddCommand(newScheduleTriggerCmd())
	return cmd
}

func newScheduleTriggerCmd() *cobra.Command {
	var (
		namespace    string
		force        bool
		kubeconfig   string
		printSession bool
	)

	cmd := &cobra.Command{
		Use:          "trigger <schedule-name>",
		Short:        "Fire a one-off PodTraceSession from a PodTraceSchedule's template",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		Long: `Create an immediate PodTraceSession from the named PodTraceSchedule's
sessionTemplate. The session is owned by the schedule (it shows up in
status.active and counts against the same history limits) unless
--force is given, in which case the session has no owner reference and
will not be subject to spec.concurrencyPolicy=Forbid/Replace.

Examples:
  # Honour the schedule's concurrency policy (recommended).
  kubectl podtrace schedule trigger nightly-diagnose -n observability

  # Override: emergency diagnose that bypasses Forbid/Replace.
  kubectl podtrace schedule trigger nightly-diagnose -n observability --force
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(ctrl.SetupSignalHandler(), 30*time.Second)
			defer cancel()
			return runScheduleTrigger(ctx, scheduleTriggerOptions{
				Name:         args[0],
				Namespace:    namespace,
				Force:        force,
				Kubeconfig:   kubeconfig,
				PrintSession: printSession,
			})
		},
	}
	cmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Namespace of the PodTraceSchedule (required)")
	cmd.Flags().BoolVar(&force, "force", false, "Bypass the schedule's concurrencyPolicy and suspend gate")
	cmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to a kubeconfig file (defaults to KUBECONFIG, then ~/.kube/config)")
	cmd.Flags().BoolVar(&printSession, "print-only", false, "Print the rendered session manifest instead of applying it")
	_ = cmd.MarkFlagRequired("namespace")
	return cmd
}

type scheduleTriggerOptions struct {
	Name         string
	Namespace    string
	Force        bool
	Kubeconfig   string
	PrintSession bool
}

func runScheduleTrigger(ctx context.Context, opts scheduleTriggerOptions) error {
	if opts.Name == "" {
		return errors.New("schedule name is required")
	}
	if opts.Namespace == "" {
		return errors.New("--namespace is required")
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

	var sch podtracev1alpha1.PodTraceSchedule
	if err := c.Get(ctx, types.NamespacedName{Namespace: opts.Namespace, Name: opts.Name}, &sch); err != nil {
		return fmt.Errorf("get PodTraceSchedule %s/%s: %w", opts.Namespace, opts.Name, err)
	}

	now := time.Now().UTC()
	session := buildManualSession(&sch, now, opts.Force)

	if opts.PrintSession {
		return printSessionYAML(session)
	}

	if !opts.Force && sch.Spec.Suspend != nil && *sch.Spec.Suspend {
		return fmt.Errorf("schedule %s/%s is suspended; pass --force to trigger anyway", opts.Namespace, opts.Name)
	}

	if err := c.Create(ctx, session); err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	if _, err := fmt.Fprintf(os.Stdout, "podtracesession.podtrace.io/%s created\n", session.Name); err != nil {
		return fmt.Errorf("write confirmation to stdout: %w", err)
	}
	return nil
}

// buildManualSession is split out so the unit test can exercise the
// owner-reference logic without a fake client.
func buildManualSession(sch *podtracev1alpha1.PodTraceSchedule, now time.Time, force bool) *podtracev1alpha1.PodTraceSession {
	name := manualSessionName(sch.Name, now)
	session := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: sch.Namespace,
			Labels: map[string]string{
				"podtrace.io/schedule": sch.Name,
				"podtrace.io/trigger":  "manual",
			},
			Annotations: map[string]string{
				"podtrace.io/triggered-at": now.Format(time.RFC3339),
			},
		},
		Spec: *sch.Spec.SessionTemplate.Spec.DeepCopy(),
	}
	for k, v := range sch.Spec.SessionTemplate.Metadata.Labels {
		if _, ok := session.Labels[k]; !ok {
			session.Labels[k] = v
		}
	}
	for k, v := range sch.Spec.SessionTemplate.Metadata.Annotations {
		if _, ok := session.Annotations[k]; !ok {
			session.Annotations[k] = v
		}
	}
	if !force {
		controller := true
		session.OwnerReferences = []metav1.OwnerReference{{
			APIVersion: podtracev1alpha1.GroupVersion.String(),
			Kind:       "PodTraceSchedule",
			Name:       sch.Name,
			UID:        sch.UID,
			Controller: &controller,
		}}
	}
	return session
}

// manualSessionName stamps the trigger time and a random suffix: a second
// is too coarse on its own, and two triggers in the same second would
// collide with AlreadyExists.
func manualSessionName(scheduleName string, t time.Time) string {
	stamp := strconv.FormatInt(t.Unix(), 10) + "-" + utilrand.String(5)
	raw := scheduleName + "-manual-" + stamp
	if len(raw) > 63 {
		trail := "-manual-" + stamp
		raw = scheduleName[:63-len(trail)] + trail
	}
	return raw
}

// printSessionYAML emits the rendered session to stdout. Keeps a
// dry-run path for users to inspect what would be applied.
func printSessionYAML(s *podtracev1alpha1.PodTraceSession) error {
	out, err := marshalSessionYAML(s)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(out)
	return err
}
