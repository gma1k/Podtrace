package v1alpha1

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

// +kubebuilder:webhook:path=/validate-podtrace-io-v1alpha1-podtraceschedule,mutating=false,failurePolicy=fail,sideEffects=None,groups=podtrace.io,resources=podtraceschedules,verbs=create;update,versions=v1alpha1,name=vpodtraceschedule.podtrace.io,admissionReviewVersions=v1

// PodTraceScheduleCustomValidator enforces admission-time invariants on
// PodTraceSchedule resources: cron syntax, time zone validity, and
// (recursively) the embedded SessionTemplate spec, so a schedule cannot
// fire sessions that would themselves be rejected.
type PodTraceScheduleCustomValidator struct {
	Client          client.Client
	SystemNamespace string
}

func SetupPodTraceScheduleWebhookWithManager(mgr ctrl.Manager, systemNamespace string) error {
	return ctrl.NewWebhookManagedBy(mgr, &podtracev1alpha1.PodTraceSchedule{}).
		WithValidator(&PodTraceScheduleCustomValidator{Client: mgr.GetClient(), SystemNamespace: systemNamespace}).
		Complete()
}

var _ admission.Validator[*podtracev1alpha1.PodTraceSchedule] = &PodTraceScheduleCustomValidator{}

func (v *PodTraceScheduleCustomValidator) ValidateCreate(ctx context.Context, s *podtracev1alpha1.PodTraceSchedule) (admission.Warnings, error) {
	return v.validate(ctx, s)
}

func (v *PodTraceScheduleCustomValidator) ValidateUpdate(ctx context.Context, oldSchedule, newSchedule *podtracev1alpha1.PodTraceSchedule) (admission.Warnings, error) {
	if oldSchedule != nil && specUnchanged(oldSchedule.Spec, newSchedule.Spec) {
		return nil, nil
	}
	return v.validate(ctx, newSchedule)
}

func (v *PodTraceScheduleCustomValidator) ValidateDelete(_ context.Context, _ *podtracev1alpha1.PodTraceSchedule) (admission.Warnings, error) {
	return nil, nil
}

func (v *PodTraceScheduleCustomValidator) validate(ctx context.Context, s *podtracev1alpha1.PodTraceSchedule) (admission.Warnings, error) {
	if len(s.Name) > podtracev1alpha1.MaxManagedCRNameLength {
		return nil, fmt.Errorf("metadata.name is %d characters; PodTraceSchedule names are limited to %d because the name is stamped into the podtrace.io/schedule label of every session",
			len(s.Name), podtracev1alpha1.MaxManagedCRNameLength)
	}
	hasSchedule := s.Spec.Schedule != ""
	hasTrigger := s.Spec.Trigger != nil
	switch {
	case hasSchedule && hasTrigger:
		return nil, fmt.Errorf("spec: set exactly one of schedule or trigger, not both")
	case !hasSchedule && !hasTrigger:
		return nil, fmt.Errorf("spec: exactly one of schedule or trigger is required")
	}

	var warnings admission.Warnings

	if hasSchedule {
		if _, err := podtracev1alpha1.ParseSchedule(s.Spec.Schedule); err != nil {
			return nil, fmt.Errorf("spec.schedule: %w", err)
		}
		if s.Spec.TimeZone != nil && *s.Spec.TimeZone != "" {
			if _, err := time.LoadLocation(*s.Spec.TimeZone); err != nil {
				return nil, fmt.Errorf("spec.timeZone: %w", err)
			}
		}
		if err := validateConcurrencyPolicy("spec.concurrencyPolicy", s.Spec.ConcurrencyPolicy); err != nil {
			return nil, err
		}
	}

	if hasTrigger {
		tw, err := v.validateTrigger(ctx, s)
		if err != nil {
			return nil, err
		}
		warnings = append(warnings, tw...)
	}

	tmpl := &s.Spec.SessionTemplate.Spec
	if err := validateSelectorExclusivity(tmpl.Selector, tmpl.PodRefs); err != nil {
		return nil, fmt.Errorf("spec.sessionTemplate.spec.%w", err)
	}
	if err := validateNamespaceSelector(tmpl.NamespaceSelector); err != nil {
		return nil, fmt.Errorf("spec.sessionTemplate.%w", err)
	}
	if tmpl.Duration.Duration <= 0 {
		return nil, fmt.Errorf("spec.sessionTemplate.spec.duration must be greater than zero")
	}
	if err := resolveSessionExporterRef(ctx, v.Client, s.Namespace, tmpl.ExporterRef.Name); err != nil {
		return nil, fmt.Errorf("spec.sessionTemplate.%w", err)
	}
	if err := resolveTracerConfigRef(ctx, v.Client, tmpl.TracerConfigRef, s.Namespace, v.SystemNamespace); err != nil {
		return nil, fmt.Errorf("spec.sessionTemplate.%w", err)
	}
	if err := validateReportRef(tmpl.ReportRef); err != nil {
		return nil, fmt.Errorf("spec.sessionTemplate.%w", err)
	}
	if err := podtracev1alpha1.ValidateSessionTemplateMetadata(s.Spec.SessionTemplate.Metadata); err != nil {
		return nil, err
	}
	tmplWarnings, err := validateCrossNamespaceGrants(ctx, v.Client, s.Namespace, tmpl.PodRefs, tmpl.NamespaceSelector)
	if err != nil {
		return nil, fmt.Errorf("spec.sessionTemplate.%w", err)
	}
	warnings = append(warnings, tmplWarnings...)
	return warnings, nil
}

// validateConcurrencyPolicy enforces the ConcurrencyPolicy enum for the
// named field (empty is allowed and resolved to a default by the controller).
func validateConcurrencyPolicy(field string, p podtracev1alpha1.ConcurrencyPolicy) error {
	switch p {
	case "", podtracev1alpha1.AllowConcurrent, podtracev1alpha1.ForbidConcurrent, podtracev1alpha1.ReplaceConcurrent:
		return nil
	default:
		return fmt.Errorf("%s: unknown policy %q", field, p)
	}
}

// validateTrigger enforces the trigger-mode invariants: at least one source,
// a known concurrency policy, well-formed label selectors, and target
// namespace consent for a cross-namespace NamespaceSelector (surfaced as a
// warning, matching the schedule/session grant-gap feedback).
func (v *PodTraceScheduleCustomValidator) validateTrigger(ctx context.Context, s *podtracev1alpha1.PodTraceSchedule) (admission.Warnings, error) {
	tr := s.Spec.Trigger
	if len(tr.Sources) == 0 {
		return nil, fmt.Errorf("spec.trigger.sources: at least one source is required")
	}
	if err := validateConcurrencyPolicy("spec.trigger.concurrencyPolicy", tr.ConcurrencyPolicy); err != nil {
		return nil, err
	}
	for _, sel := range []struct {
		field string
		ls    *metav1.LabelSelector
	}{
		{"spec.trigger.selector", tr.Selector},
		{"spec.trigger.namespaceSelector", tr.NamespaceSelector},
	} {
		if sel.ls == nil {
			continue
		}
		if _, err := metav1.LabelSelectorAsSelector(sel.ls); err != nil {
			return nil, fmt.Errorf("%s: %w", sel.field, err)
		}
	}
	return validateCrossNamespaceGrants(ctx, v.Client, s.Namespace, nil, tr.NamespaceSelector)
}
