package v1alpha1

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

// +kubebuilder:webhook:path=/validate-podtrace-io-v1alpha1-applicationtrace,mutating=false,failurePolicy=fail,sideEffects=None,groups=podtrace.io,resources=applicationtraces,verbs=create;update,versions=v1alpha1,name=vapplicationtrace.podtrace.io,admissionReviewVersions=v1

// ApplicationTraceCustomValidator rejects at admission what the operator would
// otherwise only report as Degraded on the generated PodTrace.
type ApplicationTraceCustomValidator struct {
	Client client.Client
}

func SetupApplicationTraceWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &podtracev1alpha1.ApplicationTrace{}).
		WithValidator(&ApplicationTraceCustomValidator{Client: mgr.GetClient()}).
		Complete()
}

var _ admission.Validator[*podtracev1alpha1.ApplicationTrace] = &ApplicationTraceCustomValidator{}

func (v *ApplicationTraceCustomValidator) ValidateCreate(ctx context.Context, app *podtracev1alpha1.ApplicationTrace) (admission.Warnings, error) {
	return v.validate(ctx, app)
}

func (v *ApplicationTraceCustomValidator) ValidateUpdate(ctx context.Context, oldApp, newApp *podtracev1alpha1.ApplicationTrace) (admission.Warnings, error) {
	if oldApp != nil && specUnchanged(oldApp.Spec, newApp.Spec) {
		return nil, nil
	}
	return v.validate(ctx, newApp)
}

func (v *ApplicationTraceCustomValidator) ValidateDelete(_ context.Context, _ *podtracev1alpha1.ApplicationTrace) (admission.Warnings, error) {
	return nil, nil
}

func (v *ApplicationTraceCustomValidator) validate(ctx context.Context, app *podtracev1alpha1.ApplicationTrace) (admission.Warnings, error) {
	if len(app.Name) > podtracev1alpha1.MaxManagedCRNameLength {
		return nil, fmt.Errorf("metadata.name is %d characters; ApplicationTrace names are limited to %d because the name is stamped into a Kubernetes label value",
			len(app.Name), podtracev1alpha1.MaxManagedCRNameLength)
	}
	if len(app.Spec.AppSelector.MatchSelectors) == 0 {
		return nil, fmt.Errorf("spec.appSelector.matchSelectors: at least one selector is required")
	}
	for i := range app.Spec.AppSelector.MatchSelectors {
		if _, err := metav1.LabelSelectorAsSelector(&app.Spec.AppSelector.MatchSelectors[i]); err != nil {
			return nil, fmt.Errorf("spec.appSelector.matchSelectors[%d]: %w", i, err)
		}
	}
	if err := validateNamespaceSelector(app.Spec.NamespaceSelector); err != nil {
		return nil, err
	}
	if err := resolveExporterRef(ctx, v.Client, app.Namespace, app.Spec.ExporterRef.Name); err != nil {
		return nil, err
	}
	return validateCrossNamespaceGrants(ctx, v.Client, app.Namespace, nil, app.Spec.NamespaceSelector)
}
