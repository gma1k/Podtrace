package operator

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func syncBundleTestPodTrace() *podtracev1alpha1.PodTrace {
	return &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: "team-a", UID: "pt-uid"},
	}
}

func TestSyncExporterBundle_RenderError(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &PodTraceReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}

	ec := &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "ec", Namespace: "team-a"},
		Spec:       podtracev1alpha1.ExporterConfigSpec{Type: podtracev1alpha1.ExporterTypeOTLP},
	}
	if err := r.syncExporterBundle(context.Background(), syncBundleTestPodTrace(), ec, []string{"team-a"}, []string{"podtrace-system"}); err == nil {
		t.Fatal("an OTLP ExporterConfig with a nil OTLP block must fail bundle rendering")
	}
}

func TestSyncExporterBundle_SecretCreateError(t *testing.T) {
	scheme := newOperatorScheme(t)
	headers := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "hdr", Namespace: "team-a"},
		Data:       map[string][]byte{"Authorization": []byte("Bearer x")},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(headers).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if _, ok := obj.(*corev1.Secret); ok {
					return errInternal()
				}
				return cl.Create(ctx, obj, opts...)
			},
		}).Build()
	r := &PodTraceReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}

	ec := &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "ec", Namespace: "team-a"},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{
				Endpoint:          "otel:4318",
				Protocol:          podtracev1alpha1.OTLPProtocolHTTP,
				HeadersFromSecret: &corev1.LocalObjectReference{Name: "hdr"},
			},
		},
	}
	if err := r.syncExporterBundle(context.Background(), syncBundleTestPodTrace(), ec, []string{"team-a"}, []string{"podtrace-system"}); err == nil {
		t.Fatal("a failing bundle Secret create-or-update must be surfaced")
	}
}
