package operator

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/reportsink/objectstore"
)

func TestCheckSessionObjectStorePolicy_SecretReadErrorIsReported(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return errInternal()
		},
	}).Build()
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "team-a"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{ReportRef: &podtracev1alpha1.ReportReference{ObjectStore: &podtracev1alpha1.ObjectStoreReference{
			URI:                  "s3://bucket/reports/",
			CredentialsSecretRef: &corev1.LocalObjectReference{Name: "creds"},
		}}},
	}

	err := checkSessionObjectStorePolicy(context.Background(), cl, s, objectstore.CredentialPolicy{AllowAmbientCredentials: true})
	if err == nil || !strings.Contains(err.Error(), "get objectstore credentials Secret team-a/creds") || !apierrors.IsInternalError(err) {
		t.Fatalf("err = %v, want the wrapped Secret read failure", err)
	}
	if strings.Contains(err.Error(), "not found") {
		t.Fatalf("a transient read error must not be reported as a missing Secret: %v", err)
	}
}
