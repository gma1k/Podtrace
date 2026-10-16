package v1alpha1

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestTracerConfigWebhook_ReservedSystemNamespaceRejected(t *testing.T) {
	tc := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "fleet"},
		Spec:       podtracev1alpha1.TracerConfigSpec{Image: "ghcr.io/gma1k/podtrace:v1", SystemNamespace: "kube-system"},
	}
	_, err := (&TracerConfigCustomValidator{}).validate(context.Background(), tc)
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("a fleet in kube-system must be rejected at admission, got %v", err)
	}
}
