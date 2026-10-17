package agent

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestStatusWriter_FailedRetractIsRetriedNextTick(t *testing.T) {
	failing := true
	calls := 0
	c := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceApply: func(_ context.Context, _ client.Client, _ string, _ runtime.ApplyConfiguration, _ ...client.SubResourceApplyOption) error {
				calls++
				if failing {
					return errSyntheticApply
				}
				return nil
			},
		}).Build()

	stale := CRKey{Namespace: "ns", Name: "stale"}
	w := &StatusWriter{Client: c, NodeName: "n", Router: NewRouter(nil), Ready: func() bool { return true }}
	w.reportedKeys = map[CRKey]struct{}{stale: {}}

	if err := w.emitOnce(context.Background()); err == nil {
		t.Fatal("expected the retract error to surface")
	}
	if _, ok := w.reportedKeys[stale]; !ok {
		t.Fatal("key whose retraction failed must stay tracked for retry")
	}

	failing = false
	if err := w.emitOnce(context.Background()); err != nil {
		t.Fatalf("retry tick: %v", err)
	}
	if calls != 2 {
		t.Errorf("retract attempts = %d, want 2", calls)
	}
	if _, ok := w.reportedKeys[stale]; ok {
		t.Error("key should be dropped once the retraction succeeds")
	}
}
