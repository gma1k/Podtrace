//go:build envtest
// +build envtest

package operator

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	podtraceac "github.com/gma1k/podtrace/pkg/client/applyconfiguration/api/v1alpha1"
)

func TestPodTraceReconciler_EnvtestBundleSync_OTLPLiteral(t *testing.T) {
	scheme, c, ns := setupSharedEnvtest(t)
	systemNS := ensureSystemNamespace(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ec := &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "otlp", Namespace: ns},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "otel:4318", Protocol: podtracev1alpha1.OTLPProtocolHTTP},
		},
	}
	if err := c.Create(ctx, ec); err != nil {
		t.Fatal(err)
	}

	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "trace", Namespace: ns},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			ExporterRef: corev1.LocalObjectReference{Name: "otlp"},
		},
	}
	if err := c.Create(ctx, pt); err != nil {
		t.Fatal(err)
	}

	r := &PodTraceReconciler{Client: c, Scheme: scheme, SystemNamespace: systemNS}
	bundleName := ExporterBundleName(pt.UID)

	reconcileUntil(t, 10*time.Second,
		func() error {
			var cm corev1.ConfigMap
			return c.Get(ctx, types.NamespacedName{Name: bundleName, Namespace: systemNS}, &cm)
		},
		func() error {
			_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: pt.Name, Namespace: ns}})
			return err
		},
	)

	var cm corev1.ConfigMap
	if err := c.Get(ctx, types.NamespacedName{Name: bundleName, Namespace: systemNS}, &cm); err != nil {
		t.Fatalf("bundle ConfigMap missing: %v", err)
	}
	if cm.Data["type"] != "otlp" || cm.Data["endpoint"] != "otel."+ns+".svc:4318" {
		t.Errorf("bundle data wrong: %+v", cm.Data)
	}
	// Credential-less exporter → no companion Secret.
	var secret corev1.Secret
	err := c.Get(ctx, types.NamespacedName{Name: bundleName, Namespace: systemNS}, &secret)
	if err == nil {
		t.Error("companion Secret should not exist for credential-less OTLP")
	}
}

func TestPodTraceReconciler_EnvtestBundleSync_SecretCredentials(t *testing.T) {
	scheme, c, ns := setupSharedEnvtest(t)
	systemNS := ensureSystemNamespace(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := c.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "dd-key", Namespace: ns},
		Data:       map[string][]byte{"api": []byte("super-secret-token")},
	}); err != nil {
		t.Fatal(err)
	}

	ec := &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "dd", Namespace: ns},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeDataDog,
			DataDog: &podtracev1alpha1.DataDogExporter{
				Site:            "datadoghq.eu",
				APIKeySecretRef: podtracev1alpha1.SecretKeySelector{Name: "dd-key", Key: "api"},
			},
		},
	}
	if err := c.Create(ctx, ec); err != nil {
		t.Fatal(err)
	}

	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "dd-trace", Namespace: ns},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
			ExporterRef: corev1.LocalObjectReference{Name: "dd"},
		},
	}
	if err := c.Create(ctx, pt); err != nil {
		t.Fatal(err)
	}

	r := &PodTraceReconciler{Client: c, Scheme: scheme, SystemNamespace: systemNS}
	bundleName := ExporterBundleName(pt.UID)

	reconcileUntil(t, 10*time.Second,
		func() error {
			var s corev1.Secret
			return c.Get(ctx, types.NamespacedName{Name: bundleName, Namespace: systemNS}, &s)
		},
		func() error {
			_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: pt.Name, Namespace: ns}})
			return err
		},
	)

	var bundle corev1.Secret
	if err := c.Get(ctx, types.NamespacedName{Name: bundleName, Namespace: systemNS}, &bundle); err != nil {
		t.Fatalf("bundle Secret missing: %v", err)
	}
	if string(bundle.Data["credential"]) != "super-secret-token" {
		t.Errorf("bundle credential not copied: %q", bundle.Data["credential"])
	}

	var cm corev1.ConfigMap
	if err := c.Get(ctx, types.NamespacedName{Name: bundleName, Namespace: systemNS}, &cm); err != nil {
		t.Fatalf("bundle ConfigMap missing: %v", err)
	}
	if cm.Data["site"] != "datadoghq.eu" {
		t.Errorf("site not carried in bundle: %+v", cm.Data)
	}
}

func TestPodTraceReconciler_EnvtestExporterRefMissing(t *testing.T) {
	scheme, c, ns := setupSharedEnvtest(t)
	systemNS := ensureSystemNamespace(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "orphan", Namespace: ns},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
			ExporterRef: corev1.LocalObjectReference{Name: "does-not-exist"},
		},
	}
	if err := c.Create(ctx, pt); err != nil {
		t.Fatal(err)
	}

	r := &PodTraceReconciler{Client: c, Scheme: scheme, SystemNamespace: systemNS}

	reconcileUntil(t, 10*time.Second,
		func() error {
			var got podtracev1alpha1.PodTrace
			if err := c.Get(ctx, types.NamespacedName{Name: pt.Name, Namespace: ns}, &got); err != nil {
				return err
			}
			if !conditionIs(got.Status.Conditions, ConditionDegraded, metav1.ConditionTrue) {
				return fmt.Errorf("Degraded not yet True: %+v", got.Status.Conditions)
			}
			return nil
		},
		func() error {
			_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: pt.Name, Namespace: ns}})
			return err
		},
	)

	var got podtracev1alpha1.PodTrace
	if err := c.Get(ctx, types.NamespacedName{Name: pt.Name, Namespace: ns}, &got); err != nil {
		t.Fatal(err)
	}
	if !conditionIs(got.Status.Conditions, ConditionReady, metav1.ConditionFalse) {
		t.Errorf("expected Ready=False, got %+v", got.Status.Conditions)
	}
}

func TestPodTraceReconciler_DegradedRollupFromNodeStatus(t *testing.T) {
	scheme, c, ns := setupSharedEnvtest(t)
	systemNS := ensureSystemNamespace(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ec := &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "otlp", Namespace: ns},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "otel:4318", Protocol: podtracev1alpha1.OTLPProtocolHTTP},
		},
	}
	if err := c.Create(ctx, ec); err != nil {
		t.Fatal(err)
	}
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "with-agent-failure", Namespace: ns},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
			ExporterRef: corev1.LocalObjectReference{Name: "otlp"},
		},
	}
	if err := c.Create(ctx, pt); err != nil {
		t.Fatal(err)
	}

	r := &PodTraceReconciler{Client: c, Scheme: scheme, SystemNamespace: systemNS}

	reconcileUntil(t, 10*time.Second,
		func() error {
			var got podtracev1alpha1.PodTrace
			if err := c.Get(ctx, types.NamespacedName{Name: pt.Name, Namespace: ns}, &got); err != nil {
				return err
			}
			if !conditionIs(got.Status.Conditions, ConditionDegraded, metav1.ConditionFalse) {
				return fmt.Errorf("Degraded not yet False (baseline): %+v", got.Status.Conditions)
			}
			return nil
		},
		func() error {
			_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: pt.Name, Namespace: ns}})
			return err
		},
	)

	// PodTraceNodeStatus's int counters are non-omitempty in the CRD
	// schema (kubebuilder rejects the patch otherwise), so set them
	// explicitly to zero even when the row is just carrying a failure
	// message. The production agent does the same in status_writer.go.
	agentPatch := podtraceac.PodTrace(pt.Name, ns).
		WithStatus(podtraceac.PodTraceStatus().
			WithNodeStatus(podtraceac.PodTraceNodeStatus().
				WithNode("broken-1").
				WithReady(false).
				WithActiveCgroups(0).
				WithTotalEvents(0).
				WithDroppedEvents(0).
				WithMessage("build exporter: exporter type \"jaeger\" not yet implemented in agent mode").
				WithLastHeartbeat(metav1.Now())))
	if err := c.Status().Apply(ctx, agentPatch,
		client.FieldOwner("podtrace-agent-broken-1"),
		client.ForceOwnership,
	); err != nil {
		t.Fatalf("agent status patch: %v", err)
	}

	reconcileUntil(t, 10*time.Second,
		func() error {
			var got podtracev1alpha1.PodTrace
			if err := c.Get(ctx, types.NamespacedName{Name: pt.Name, Namespace: ns}, &got); err != nil {
				return err
			}
			var cond *metav1.Condition
			for i := range got.Status.Conditions {
				if got.Status.Conditions[i].Type == ConditionDegraded {
					cond = &got.Status.Conditions[i]
					break
				}
			}
			if cond == nil {
				return fmt.Errorf("Degraded condition missing")
			}
			if cond.Status != metav1.ConditionTrue {
				return fmt.Errorf("Degraded status = %q, want True", cond.Status)
			}
			if cond.Reason != "AgentNodeStatus" {
				return fmt.Errorf("Degraded reason = %q, want AgentNodeStatus", cond.Reason)
			}
			if !strings.Contains(cond.Message, "broken-1") {
				return fmt.Errorf("Degraded message = %q, want it to name node 'broken-1'", cond.Message)
			}
			if !strings.Contains(cond.Message, "not yet implemented") {
				return fmt.Errorf("Degraded message = %q, want it to surface the agent's cause", cond.Message)
			}
			return nil
		},
		func() error {
			_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: pt.Name, Namespace: ns}})
			return err
		},
	)
}

func conditionIs(conds []metav1.Condition, condType string, want metav1.ConditionStatus) bool {
	for _, c := range conds {
		if c.Type == condType {
			return c.Status == want
		}
	}
	return false
}
