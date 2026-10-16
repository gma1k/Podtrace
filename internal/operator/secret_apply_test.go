package operator

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func desiredBundleSecret(value string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "bundle",
			Namespace: "fleet-system",
			Labels:    map[string]string{LabelComponent: ComponentBundle},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{"credential": []byte(value)},
	}
}

type secretWrites struct {
	creates, updates, deletes int
}

func secretApplyClient(t *testing.T, writes *secretWrites, forbidUpdate bool, objects ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).WithObjects(objects...).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				writes.creates++
				return cl.Create(ctx, obj, opts...)
			},
			Update: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				writes.updates++
				if forbidUpdate {
					return apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, obj.GetName(), nil)
				}
				return cl.Update(ctx, obj, opts...)
			},
			Delete: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
				writes.deletes++
				return cl.Delete(ctx, obj, opts...)
			},
		}).Build()
}

func liveSecretValue(t *testing.T, c client.Client) string {
	t.Helper()
	var got corev1.Secret
	if err := c.Get(context.Background(), types.NamespacedName{Name: "bundle", Namespace: "fleet-system"}, &got); err != nil {
		t.Fatal(err)
	}
	return string(got.Data["credential"])
}

func TestApplySecret_CreatesMissingSecret(t *testing.T) {
	writes := &secretWrites{}
	c := secretApplyClient(t, writes, false)
	if err := applySecret(context.Background(), c, c, desiredBundleSecret("v1")); err != nil {
		t.Fatal(err)
	}
	if writes.creates != 1 || liveSecretValue(t, c) != "v1" {
		t.Errorf("want one create of v1, got %+v value %q", writes, liveSecretValue(t, c))
	}
}

func TestApplySecret_UnchangedSecretIsNotWritten(t *testing.T) {
	writes := &secretWrites{}
	c := secretApplyClient(t, writes, false, desiredBundleSecret("v1"))
	if err := applySecret(context.Background(), c, c, desiredBundleSecret("v1")); err != nil {
		t.Fatal(err)
	}
	if *writes != (secretWrites{}) {
		t.Errorf("a Secret already matching must not be written, got %+v", writes)
	}
}

func TestApplySecret_ChangedSecretIsUpdated(t *testing.T) {
	writes := &secretWrites{}
	c := secretApplyClient(t, writes, false, desiredBundleSecret("v1"))
	if err := applySecret(context.Background(), c, c, desiredBundleSecret("v2")); err != nil {
		t.Fatal(err)
	}
	if writes.updates != 1 || writes.deletes != 0 || liveSecretValue(t, c) != "v2" {
		t.Errorf("want one in-place update to v2, got %+v value %q", writes, liveSecretValue(t, c))
	}
}

func TestApplySecret_ForbiddenUpdateReplacesSecret(t *testing.T) {
	writes := &secretWrites{}
	c := secretApplyClient(t, writes, true, desiredBundleSecret("v1"))
	if err := applySecret(context.Background(), c, c, desiredBundleSecret("v2")); err != nil {
		t.Fatal(err)
	}
	if writes.deletes != 1 || writes.creates != 1 || liveSecretValue(t, c) != "v2" {
		t.Errorf("a forbidden update must fall back to delete and create, got %+v value %q", writes, liveSecretValue(t, c))
	}
}

func TestApplySecret_TypeChangeReplacesSecret(t *testing.T) {
	writes := &secretWrites{}
	live := desiredBundleSecret("v1")
	live.Type = corev1.SecretTypeBasicAuth
	c := secretApplyClient(t, writes, false, live)
	if err := applySecret(context.Background(), c, c, desiredBundleSecret("v1")); err != nil {
		t.Fatal(err)
	}
	if writes.updates != 0 || writes.deletes != 1 || writes.creates != 1 {
		t.Errorf("an immutable type change must replace the Secret, got %+v", writes)
	}
}
