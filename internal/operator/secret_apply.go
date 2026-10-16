package operator

import (
	"bytes"
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// applySecret makes the live Secret match desired without going through the
// manager cache, whose Secret transform drops Data: a CreateOrUpdate against
// the cache sees an empty Secret on every pass and rewrites it every time.
func applySecret(ctx context.Context, c client.Client, reader client.Reader, desired *corev1.Secret) error {
	if desired.Type == "" {
		desired.Type = corev1.SecretTypeOpaque
	}
	var live corev1.Secret
	err := reader.Get(ctx, client.ObjectKeyFromObject(desired), &live)
	if apierrors.IsNotFound(err) {
		return c.Create(ctx, desired.DeepCopy())
	}
	if err != nil {
		return fmt.Errorf("read Secret %s/%s: %w", desired.Namespace, desired.Name, err)
	}
	if secretMatches(&live, desired) {
		return nil
	}
	if live.Type == desired.Type {
		updated := live.DeepCopy()
		updated.Labels = mergeLabels(updated.Labels, desired.Labels)
		updated.Annotations = mergeLabels(updated.Annotations, desired.Annotations)
		updated.Data = desired.Data
		updated.StringData = nil
		err := c.Update(ctx, updated)
		if err == nil || !apierrors.IsForbidden(err) {
			return err
		}
	}
	return replaceSecret(ctx, c, &live, desired)
}

// replaceSecret deletes the live Secret (pinned to its UID so a concurrent
// replacement is never removed) and creates desired in its place.
func replaceSecret(ctx context.Context, c client.Client, live, desired *corev1.Secret) error {
	uid := live.UID
	if err := c.Delete(ctx, live, client.Preconditions{UID: &uid}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("replace Secret %s/%s: delete: %w", live.Namespace, live.Name, err)
	}
	if err := c.Create(ctx, desired.DeepCopy()); err != nil {
		return fmt.Errorf("replace Secret %s/%s: create: %w", desired.Namespace, desired.Name, err)
	}
	return nil
}

func secretMatches(live, desired *corev1.Secret) bool {
	if live.Type != desired.Type || len(live.Data) != len(desired.Data) {
		return false
	}
	for k, v := range desired.Data {
		got, ok := live.Data[k]
		if !ok || !bytes.Equal(got, v) {
			return false
		}
	}
	return mapContains(live.Labels, desired.Labels) && mapContains(live.Annotations, desired.Annotations)
}

func mapContains(have, want map[string]string) bool {
	for k, v := range want {
		if got, ok := have[k]; !ok || got != v {
			return false
		}
	}
	return true
}
