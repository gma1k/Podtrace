// SPDX-License-Identifier: Apache-2.0

package nodespawn

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// createSplunkTokenSecret creates the Secret that backs the spawn pod's
// PODTRACE_SPLUNK_TOKEN SecretKeyRef.
func createSplunkTokenSecret(ctx context.Context, cs kubernetes.Interface, namespace, name string, labels map[string]string, token string) error {
	return createSpawnSecret(ctx, cs, namespace, name, labels, spawnSecretData(token, nil))
}

// spawnSecretData is everything the spawn pod reads from its Secret: the
// Splunk token under its fixed key, and each SecretEnv value under the name
// of the environment variable it becomes.
func spawnSecretData(splunkToken string, secretEnv map[string]string) map[string]string {
	data := make(map[string]string, len(secretEnv)+1)
	if splunkToken != "" {
		data[SplunkSecretKey] = splunkToken
	}
	for name, value := range secretEnv {
		data[name] = value
	}
	return data
}

// createSpawnSecret creates the Secret behind the spawn pod's SecretKeyRefs,
// so credentials never appear in its args, which anyone who can read pods
// in the namespace can see.
func createSpawnSecret(ctx context.Context, cs kubernetes.Interface, namespace, name string, labels map[string]string, data map[string]string) error {
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Type:       corev1.SecretTypeOpaque,
		StringData: data,
	}
	_, err := cs.CoreV1().Secrets(namespace).Create(ctx, sec, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("nodespawn: create secret %s/%s: %w", namespace, name, err)
	}
	return nil
}

// ownSecretByPod makes the spawn pod the owner of its token Secret so the
// Kubernetes garbage collector deletes the Secret when the pod is deleted,
// covering the crash path where the CLI dies before explicit cleanup and the
// reaper removes the pod later.
func ownSecretByPod(ctx context.Context, cs kubernetes.Interface, pod *corev1.Pod, secretName string) error {
	sec, err := cs.CoreV1().Secrets(pod.Namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	sec.OwnerReferences = append(sec.OwnerReferences, metav1.OwnerReference{
		APIVersion: "v1",
		Kind:       "Pod",
		Name:       pod.Name,
		UID:        pod.UID,
	})
	_, err = cs.CoreV1().Secrets(pod.Namespace).Update(ctx, sec, metav1.UpdateOptions{})
	return err
}

// DeleteSecret best-effort deletes a spawn Secret; NotFound is swallowed so
// parallel reapers and owner-reference GC racing the explicit delete do not
// error out.
func DeleteSecret(ctx context.Context, cs kubernetes.Interface, namespace, name string) error {
	err := cs.CoreV1().Secrets(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	if err == nil || IsNotFound(err) {
		return nil
	}
	return fmt.Errorf("nodespawn: delete secret %s/%s: %w", namespace, name, err)
}
