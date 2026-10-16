package operator

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

// SessionObjectStoreCredsName is the name of the system-namespace
// Secret the operator stamps with a verbatim copy of the user-supplied
// ObjectStore credentials.
func SessionObjectStoreCredsName(sessionUID types.UID) string {
	return "pts-objstore-" + shortUID(sessionUID)
}

// ensureSessionObjectStoreCredentials copies the user's
// CredentialsSecretRef Secret from the session's namespace into
// systemNS.
func ensureSessionObjectStoreCredentials(ctx context.Context, c client.Client, reader client.Reader, s *podtracev1alpha1.PodTraceSession, systemNS string) (string, error) {
	if s == nil || s.Spec.ReportRef == nil || s.Spec.ReportRef.ObjectStore == nil {
		return "", nil
	}
	ref := s.Spec.ReportRef.ObjectStore.CredentialsSecretRef
	if ref == nil || ref.Name == "" {
		return "", nil
	}

	var src corev1.Secret
	if err := reader.Get(ctx, types.NamespacedName{Namespace: s.Namespace, Name: ref.Name}, &src); err != nil {
		if apierrors.IsNotFound(err) {
			return "", fmt.Errorf("objectstore credentials Secret %s/%s not found", s.Namespace, ref.Name)
		}
		return "", fmt.Errorf("get objectstore credentials Secret %s/%s: %w", s.Namespace, ref.Name, err)
	}

	dstName := SessionObjectStoreCredsName(s.UID)
	dst := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      dstName,
			Namespace: systemNS,
			Labels: map[string]string{
				LabelManagedBy:   ManagedByValue,
				LabelComponent:   "objectstore-credentials",
				LabelSessionName: s.Name,
				LabelSessionNS:   s.Namespace,
			},
			Annotations: map[string]string{
				"podtrace.io/source-ref": s.Namespace + "/" + ref.Name,
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: src.Data,
	}
	if err := applySecret(ctx, c, reader, dst); err != nil {
		return "", fmt.Errorf("upsert objectstore credentials in %s: %w", systemNS, err)
	}
	return dstName, nil
}
