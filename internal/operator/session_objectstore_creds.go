package operator

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/reportsink/objectstore"
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

// ObjectStoreCrossNamespaceAmbientCredentialsEnv is the operator setting
// that lets sessions outside the operator's namespace upload with the
// uploader's ambient identity.
const ObjectStoreCrossNamespaceAmbientCredentialsEnv = "PODTRACE_OBJECTSTORE_CROSS_NAMESPACE_AMBIENT_CREDENTIALS"

// objectStoreCredentialPolicy is the policy a session's uploader runs
// under. A session in the operator's own namespace is admin-owned and may
// use ambient credentials; any other session needs the admin opt-in. The
// endpoint allowlist is the operator's own PODTRACE_OBJECTSTORE_ENDPOINT_ALLOWLIST.
func objectStoreCredentialPolicy(s *podtracev1alpha1.PodTraceSession, operatorNS string) objectstore.CredentialPolicy {
	crossNamespace, _ := strconv.ParseBool(strings.TrimSpace(os.Getenv(ObjectStoreCrossNamespaceAmbientCredentialsEnv)))
	return objectstore.CredentialPolicy{
		AllowAmbientCredentials: crossNamespace || (s != nil && operatorNS != "" && s.Namespace == operatorNS),
		EndpointAllowlist:       objectstore.ParseEndpointAllowlist(os.Getenv(objectstore.EnvEndpointAllowlist)),
	}
}

// checkSessionObjectStorePolicy rejects an objectStore destination the
// uploader would refuse, so the session reports it before tracing rather
// than after.
func checkSessionObjectStorePolicy(ctx context.Context, reader client.Reader, s *podtracev1alpha1.PodTraceSession, policy objectstore.CredentialPolicy) error {
	if s == nil || s.Spec.ReportRef == nil || s.Spec.ReportRef.ObjectStore == nil {
		return nil
	}
	var creds map[string][]byte
	if ref := s.Spec.ReportRef.ObjectStore.CredentialsSecretRef; ref != nil && ref.Name != "" {
		var src corev1.Secret
		if err := reader.Get(ctx, types.NamespacedName{Namespace: s.Namespace, Name: ref.Name}, &src); err != nil {
			if apierrors.IsNotFound(err) {
				return fmt.Errorf("objectstore credentials Secret %s/%s not found", s.Namespace, ref.Name)
			}
			return fmt.Errorf("get objectstore credentials Secret %s/%s: %w", s.Namespace, ref.Name, err)
		}
		creds = src.Data
	}
	if err := policy.Check(s.Spec.ReportRef.ObjectStore.URI, creds); err != nil {
		return fmt.Errorf("objectstore destination refused: %w", err)
	}
	return nil
}

// applyObjectStoreCredentialPolicyEnv hands the policy to the uploader
// sidecar, which enforces it again when it builds the sink.
func applyObjectStoreCredentialPolicyEnv(spec *corev1.PodSpec, policy objectstore.CredentialPolicy) {
	for i := range spec.InitContainers {
		c := &spec.InitContainers[i]
		if c.Name != reportUploaderContainerName {
			continue
		}
		c.Env = append(c.Env,
			corev1.EnvVar{Name: objectstore.EnvAllowAmbientCredentials, Value: strconv.FormatBool(policy.AllowAmbientCredentials)},
			corev1.EnvVar{Name: objectstore.EnvEndpointAllowlist, Value: strings.Join(policy.EndpointAllowlist, ",")},
		)
	}
}
