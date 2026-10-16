package operator

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/pkg/exporter/bundle"
)

// marshalBundleToYAML converts the flat ConfigMap representation the
// existing renderBundlePayload emits into the structured YAML the CLI's
// --exporter-from-file reads.
func marshalBundleToYAML(data map[string]string) (string, error) {
	p, err := bundle.FromConfigMapData(data)
	if err != nil {
		return "", err
	}
	raw, err := bundle.ToYAML(p)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// SessionBundleName returns the ConfigMap/Secret name for a session's
// exporter bundle.
func SessionBundleName(sessionUID types.UID) string {
	return "pts-bundle-" + shortUID(sessionUID)
}

// ensureSessionExporterBundle creates-or-updates the ConfigMap + optional
// companion Secret the session Job mounts at /etc/podtrace/exporter/.
func ensureSessionExporterBundleIfReferenced(ctx context.Context, c client.Client, reader client.Reader, s *podtracev1alpha1.PodTraceSession, ec *podtracev1alpha1.ExporterConfig, systemNS string, referenced bool) error {
	if !referenced {
		return nil
	}
	return ensureSessionExporterBundle(ctx, c, reader, s, ec, systemNS)
}

func ensureSessionExporterBundle(ctx context.Context, c client.Client, reader client.Reader, s *podtracev1alpha1.PodTraceSession, ec *podtracev1alpha1.ExporterConfig, systemNS string) error {
	name := SessionBundleName(s.UID)

	payload, credSecretRef, headersFrom, err := renderBundlePayload(policyFromSession(s), ec, nil)
	if err != nil {
		return fmt.Errorf("render session bundle payload: %w", err)
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: systemNS},
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, c, cm, func() error {
		cm.Labels = mergeLabels(cm.Labels, map[string]string{
			LabelManagedBy:      ManagedByValue,
			LabelComponent:      ComponentBundle,
			LabelSessionName:    s.Name,
			LabelSessionNS:      s.Namespace,
			LabelExporterConfig: ec.Name,
		})
		cm.Annotations = mergeLabels(cm.Annotations, map[string]string{
			BundleAnnotationSourceRef: ec.Namespace + "/" + ec.Name,
		})
		bundleYAML, err := marshalBundleToYAML(payload)
		if err != nil {
			return err
		}
		data := make(map[string]string, len(payload)+1)
		data["bundle.yaml"] = bundleYAML
		for k, v := range payload {
			data[k] = v
		}
		cm.Data = data
		return nil
	}); err != nil {
		return fmt.Errorf("session bundle ConfigMap: %w", err)
	}

	if credSecretRef != nil || headersFrom != nil {
		credData, err := buildBundleSecretData(ctx, reader, ec.Namespace, credSecretRef, headersFrom)
		if err != nil {
			return fmt.Errorf("load session credential Secret: %w", err)
		}
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: systemNS,
				Labels: map[string]string{
					LabelManagedBy:      ManagedByValue,
					LabelComponent:      ComponentBundle,
					LabelSessionName:    s.Name,
					LabelSessionNS:      s.Namespace,
					LabelExporterConfig: ec.Name,
				},
				Annotations: map[string]string{
					BundleAnnotationSourceRef: ec.Namespace + "/" + ec.Name,
				},
			},
			Type: corev1.SecretTypeOpaque,
			Data: credData,
		}
		if err := applySecret(ctx, c, reader, secret); err != nil {
			return fmt.Errorf("session bundle Secret: %w", err)
		}
	} else {
		stale := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: systemNS}}
		if err := c.Delete(ctx, stale); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("prune stale session bundle Secret: %w", err)
		}
	}
	return nil
}

// loadCredentialSecret fetches exactly the one SecretKeySelector an
// ExporterConfig references and returns the value under the fixed
// "credential" key.
func loadCredentialSecret(ctx context.Context, reader client.Reader, namespace string, ref podtracev1alpha1.SecretKeySelector) (map[string][]byte, error) {
	var src corev1.Secret
	if err := reader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: ref.Name}, &src); err != nil {
		return nil, fmt.Errorf("get Secret %s/%s: %w", namespace, ref.Name, err)
	}
	val, ok := src.Data[ref.Key]
	if !ok {
		return nil, fmt.Errorf("secret %s/%s has no key %q", namespace, ref.Name, ref.Key)
	}
	return map[string][]byte{"credential": val}, nil
}
