package v1alpha1

import (
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

var reservedSystemNamespaces = map[string]struct{}{
	"default":         {},
	"kube-system":     {},
	"kube-public":     {},
	"kube-node-lease": {},
}

// ValidateSystemNamespace rejects a TracerConfig.spec.systemNamespace that is
// not a namespace name, or that names one of the cluster's own namespaces.
// Empty means the operator's namespace and is valid.
func ValidateSystemNamespace(namespace string) error {
	if namespace == "" {
		return nil
	}
	if errs := validation.IsDNS1123Label(namespace); len(errs) > 0 {
		return fmt.Errorf("spec.systemNamespace %q is not a namespace name: %s", namespace, strings.Join(errs, "; "))
	}
	if _, reserved := reservedSystemNamespaces[namespace]; reserved {
		return fmt.Errorf("spec.systemNamespace %q is reserved for the cluster; the system namespace receives a privileged agent DaemonSet, tenant exporter credentials and session Jobs, so give the fleet a namespace of its own", namespace)
	}
	return nil
}
