package kubernetes

import (
	"os"
	"path/filepath"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/gma1k/podtrace/internal/hostfs"
)

// ClusterAccess names the kubeconfig file and context a command reaches the
// cluster with. Empty fields follow kubectl: the KUBECONFIG path list, then
// ~/.kube/config, and only when neither holds a config, the in-cluster
// ServiceAccount.
type ClusterAccess struct {
	Kubeconfig string
	Context    string
}

var inClusterConfig = rest.InClusterConfig

var homeRoot = "/home"

func (a ClusterAccess) clientConfig() clientcmd.ClientConfig {
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		kubeconfigLoadingRules(a.Kubeconfig),
		&clientcmd.ConfigOverrides{CurrentContext: a.Context})
}

// RESTConfig resolves the cluster to talk to and reports whether it is the
// in-cluster ServiceAccount, which is used only when no kubeconfig names a
// cluster. A kubeconfig that is named but unusable is an error, never a
// silent fall back to whatever cluster the process runs in.
func (a ClusterAccess) RESTConfig() (*rest.Config, bool, error) {
	cc := a.clientConfig()
	raw, err := cc.RawConfig()
	if err != nil {
		return nil, false, NewKubeconfigError(err)
	}
	if clientcmdapi.IsConfigEmpty(&raw) && a.Context == "" {
		if cfg, err := inClusterConfig(); err == nil {
			return cfg, true, nil
		}
	}
	cfg, err := cc.ClientConfig()
	if err != nil {
		return nil, false, NewKubeconfigError(err)
	}
	return cfg, false, nil
}

// Namespace is the namespace of the context RESTConfig resolves, so the
// cluster and the namespace always come from the same kubeconfig.
func (a ClusterAccess) Namespace() (string, bool) {
	ns, _, err := a.clientConfig().Namespace()
	if err != nil || ns == "" {
		return "", false
	}
	return ns, true
}

// kubeconfigLoadingRules starts from client-go's defaults, which already read
// KUBECONFIG as a path list. ExplicitPath is set only for an explicit
// --kubeconfig, or under sudo, where HOME is root's and the invoking user's
// own config is the one they mean.
func kubeconfigLoadingRules(explicit string) *clientcmd.ClientConfigLoadingRules {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if explicit != "" {
		loadingRules.ExplicitPath = explicit
		return loadingRules
	}
	if os.Getenv(clientcmd.RecommendedConfigPathEnvVar) != "" {
		return loadingRules
	}

	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		homePath := filepath.Join(homeRoot, sudoUser, ".kube", "config")
		if _, err := hostfs.Stat(homePath); err == nil {
			loadingRules.ExplicitPath = homePath
			return loadingRules
		}
	}
	if home := os.Getenv("HOME"); home != "" && home != "/root" {
		homePath := filepath.Join(home, ".kube", "config")
		if _, err := hostfs.Stat(homePath); err == nil {
			loadingRules.ExplicitPath = homePath
		}
	}
	return loadingRules
}
