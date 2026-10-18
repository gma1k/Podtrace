package kubernetes

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/client-go/rest"
)

const twoContextKubeconfig = `apiVersion: v1
kind: Config
clusters:
- name: prod
  cluster:
    server: https://prod.example:6443
- name: staging
  cluster:
    server: https://staging.example:6443
contexts:
- name: prod
  context:
    cluster: prod
    user: me
    namespace: shop
- name: staging
  context:
    cluster: staging
    user: me
    namespace: qa
current-context: prod
users:
- name: me
  user:
    token: t
`

func writeKubeconfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func stubInCluster(t *testing.T, host string, err error) {
	t.Helper()
	orig := inClusterConfig
	inClusterConfig = func() (*rest.Config, error) {
		if err != nil {
			return nil, err
		}
		return &rest.Config{Host: host}, nil
	}
	t.Cleanup(func() { inClusterConfig = orig })
}

func TestAnExplicitKubeconfigWinsOverTheInClusterAccount(t *testing.T) {
	stubInCluster(t, "https://in-cluster", nil)
	cfg, inCluster, err := ClusterAccess{Kubeconfig: writeKubeconfig(t, twoContextKubeconfig)}.RESTConfig()
	if err != nil {
		t.Fatal(err)
	}
	if inCluster || cfg.Host != "https://prod.example:6443" {
		t.Fatalf("resolved %q (inCluster=%v), want the kubeconfig's prod cluster", cfg.Host, inCluster)
	}
}

func TestKubeconfigEnvWinsOverTheInClusterAccount(t *testing.T) {
	stubInCluster(t, "https://in-cluster", nil)
	t.Setenv("KUBECONFIG", writeKubeconfig(t, twoContextKubeconfig))
	cfg, inCluster, err := ClusterAccess{}.RESTConfig()
	if err != nil {
		t.Fatal(err)
	}
	if inCluster || cfg.Host != "https://prod.example:6443" {
		t.Fatalf("resolved %q (inCluster=%v), want KUBECONFIG's cluster", cfg.Host, inCluster)
	}
}

func TestTheInClusterAccountIsUsedWhenNoKubeconfigNamesACluster(t *testing.T) {
	stubInCluster(t, "https://in-cluster", nil)
	cfg, inCluster, err := ClusterAccess{Kubeconfig: writeKubeconfig(t, "apiVersion: v1\nkind: Config\n")}.RESTConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !inCluster || cfg.Host != "https://in-cluster" {
		t.Fatalf("resolved %q (inCluster=%v), want the in-cluster account", cfg.Host, inCluster)
	}
}

func TestAMissingExplicitKubeconfigFailsInsteadOfFallingBack(t *testing.T) {
	stubInCluster(t, "https://in-cluster", nil)
	_, _, err := ClusterAccess{Kubeconfig: filepath.Join(t.TempDir(), "absent")}.RESTConfig()
	if err == nil {
		t.Fatal("a missing --kubeconfig must not fall back to the in-cluster account")
	}
}

func TestAContextWithoutAKubeconfigFailsInsteadOfFallingBack(t *testing.T) {
	stubInCluster(t, "https://in-cluster", nil)
	_, _, err := ClusterAccess{Kubeconfig: writeKubeconfig(t, "apiVersion: v1\nkind: Config\n"), Context: "prod"}.RESTConfig()
	if err == nil {
		t.Fatal("--context names a kubeconfig context and must not resolve to the in-cluster account")
	}
}

func TestAKubeconfigPathListIsMerged(t *testing.T) {
	stubInCluster(t, "", errors.New("not in a cluster"))
	clusters := writeKubeconfig(t, twoContextKubeconfig)
	other := writeKubeconfig(t, "apiVersion: v1\nkind: Config\n")
	t.Setenv("KUBECONFIG", other+string(os.PathListSeparator)+clusters)
	cfg, _, err := ClusterAccess{}.RESTConfig()
	if err != nil {
		t.Fatalf("a KUBECONFIG path list must load: %v", err)
	}
	if cfg.Host != "https://prod.example:6443" {
		t.Fatalf("resolved %q", cfg.Host)
	}
}

func TestTheNamespaceComesFromTheSameContextAsTheCluster(t *testing.T) {
	access := ClusterAccess{Kubeconfig: writeKubeconfig(t, twoContextKubeconfig), Context: "staging"}
	cfg, _, err := access.RESTConfig()
	if err != nil {
		t.Fatal(err)
	}
	ns, ok := access.Namespace()
	if !ok || ns != "qa" || !strings.Contains(cfg.Host, "staging") {
		t.Fatalf("cluster %q namespace %q, want staging and qa", cfg.Host, ns)
	}
}
