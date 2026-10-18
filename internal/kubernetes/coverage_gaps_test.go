package kubernetes

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestSudoUsesTheInvokingUsersKubeconfig(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "alice", ".kube", "config")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(twoContextKubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := homeRoot
	homeRoot = root
	t.Cleanup(func() { homeRoot = orig })
	t.Setenv("KUBECONFIG", "")
	t.Setenv("SUDO_USER", "alice")

	if got := kubeconfigLoadingRules("").ExplicitPath; got != path {
		t.Fatalf("ExplicitPath = %q, want the sudo user's %q", got, path)
	}
}

func TestAResolverForAnUnusableKubeconfigIsAnError(t *testing.T) {
	if _, err := NewPodResolverFor(ClusterAccess{Kubeconfig: filepath.Join(t.TempDir(), "absent")}); err == nil {
		t.Fatal("expected an error for a missing kubeconfig")
	}
}

func TestAResolverReportsWhetherItIsInCluster(t *testing.T) {
	stubInCluster(t, "https://in-cluster", nil)
	r, err := NewPodResolverFor(ClusterAccess{Kubeconfig: writeKubeconfig(t, "apiVersion: v1\nkind: Config\n")})
	if err != nil {
		t.Fatal(err)
	}
	if !r.InCluster() {
		t.Fatal("a resolver on the in-cluster account must say so")
	}
	r, err = NewPodResolverFor(ClusterAccess{Kubeconfig: writeKubeconfig(t, twoContextKubeconfig)})
	if err != nil {
		t.Fatal(err)
	}
	if r.InCluster() {
		t.Fatal("a resolver on a kubeconfig must not claim to be in-cluster")
	}
}

func TestAZeroValueResolverStillRemembersMisses(t *testing.T) {
	cs := fake.NewClientset()
	cs.PrependReactor("list", "endpoints", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, &corev1.EndpointsList{}, nil
	})
	sr := &ServiceResolver{clientset: cs, cacheTTL: 60e9, negativeTTL: 30e9}
	if sr.ResolveService(context.Background(), "10.0.0.1", 80) != nil {
		t.Fatal("unexpected match")
	}
	if _, ok := sr.lookupCache("10.0.0.1:80"); !ok {
		t.Fatal("the miss was not remembered")
	}
}

func TestTheFirstServiceForAnAddressWins(t *testing.T) {
	cs := fake.NewClientset()
	cs.PrependReactor("list", "endpoints", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, &corev1.EndpointsList{Items: []endpointsObject{
			endpointsFor("a", "first", "10.0.0.1", 80),
			endpointsFor("a", "second", "10.0.0.1", 80),
		}}, nil
	})
	if svc := NewServiceResolver(cs).ResolveService(context.Background(), "10.0.0.1", 80); svc == nil || svc.Name != "first" {
		t.Fatalf("resolved %+v, want the first listed service", svc)
	}
}

func TestARegistryWithAnInvalidSelectorDoesNotStart(t *testing.T) {
	tr := NewTargetRegistry(fake.NewClientset(), TargetSelection{PodSelector: "app in (("})
	if err := tr.Start(context.Background()); err == nil {
		t.Fatal("expected the invalid selector to stop Start")
	}
}
