package kubernetes

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

type endpointsObject = corev1.Endpoints //nolint:staticcheck // Endpoints API still widely used

func endpointsFor(ns, name, ip string, port int32) endpointsObject {
	return endpointsObject{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Subsets: []corev1.EndpointSubset{{ //nolint:staticcheck // Endpoints API still widely used
			Addresses: []corev1.EndpointAddress{{IP: ip}},
			Ports:     []corev1.EndpointPort{{Port: port}},
		}},
	}
}

func servePages(cs *fake.Clientset, pages ...[]endpointsObject) *[]string {
	var continues []string
	cs.PrependReactor("list", "endpoints", func(a k8stesting.Action) (bool, runtime.Object, error) {
		opts := a.(k8stesting.ListActionImpl).ListOptions
		continues = append(continues, opts.Continue)
		i := 0
		if opts.Continue != "" {
			i = int(opts.Continue[0] - '0')
		}
		list := &corev1.EndpointsList{Items: pages[i]}
		if i+1 < len(pages) {
			list.Continue = string(rune('0' + i + 1))
		}
		return true, list, nil
	})
	return &continues
}

func TestTheEndpointListingIsReadPageByPage(t *testing.T) {
	cs := fake.NewClientset()
	continues := servePages(cs,
		[]endpointsObject{endpointsFor("a", "api", "10.0.0.1", 80)},
		[]endpointsObject{endpointsFor("b", "web", "10.0.0.2", 80)},
	)
	sr := NewServiceResolver(cs)
	svc := sr.ResolveService(context.Background(), "10.0.0.2", 80)
	if svc == nil || svc.Name != "web" {
		t.Fatalf("resolved %+v, want the service on the second page", svc)
	}
	if len(*continues) != 2 || (*continues)[1] == "" {
		t.Fatalf("list calls carried continue tokens %q, want a second page fetched", *continues)
	}
}

func TestARefreshDropsAddressesThatLeftTheCluster(t *testing.T) {
	cs := fake.NewClientset()
	current := []endpointsObject{endpointsFor("a", "old", "10.0.0.1", 80)}
	cs.PrependReactor("list", "endpoints", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, &corev1.EndpointsList{Items: current}, nil
	})
	sr := NewServiceResolver(cs)
	if sr.ResolveService(context.Background(), "10.0.0.1", 80) == nil {
		t.Fatal("first lookup missed")
	}

	current = []endpointsObject{endpointsFor("a", "new", "10.0.0.9", 80)}
	sr.mu.Lock()
	sr.endpointsExpireAt = time.Now().Add(-time.Second)
	sr.mu.Unlock()
	if svc := sr.ResolveService(context.Background(), "10.0.0.9", 80); svc == nil || svc.Name != "new" {
		t.Fatalf("lookup after refresh = %+v", svc)
	}

	sr.mu.RLock()
	defer sr.mu.RUnlock()
	if _, kept := sr.endpoints["10.0.0.1:80"]; kept {
		t.Fatal("an address no longer in any Endpoints object survived the refresh")
	}
}

func TestExpiredMissesArePrunedOnRefresh(t *testing.T) {
	cs := fake.NewClientset()
	cs.PrependReactor("list", "endpoints", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, &corev1.EndpointsList{}, nil
	})
	sr := NewServiceResolver(cs)
	sr.mu.Lock()
	sr.notFound["10.9.9.9:80"] = time.Now().Add(-time.Minute)
	sr.mu.Unlock()

	_ = sr.ResolveService(context.Background(), "10.0.0.5", 80)

	sr.mu.RLock()
	defer sr.mu.RUnlock()
	if _, kept := sr.notFound["10.9.9.9:80"]; kept {
		t.Fatal("an expired negative entry was kept")
	}
	if _, ok := sr.notFound["10.0.0.5:80"]; !ok {
		t.Fatal("the new miss was not remembered")
	}
}
