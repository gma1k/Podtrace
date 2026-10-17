package agent

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type orderedReader struct {
	client.Client
	slices   []discoveryv1.EndpointSlice
	services []corev1.Service
}

func (r orderedReader) List(_ context.Context, list client.ObjectList, _ ...client.ListOption) error {
	switch typed := list.(type) {
	case *discoveryv1.EndpointSliceList:
		typed.Items = append([]discoveryv1.EndpointSlice(nil), r.slices...)
	case *corev1.ServiceList:
		typed.Items = append([]corev1.Service(nil), r.services...)
	}
	return nil
}

func permutations[T any](items []T) [][]T {
	if len(items) <= 1 {
		return [][]T{append([]T(nil), items...)}
	}
	var out [][]T
	for i := range items {
		rest := make([]T, 0, len(items)-1)
		rest = append(rest, items[:i]...)
		rest = append(rest, items[i+1:]...)
		for _, tail := range permutations(rest) {
			out = append(out, append([]T{items[i]}, tail...))
		}
	}
	return out
}

func rankedSlice(namespace, service string, headless bool, managedBy string) discoveryv1.EndpointSlice {
	slice := endpointSlice(namespace, service+"-slice", service, "10.244.1.7")
	if headless {
		slice.Labels[corev1.IsHeadlessService] = ""
	}
	if managedBy != "" {
		slice.Labels[discoveryv1.LabelManagedBy] = managedBy
	}
	return *slice
}

func assertEverySliceOrderPicks(t *testing.T, slices []discoveryv1.EndpointSlice, wantNamespace, wantService string) {
	t.Helper()
	for _, order := range permutations(slices) {
		identity, ok := endpointSliceLookup(orderedReader{slices: order})("10.244.1.7", 8080)
		if !ok {
			t.Fatalf("order %v did not resolve", sliceNames(order))
		}
		if identity.Service != wantService || identity.Namespace != wantNamespace {
			t.Errorf("order %v picked %s/%s, want %s/%s", sliceNames(order),
				identity.Namespace, identity.Service, wantNamespace, wantService)
		}
	}
}

func sliceNames(slices []discoveryv1.EndpointSlice) []string {
	names := make([]string, 0, len(slices))
	for _, slice := range slices {
		names = append(names, slice.Namespace+"/"+slice.Labels[discoveryv1.LabelServiceName])
	}
	return names
}

func TestEndpointSliceLookupPrefersTheSmallestClusterIPServiceInEveryOrder(t *testing.T) {
	assertEverySliceOrderPicks(t, []discoveryv1.EndpointSlice{
		rankedSlice("shop", "b", true, endpointSliceControllerName),
		rankedSlice("shop", "z", false, endpointSliceControllerName),
		rankedSlice("shop", "a", false, endpointSliceControllerName),
	}, "shop", "a")
}

func TestEndpointSliceLookupPicksTheSmallestNameAmongHeadlessServices(t *testing.T) {
	assertEverySliceOrderPicks(t, []discoveryv1.EndpointSlice{
		rankedSlice("shop", "db-headless", true, endpointSliceControllerName),
		rankedSlice("shop", "db-cluster", true, endpointSliceControllerName),
		rankedSlice("shop", "db-peers", true, endpointSliceControllerName),
	}, "shop", "db-cluster")
}

func TestEndpointSliceLookupPrefersControllerManagedSlicesOnATie(t *testing.T) {
	assertEverySliceOrderPicks(t, []discoveryv1.EndpointSlice{
		rankedSlice("shop", "a", false, "mesh-controller.example.com"),
		rankedSlice("shop", "b", false, endpointSliceControllerName),
	}, "shop", "b")
}

func TestEndpointSliceLookupStillResolvesACustomManagedSlice(t *testing.T) {
	assertEverySliceOrderPicks(t, []discoveryv1.EndpointSlice{
		rankedSlice("data", "postgres", false, "endpointslicemirroring-controller.k8s.io"),
	}, "data", "postgres")
}

func TestEndpointSliceLookupOrdersByNamespaceBeforeName(t *testing.T) {
	assertEverySliceOrderPicks(t, []discoveryv1.EndpointSlice{
		rankedSlice("zeta", "a", false, endpointSliceControllerName),
		rankedSlice("alpha", "z", false, endpointSliceControllerName),
	}, "alpha", "z")
}

func TestServiceLookupPicksTheSmallestNamespacedNameInEveryOrder(t *testing.T) {
	services := []corev1.Service{
		*serviceObject("shop", "z", "10.96.0.20", 80),
		*serviceObject("shop", "a", "10.96.0.20", 80),
		*serviceObject("bank", "m", "10.96.0.20", 80),
	}
	for _, order := range permutations(services) {
		identity, ok := serviceLookup(orderedReader{services: order})("10.96.0.20", 80)
		if !ok {
			t.Fatal("a listed Service did not resolve")
		}
		if identity.Namespace != "bank" || identity.Service != "m" {
			t.Errorf("picked %s/%s, want bank/m", identity.Namespace, identity.Service)
		}
	}
}

func TestTrimEndpointSliceKeepsTheLabelsTheRankingReads(t *testing.T) {
	slice := endpointSlice("shop", "db-headless-abc", "db-headless", "10.244.1.7")
	slice.Labels[corev1.IsHeadlessService] = ""
	slice.Labels[discoveryv1.LabelManagedBy] = endpointSliceControllerName
	slice.Labels["unrelated"] = "value"

	trimmed, err := trimEndpointSlice(slice)
	if err != nil {
		t.Fatalf("trimEndpointSlice: %v", err)
	}
	labels := trimmed.(*discoveryv1.EndpointSlice).Labels

	if _, kept := labels[corev1.IsHeadlessService]; !kept {
		t.Error("the headless label was trimmed away")
	}
	if labels[discoveryv1.LabelManagedBy] != endpointSliceControllerName {
		t.Error("the managed-by label was trimmed away")
	}
	if _, kept := labels["unrelated"]; kept {
		t.Error("an unrelated label survived the trim")
	}
	if len(labels) != 3 {
		t.Errorf("labels = %v, want exactly the service name, headless and managed-by labels", labels)
	}
}

func TestSharedAddressSpaceIsClusterLocal(t *testing.T) {
	for _, address := range []string{"100.64.0.1", "100.100.12.7", "100.127.255.254"} {
		if !isClusterLocalIP(address) {
			t.Errorf("%s is RFC 6598 shared address space, used as a pod CIDR, but was not cluster-local", address)
		}
		if got := undrawablePeer(address); got != "" {
			t.Errorf("undrawablePeer(%s) = %q, want no edge", address, got)
		}
	}
	for _, address := range []string{"100.63.255.255", "100.128.0.1", "8.8.8.8"} {
		if isClusterLocalIP(address) {
			t.Errorf("%s is outside every cluster-local range but was treated as cluster-local", address)
		}
	}
	if !isClusterLocalIP("fd00::1") {
		t.Error("an IPv6 unique local address stopped being cluster-local")
	}
}
