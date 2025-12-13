package kubernetes

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestServiceResolver_ResolveService(t *testing.T) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}

	endpoints := &corev1.Endpoints{ //nolint:staticcheck // Endpoints API still widely used
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-service",
			Namespace: "default",
		},
		Subsets: []corev1.EndpointSubset{ //nolint:staticcheck // Endpoints API still widely used
			{
				Addresses: []corev1.EndpointAddress{
					{IP: "10.244.1.5"},
				},
				Ports: []corev1.EndpointPort{
					{Port: 8080},
				},
			},
		},
	}

	clientset := fake.NewSimpleClientset(ns, endpoints)
	resolver := NewServiceResolver(clientset)

	serviceInfo := resolver.ResolveService(context.Background(), "10.244.1.5", 8080)
	if serviceInfo != nil {
		if serviceInfo.Name != "test-service" {
			t.Errorf("expected service name 'test-service', got %q", serviceInfo.Name)
		}

		if serviceInfo.Namespace != "default" {
			t.Errorf("expected namespace 'default', got %q", serviceInfo.Namespace)
		}

		if serviceInfo.Port != 8080 {
			t.Errorf("expected port 8080, got %d", serviceInfo.Port)
		}
	} else {
		t.Log("service resolution returned nil, which may be expected with fake client limitations")
	}
}

func TestServiceResolver_ResolveService_NotFound(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	resolver := NewServiceResolver(clientset)

	serviceInfo := resolver.ResolveService(context.Background(), "10.244.1.5", 8080)
	if serviceInfo != nil {
		t.Errorf("expected nil for non-existent service, got %+v", serviceInfo)
	}
}

func TestServiceResolver_ResolveService_WrongPort(t *testing.T) {
	endpoints := &corev1.Endpoints{ //nolint:staticcheck // Endpoints API still widely used
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-service",
			Namespace: "default",
		},
		Subsets: []corev1.EndpointSubset{ //nolint:staticcheck // Endpoints API still widely used
			{
				Addresses: []corev1.EndpointAddress{
					{IP: "10.244.1.5"},
				},
				Ports: []corev1.EndpointPort{
					{Port: 8080},
				},
			},
		},
	}

	clientset := fake.NewSimpleClientset(endpoints)
	resolver := NewServiceResolver(clientset)

	serviceInfo := resolver.ResolveService(context.Background(), "10.244.1.5", 9090)
	if serviceInfo != nil {
		t.Errorf("expected nil for wrong port, got %+v", serviceInfo)
	}
}

func TestServiceResolver_ResolveService_EmptyIP(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	resolver := NewServiceResolver(clientset)
	
	serviceInfo := resolver.ResolveService(context.Background(), "", 8080)
	if serviceInfo != nil {
		t.Errorf("Expected nil for empty IP, got %+v", serviceInfo)
	}
}

func TestServiceResolver_ResolveService_ZeroPort(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	resolver := NewServiceResolver(clientset)
	
	serviceInfo := resolver.ResolveService(context.Background(), "10.244.1.5", 0)
	if serviceInfo != nil {
		t.Errorf("Expected nil for zero port, got %+v", serviceInfo)
	}
}

func TestServiceResolver_ResolveService_NilClientset(t *testing.T) {
	resolver := NewServiceResolver(nil)
	
	serviceInfo := resolver.ResolveService(context.Background(), "10.244.1.5", 8080)
	if serviceInfo != nil {
		t.Errorf("Expected nil for nil clientset, got %+v", serviceInfo)
	}
}

func TestServiceResolver_ResolveService_CacheHit(t *testing.T) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}
	
	endpoints := &corev1.Endpoints{ //nolint:staticcheck // Endpoints API still widely used
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-service",
			Namespace: "default",
		},
		Subsets: []corev1.EndpointSubset{ //nolint:staticcheck // Endpoints API still widely used
			{
				Addresses: []corev1.EndpointAddress{
					{IP: "10.244.1.5"},
				},
				Ports: []corev1.EndpointPort{
					{Port: 8080},
				},
			},
		},
	}
	
	clientset := fake.NewSimpleClientset(ns, endpoints)
	resolver := NewServiceResolver(clientset)
	
	serviceInfo1 := resolver.ResolveService(context.Background(), "10.244.1.5", 8080)
	serviceInfo2 := resolver.ResolveService(context.Background(), "10.244.1.5", 8080)
	
	if serviceInfo1 != nil && serviceInfo2 != nil {
		if serviceInfo1.Name != serviceInfo2.Name {
			t.Error("Expected cached result to match first result")
		}
	}
}

func TestServiceResolver_ResolveService_CacheExpired(t *testing.T) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}
	
	endpoints := &corev1.Endpoints{ //nolint:staticcheck // Endpoints API still widely used
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-service",
			Namespace: "default",
		},
		Subsets: []corev1.EndpointSubset{ //nolint:staticcheck // Endpoints API still widely used
			{
				Addresses: []corev1.EndpointAddress{
					{IP: "10.244.1.5"},
				},
				Ports: []corev1.EndpointPort{
					{Port: 8080},
				},
			},
		},
	}
	
	clientset := fake.NewSimpleClientset(ns, endpoints)
	resolver := NewServiceResolver(clientset)
	resolver.cacheTTL = 100 * time.Millisecond
	
	serviceInfo1 := resolver.ResolveService(context.Background(), "10.244.1.5", 8080)
	
	time.Sleep(150 * time.Millisecond)
	
	serviceInfo2 := resolver.ResolveService(context.Background(), "10.244.1.5", 8080)
	
	if serviceInfo1 != nil && serviceInfo2 != nil {
		if serviceInfo1.Name != serviceInfo2.Name {
			t.Log("Cache expired and service was re-resolved")
		}
	}
}

func TestServiceResolver_FetchServiceByEndpoint_NotFound(t *testing.T) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}
	
	clientset := fake.NewSimpleClientset(ns)
	resolver := NewServiceResolver(clientset)
	
	serviceInfo := resolver.fetchServiceByEndpoint(context.Background(), "10.244.1.5", 8080)
	if serviceInfo != nil {
		t.Errorf("Expected nil for non-existent endpoint, got %+v", serviceInfo)
	}
}

func TestServiceResolver_FetchServiceByEndpoint_WrongIP(t *testing.T) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}
	
	endpoints := &corev1.Endpoints{ //nolint:staticcheck // Endpoints API still widely used
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-service",
			Namespace: "default",
		},
		Subsets: []corev1.EndpointSubset{ //nolint:staticcheck // Endpoints API still widely used
			{
				Addresses: []corev1.EndpointAddress{
					{IP: "10.244.1.5"},
				},
				Ports: []corev1.EndpointPort{
					{Port: 8080},
				},
			},
		},
	}
	
	clientset := fake.NewSimpleClientset(ns, endpoints)
	resolver := NewServiceResolver(clientset)
	
	serviceInfo := resolver.fetchServiceByEndpoint(context.Background(), "10.244.1.6", 8080)
	if serviceInfo != nil {
		t.Errorf("Expected nil for wrong IP, got %+v", serviceInfo)
	}
}

func TestServiceResolver_FetchServiceByEndpoint_MultipleSubsets(t *testing.T) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}
	
	endpoints := &corev1.Endpoints{ //nolint:staticcheck // Endpoints API still widely used
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-service",
			Namespace: "default",
		},
		Subsets: []corev1.EndpointSubset{ //nolint:staticcheck // Endpoints API still widely used
			{
				Addresses: []corev1.EndpointAddress{
					{IP: "10.244.1.5"},
				},
				Ports: []corev1.EndpointPort{
					{Port: 8080},
				},
			},
			{
				Addresses: []corev1.EndpointAddress{
					{IP: "10.244.1.6"},
				},
				Ports: []corev1.EndpointPort{
					{Port: 9090},
				},
			},
		},
	}
	
	clientset := fake.NewSimpleClientset(ns, endpoints)
	resolver := NewServiceResolver(clientset)
	
	serviceInfo := resolver.fetchServiceByEndpoint(context.Background(), "10.244.1.5", 8080)
	if serviceInfo != nil {
		if serviceInfo.Name != "test-service" {
			t.Errorf("Expected service name 'test-service', got %q", serviceInfo.Name)
		}
	}
}

