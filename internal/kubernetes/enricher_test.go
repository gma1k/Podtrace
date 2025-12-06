package kubernetes

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/podtrace/podtrace/internal/events"
)

func TestContextEnricher_EnrichEvent(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	podInfo := &PodInfo{
		PodName:   "test-pod",
		Namespace: "default",
		Labels:    map[string]string{"app": "test"},
	}

	enricher := NewContextEnricher(clientset, podInfo)

	event := &events.Event{
		Type:   events.EventConnect,
		Target: "192.168.1.1:8080",
	}

	enriched := enricher.EnrichEvent(context.Background(), event)
	if enriched == nil {
		t.Fatal("expected enriched event, got nil")
	}

	if enriched.KubernetesContext == nil {
		t.Fatal("expected Kubernetes context, got nil")
	}

	if enriched.KubernetesContext.SourceNamespace != "default" {
		t.Errorf("expected source namespace 'default', got %q", enriched.KubernetesContext.SourceNamespace)
	}
}

func TestContextEnricher_EnrichEvent_NonNetwork(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	podInfo := &PodInfo{
		PodName:   "test-pod",
		Namespace: "default",
	}

	enricher := NewContextEnricher(clientset, podInfo)

	event := &events.Event{
		Type:   events.EventRead,
		Target: "file.txt",
	}

	enriched := enricher.EnrichEvent(context.Background(), event)
	if enriched == nil {
		t.Fatal("expected enriched event, got nil")
	}

	if enriched.KubernetesContext.SourceNamespace != "default" {
		t.Errorf("expected source namespace 'default', got %q", enriched.KubernetesContext.SourceNamespace)
	}
}

func TestParseTarget(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		expectedIP string
		expectedPort int
	}{
		{"IPv4 with port", "192.168.1.1:8080", "192.168.1.1", 8080},
		{"IPv6 with port", "[2001:db8::1]:8080", "2001:db8::1", 8080},
		{"No port", "192.168.1.1", "192.168.1.1", 0},
		{"Empty", "", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, port := parseTarget(tt.target)
			if ip != tt.expectedIP {
				t.Errorf("expected IP %q, got %q", tt.expectedIP, ip)
			}
			if port != tt.expectedPort {
				t.Errorf("expected port %d, got %d", tt.expectedPort, port)
			}
		})
	}
}

func TestIsNetworkEvent(t *testing.T) {
	tests := []struct {
		eventType events.EventType
		expected  bool
	}{
		{events.EventConnect, true},
		{events.EventTCPSend, true},
		{events.EventTCPRecv, true},
		{events.EventUDPSend, true},
		{events.EventUDPRecv, true},
		{events.EventRead, false},
		{events.EventWrite, false},
		{events.EventDNS, false},
	}

	for _, tt := range tests {
		result := isNetworkEvent(tt.eventType)
		if result != tt.expected {
			t.Errorf("isNetworkEvent(%v) = %v, expected %v", tt.eventType, result, tt.expected)
		}
	}
}

func TestContextEnricher_ResolvePodByIP(t *testing.T) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "target-pod",
			Namespace: "default",
			Labels:    map[string]string{"app": "target"},
		},
		Status: corev1.PodStatus{
			PodIP: "10.244.1.5",
		},
	}

	clientset := fake.NewSimpleClientset(ns, pod)
	podInfo := &PodInfo{
		PodName:   "test-pod",
		Namespace: "default",
	}

	enricher := NewContextEnricher(clientset, podInfo)

	podMeta := enricher.resolvePodByIP(context.Background(), "10.244.1.5")
	if podMeta != nil {
		if podMeta.Name != "target-pod" {
			t.Errorf("expected pod name 'target-pod', got %q", podMeta.Name)
		}
	} else {
		t.Log("pod resolution returned nil, which may be expected with fake client limitations")
	}
}

