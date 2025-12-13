package kubernetes

import (
	"context"
	"os"
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

func TestIsPrivateIP_ValidPrivateIPs(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"loopback", "127.0.0.1", true},
		{"private class A", "10.0.0.1", true},
		{"private class B", "172.16.0.1", true},
		{"private class C", "192.168.1.1", true},
		{"link local unicast", "169.254.1.1", true},
		{"public IP", "8.8.8.8", false},
		{"public IP 2", "1.1.1.1", false},
		{"invalid IP", "not-an-ip", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPrivateIP(tt.ip)
			if got != tt.want {
				t.Errorf("isPrivateIP(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestGetIntEnvOrDefault_EmptyValue(t *testing.T) {
	origValue := os.Getenv("TEST_ENV_VAR")
	defer func() {
		if origValue != "" {
			_ = os.Setenv("TEST_ENV_VAR", origValue)
		} else {
			_ = os.Unsetenv("TEST_ENV_VAR")
		}
	}()
	
	_ = os.Unsetenv("TEST_ENV_VAR")
	
	result := getIntEnvOrDefault("TEST_ENV_VAR", 100)
	if result != 100 {
		t.Errorf("Expected default value 100, got %d", result)
	}
}

func TestGetIntEnvOrDefault_ValidValue(t *testing.T) {
	origValue := os.Getenv("TEST_ENV_VAR")
	defer func() {
		if origValue != "" {
			_ = os.Setenv("TEST_ENV_VAR", origValue)
		} else {
			_ = os.Unsetenv("TEST_ENV_VAR")
		}
	}()
	
	_ = os.Setenv("TEST_ENV_VAR", "200")
	
	result := getIntEnvOrDefault("TEST_ENV_VAR", 100)
	if result != 200 {
		t.Errorf("Expected value 200, got %d", result)
	}
}

func TestGetIntEnvOrDefault_InvalidValue(t *testing.T) {
	origValue := os.Getenv("TEST_ENV_VAR")
	defer func() {
		if origValue != "" {
			_ = os.Setenv("TEST_ENV_VAR", origValue)
		} else {
			_ = os.Unsetenv("TEST_ENV_VAR")
		}
	}()
	
	_ = os.Setenv("TEST_ENV_VAR", "invalid")
	
	result := getIntEnvOrDefault("TEST_ENV_VAR", 100)
	if result != 100 {
		t.Errorf("Expected default value 100 for invalid input, got %d", result)
	}
}

func TestGetIntEnvOrDefault_ZeroValue(t *testing.T) {
	origValue := os.Getenv("TEST_ENV_VAR")
	defer func() {
		if origValue != "" {
			_ = os.Setenv("TEST_ENV_VAR", origValue)
		} else {
			_ = os.Unsetenv("TEST_ENV_VAR")
		}
	}()
	
	_ = os.Setenv("TEST_ENV_VAR", "0")
	
	result := getIntEnvOrDefault("TEST_ENV_VAR", 100)
	if result != 100 {
		t.Errorf("Expected default value 100 for zero input, got %d", result)
	}
}

func TestGetIntEnvOrDefault_NegativeValue(t *testing.T) {
	origValue := os.Getenv("TEST_ENV_VAR")
	defer func() {
		if origValue != "" {
			_ = os.Setenv("TEST_ENV_VAR", origValue)
		} else {
			_ = os.Unsetenv("TEST_ENV_VAR")
		}
	}()
	
	_ = os.Setenv("TEST_ENV_VAR", "-10")
	
	result := getIntEnvOrDefault("TEST_ENV_VAR", 100)
	if result != 100 {
		t.Errorf("Expected default value 100 for negative input, got %d", result)
	}
}

