package kubernetes

import (
	"errors"
	"testing"
)

func TestNewKubeconfigError(t *testing.T) {
	originalErr := errors.New("kubeconfig error")
	err := NewKubeconfigError(originalErr)
	
	if err == nil {
		t.Fatal("NewKubeconfigError returned nil")
	}
	if err.Code != ErrCodeKubeconfigFailed {
		t.Errorf("Expected error code %d, got %d", ErrCodeKubeconfigFailed, err.Code)
	}
	if err.Message != "failed to get kubeconfig" {
		t.Errorf("Expected message 'failed to get kubeconfig', got %q", err.Message)
	}
	if err.Unwrap() != originalErr {
		t.Errorf("Expected unwrapped error to be original error")
	}
}

func TestNewClientsetError(t *testing.T) {
	originalErr := errors.New("clientset error")
	err := NewClientsetError(originalErr)
	
	if err == nil {
		t.Fatal("NewClientsetError returned nil")
	}
	if err.Code != ErrCodeClientsetFailed {
		t.Errorf("Expected error code %d, got %d", ErrCodeClientsetFailed, err.Code)
	}
	if err.Message != "failed to create Kubernetes clientset" {
		t.Errorf("Expected message 'failed to create Kubernetes clientset', got %q", err.Message)
	}
	if err.Unwrap() != originalErr {
		t.Errorf("Expected unwrapped error to be original error")
	}
}

func TestKubernetesError_Error_WithErr(t *testing.T) {
	originalErr := errors.New("underlying error")
	kerr := &KubernetesError{
		Code:    ErrCodePodNotFound,
		Message: "test message",
		Err:     originalErr,
	}
	
	errStr := kerr.Error()
	if errStr == "" {
		t.Error("Error() should return non-empty string")
	}
	if !contains(errStr, "test message") {
		t.Errorf("Expected error string to contain 'test message', got %q", errStr)
	}
}

func TestKubernetesError_Error_WithoutErr(t *testing.T) {
	kerr := &KubernetesError{
		Code:    ErrCodePodNotFound,
		Message: "test message",
		Err:     nil,
	}
	
	errStr := kerr.Error()
	if errStr != "test message" {
		t.Errorf("Expected error string 'test message', got %q", errStr)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || 
		(len(s) > len(substr) && containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

