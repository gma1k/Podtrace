package loader

import (
	"errors"
	"testing"
)

func TestLoaderError_Error_WithErr(t *testing.T) {
	originalErr := errors.New("underlying error")
	loaderErr := &LoaderError{
		Code:    ErrCodeLoadFailed,
		Message: "test message",
		Err:     originalErr,
	}
	
	errStr := loaderErr.Error()
	if errStr == "" {
		t.Error("Error() should return non-empty string")
	}
	if !contains(errStr, "test message") {
		t.Errorf("Expected error string to contain 'test message', got %q", errStr)
	}
	if !contains(errStr, "underlying error") {
		t.Errorf("Expected error string to contain 'underlying error', got %q", errStr)
	}
}

func TestLoaderError_Error_WithoutErr(t *testing.T) {
	loaderErr := &LoaderError{
		Code:    ErrCodeLoadFailed,
		Message: "test message",
		Err:     nil,
	}
	
	errStr := loaderErr.Error()
	if errStr != "test message" {
		t.Errorf("Expected error string 'test message', got %q", errStr)
	}
}

func TestLoaderError_Unwrap(t *testing.T) {
	originalErr := errors.New("underlying error")
	loaderErr := &LoaderError{
		Code:    ErrCodeLoadFailed,
		Message: "test message",
		Err:     originalErr,
	}
	
	unwrapped := loaderErr.Unwrap()
	if unwrapped != originalErr {
		t.Errorf("Expected unwrapped error to be original error, got %v", unwrapped)
	}
}

func TestLoaderError_Unwrap_Nil(t *testing.T) {
	loaderErr := &LoaderError{
		Code:    ErrCodeLoadFailed,
		Message: "test message",
		Err:     nil,
	}
	
	unwrapped := loaderErr.Unwrap()
	if unwrapped != nil {
		t.Errorf("Expected unwrapped error to be nil, got %v", unwrapped)
	}
}

func TestNewLoadError(t *testing.T) {
	originalErr := errors.New("file not found")
	loaderErr := NewLoadError("/path/to/bpf.o", originalErr)
	
	if loaderErr == nil {
		t.Fatal("NewLoadError returned nil")
	}
	if loaderErr.Code != ErrCodeLoadFailed {
		t.Errorf("Expected error code %d, got %d", ErrCodeLoadFailed, loaderErr.Code)
	}
	if !contains(loaderErr.Message, "failed to load eBPF program") {
		t.Errorf("Expected message to contain 'failed to load eBPF program', got %q", loaderErr.Message)
	}
	if !contains(loaderErr.Message, "/path/to/bpf.o") {
		t.Errorf("Expected message to contain '/path/to/bpf.o', got %q", loaderErr.Message)
	}
	if loaderErr.Unwrap() != originalErr {
		t.Errorf("Expected unwrapped error to be original error")
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

