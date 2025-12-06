package tracer

import (
	"errors"
	"testing"
)

func TestTracerError_Error(t *testing.T) {
	tests := []struct {
		name    string
		err     *TracerError
		wantMsg string
	}{
		{
			name: "error with wrapped error",
			err: &TracerError{
				Code:    ErrCodeCollectionFailed,
				Message: "test error",
				Err:     errors.New("wrapped error"),
			},
			wantMsg: "test error: wrapped error",
		},
		{
			name: "error without wrapped error",
			err: &TracerError{
				Code:    ErrCodeRingBufferFailed,
				Message: "test error",
				Err:     nil,
			},
			wantMsg: "test error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.wantMsg {
				t.Errorf("Error() = %v, want %v", got, tt.wantMsg)
			}
		})
	}
}

func TestTracerError_Unwrap(t *testing.T) {
	wrappedErr := errors.New("wrapped error")
	err := &TracerError{
		Code:    ErrCodeCollectionFailed,
		Message: "test error",
		Err:     wrappedErr,
	}

	unwrapped := err.Unwrap()
	if unwrapped != wrappedErr {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, wrappedErr)
	}

	errNoWrap := &TracerError{
		Code:    ErrCodeRingBufferFailed,
		Message: "test error",
		Err:     nil,
	}

	unwrapped = errNoWrap.Unwrap()
	if unwrapped != nil {
		t.Errorf("Unwrap() = %v, want nil", unwrapped)
	}
}

func TestNewCollectionError(t *testing.T) {
	wrappedErr := errors.New("collection failed")
	err := NewCollectionError(wrappedErr)

	if err == nil {
		t.Fatal("Expected non-nil error")
	}

	if err.Code != ErrCodeCollectionFailed {
		t.Errorf("Expected Code %d, got %d", ErrCodeCollectionFailed, err.Code)
	}

	if err.Message != "failed to create eBPF collection" {
		t.Errorf("Expected Message 'failed to create eBPF collection', got %q", err.Message)
	}

	if err.Err != wrappedErr {
		t.Errorf("Expected wrapped error %v, got %v", wrappedErr, err.Err)
	}
}

func TestNewRingBufferError(t *testing.T) {
	wrappedErr := errors.New("ring buffer failed")
	err := NewRingBufferError(wrappedErr)

	if err == nil {
		t.Fatal("Expected non-nil error")
	}

	if err.Code != ErrCodeRingBufferFailed {
		t.Errorf("Expected Code %d, got %d", ErrCodeRingBufferFailed, err.Code)
	}

	if err.Message != "failed to create ring buffer reader" {
		t.Errorf("Expected Message 'failed to create ring buffer reader', got %q", err.Message)
	}

	if err.Err != wrappedErr {
		t.Errorf("Expected wrapped error %v, got %v", wrappedErr, err.Err)
	}
}

func TestNewMapLookupError(t *testing.T) {
	mapName := "test_map"
	wrappedErr := errors.New("lookup failed")
	err := NewMapLookupError(mapName, wrappedErr)

	if err == nil {
		t.Fatal("Expected non-nil error")
	}

	if err.Code != ErrCodeMapLookupFailed {
		t.Errorf("Expected Code %d, got %d", ErrCodeMapLookupFailed, err.Code)
	}

	expectedMsg := "failed to lookup map test_map"
	if err.Message != expectedMsg {
		t.Errorf("Expected Message %q, got %q", expectedMsg, err.Message)
	}

	if err.Err != wrappedErr {
		t.Errorf("Expected wrapped error %v, got %v", wrappedErr, err.Err)
	}
}

func TestNewInvalidEventError(t *testing.T) {
	reason := "invalid format"
	err := NewInvalidEventError(reason)

	if err == nil {
		t.Fatal("Expected non-nil error")
	}

	if err.Code != ErrCodeInvalidEvent {
		t.Errorf("Expected Code %d, got %d", ErrCodeInvalidEvent, err.Code)
	}

	expectedMsg := "invalid event: invalid format"
	if err.Message != expectedMsg {
		t.Errorf("Expected Message %q, got %q", expectedMsg, err.Message)
	}

	if err.Err != nil {
		t.Errorf("Expected nil wrapped error, got %v", err.Err)
	}
}

