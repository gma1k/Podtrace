package tracer

import "fmt"

type ErrorCode int

const (
	ErrCodeCollectionFailed ErrorCode = iota + 1
	ErrCodeRingBufferFailed
	ErrCodeMapLookupFailed
	ErrCodeInvalidEvent
)

type TracerError struct {
	Code    ErrorCode
	Message string
	Err     error
}

func (e *TracerError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *TracerError) Unwrap() error {
	return e.Err
}

func NewCollectionError(err error) *TracerError {
	return &TracerError{
		Code:    ErrCodeCollectionFailed,
		Message: "failed to create eBPF collection",
		Err:     err,
	}
}

func NewRingBufferError(err error) *TracerError {
	return &TracerError{
		Code:    ErrCodeRingBufferFailed,
		Message: "failed to create ring buffer reader",
		Err:     err,
	}
}

func NewMapLookupError(mapName string, err error) *TracerError {
	return &TracerError{
		Code:    ErrCodeMapLookupFailed,
		Message: fmt.Sprintf("failed to lookup map %s", mapName),
		Err:     err,
	}
}

func NewInvalidEventError(reason string) *TracerError {
	return &TracerError{
		Code:    ErrCodeInvalidEvent,
		Message: fmt.Sprintf("invalid event: %s", reason),
	}
}

