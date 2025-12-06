package probes

import "fmt"

type ErrorCode int

const (
	ErrCodeProbeAttachFailed ErrorCode = iota + 1
)

type ProbeError struct {
	Code    ErrorCode
	Message string
	Err     error
}

func (e *ProbeError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *ProbeError) Unwrap() error {
	return e.Err
}

func NewProbeAttachError(probeName string, err error) *ProbeError {
	return &ProbeError{
		Code:    ErrCodeProbeAttachFailed,
		Message: fmt.Sprintf("failed to attach probe %s", probeName),
		Err:     err,
	}
}

