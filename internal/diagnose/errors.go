package diagnose

import "fmt"

type ErrorCode int

const (
	ErrCodeEventLimitReached ErrorCode = iota + 1
	ErrCodeContextCancelled
	ErrCodeTimeout
	ErrCodeInvalidOperation
)

type DiagnoseError struct {
	Code    ErrorCode
	Message string
	Err     error
}

func (e *DiagnoseError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *DiagnoseError) Unwrap() error {
	return e.Err
}

func NewEventLimitError(dropped int) *DiagnoseError {
	return &DiagnoseError{
		Code:    ErrCodeEventLimitReached,
		Message: fmt.Sprintf("event limit reached, %d events dropped", dropped),
	}
}

func NewContextCancelledError(err error) *DiagnoseError {
	return &DiagnoseError{
		Code:    ErrCodeContextCancelled,
		Message: "operation cancelled",
		Err:     err,
	}
}

func NewTimeoutError(operation string) *DiagnoseError {
	return &DiagnoseError{
		Code:    ErrCodeTimeout,
		Message: fmt.Sprintf("operation timed out: %s", operation),
	}
}

func NewInvalidOperationError(operation string) *DiagnoseError {
	return &DiagnoseError{
		Code:    ErrCodeInvalidOperation,
		Message: fmt.Sprintf("invalid operation: %s", operation),
	}
}

