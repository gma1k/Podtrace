package loader

import "fmt"

type ErrorCode int

const (
	ErrCodeLoadFailed ErrorCode = iota + 1
)

type LoaderError struct {
	Code    ErrorCode
	Message string
	Err     error
}

func (e *LoaderError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *LoaderError) Unwrap() error {
	return e.Err
}

func NewLoadError(path string, err error) *LoaderError {
	return &LoaderError{
		Code:    ErrCodeLoadFailed,
		Message: fmt.Sprintf("failed to load eBPF program from %s", path),
		Err:     err,
	}
}

