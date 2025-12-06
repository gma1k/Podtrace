package kubernetes

import "fmt"

type ErrorCode int

const (
	ErrCodeKubeconfigFailed ErrorCode = iota + 1
	ErrCodeClientsetFailed
	ErrCodePodNotFound
	ErrCodeNoContainers
	ErrCodeContainerNotFound
	ErrCodeInvalidContainerID
	ErrCodeCgroupNotFound
)

type KubernetesError struct {
	Code    ErrorCode
	Message string
	Err     error
}

func (e *KubernetesError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *KubernetesError) Unwrap() error {
	return e.Err
}

func NewKubeconfigError(err error) *KubernetesError {
	return &KubernetesError{
		Code:    ErrCodeKubeconfigFailed,
		Message: "failed to get kubeconfig",
		Err:     err,
	}
}

func NewClientsetError(err error) *KubernetesError {
	return &KubernetesError{
		Code:    ErrCodeClientsetFailed,
		Message: "failed to create Kubernetes clientset",
		Err:     err,
	}
}

func NewPodNotFoundError(podName, namespace string, err error) *KubernetesError {
	return &KubernetesError{
		Code:    ErrCodePodNotFound,
		Message: fmt.Sprintf("failed to get pod %s in namespace %s", podName, namespace),
		Err:     err,
	}
}

func NewNoContainersError() *KubernetesError {
	return &KubernetesError{
		Code:    ErrCodeNoContainers,
		Message: "pod has no containers",
	}
}

func NewContainerNotFoundError(containerName string) *KubernetesError {
	return &KubernetesError{
		Code:    ErrCodeContainerNotFound,
		Message: fmt.Sprintf("container %s not found in pod", containerName),
	}
}

func NewInvalidContainerIDError(reason string) *KubernetesError {
	return &KubernetesError{
		Code:    ErrCodeInvalidContainerID,
		Message: fmt.Sprintf("invalid container ID: %s", reason),
	}
}

func NewCgroupNotFoundError(containerID string) *KubernetesError {
	return &KubernetesError{
		Code:    ErrCodeCgroupNotFound,
		Message: fmt.Sprintf("cgroup path not found for container %s", containerID),
	}
}

