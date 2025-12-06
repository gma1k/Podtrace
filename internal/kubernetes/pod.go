package kubernetes

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/validation"
)

type PodResolver struct {
	clientset kubernetes.Interface
}

var _ PodResolverInterface = (*PodResolver)(nil)

func NewPodResolver() (*PodResolver, error) {
	var config *rest.Config
	var err error

	config, err = rest.InClusterConfig()
	if err != nil {
		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()

		if kubeconfig := os.Getenv("KUBECONFIG"); kubeconfig != "" {
			loadingRules.ExplicitPath = kubeconfig
		} else {
			sudoUser := os.Getenv("SUDO_USER")
			if sudoUser != "" {
				homePath := filepath.Join("/home", sudoUser, ".kube", "config")
				if _, err := os.Stat(homePath); err == nil {
					loadingRules.ExplicitPath = homePath
				}
			}
			if loadingRules.ExplicitPath == "" {
				if home := os.Getenv("HOME"); home != "" && home != "/root" {
					homePath := filepath.Join(home, ".kube", "config")
					if _, err := os.Stat(homePath); err == nil {
						loadingRules.ExplicitPath = homePath
					}
				}
			}
		}

		configOverrides := &clientcmd.ConfigOverrides{}
		kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)

		config, err = kubeConfig.ClientConfig()
		if err != nil {
			return nil, NewKubeconfigError(err)
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, NewClientsetError(err)
	}

	return &PodResolver{clientset: clientset}, nil
}

func (r *PodResolver) ResolvePod(ctx context.Context, podName, namespace, containerName string) (*PodInfo, error) {
	pod, err := r.clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return nil, NewPodNotFoundError(podName, namespace, err)
	}

	if len(pod.Status.ContainerStatuses) == 0 {
		return nil, NewNoContainersError()
	}

	var containerStatus *corev1.ContainerStatus
	var containerSpec *corev1.Container

	if containerName != "" {
		for i, status := range pod.Status.ContainerStatuses {
			if status.Name == containerName {
				containerStatus = &pod.Status.ContainerStatuses[i]
				for j, spec := range pod.Spec.Containers {
					if spec.Name == containerName {
						containerSpec = &pod.Spec.Containers[j]
						break
					}
				}
				break
			}
		}
		if containerStatus == nil {
			return nil, NewContainerNotFoundError(containerName)
		}
	} else {
		containerStatus = &pod.Status.ContainerStatuses[0]
		containerSpec = &pod.Spec.Containers[0]
	}

	containerID := containerStatus.ContainerID

	parts := strings.Split(containerID, "://")
	if len(parts) != 2 {
		return nil, NewInvalidContainerIDError("invalid container ID format")
	}
	shortID := parts[1]

	if !validation.ValidateContainerID(shortID) {
		return nil, NewInvalidContainerIDError("validation failed")
	}

	cgroupPath, err := findCgroupPath(shortID)
	if err != nil {
		return nil, NewCgroupNotFoundError(shortID)
	}

	return &PodInfo{
		PodName:       podName,
		Namespace:     namespace,
		ContainerID:   shortID,
		CgroupPath:    cgroupPath,
		ContainerName: containerSpec.Name,
	}, nil
}

type PodInfo struct {
	PodName       string
	Namespace     string
	ContainerID   string
	CgroupPath    string
	ContainerName string
}

func findCgroupPath(containerID string) (string, error) {
	paths := []string{
		filepath.Join(config.CgroupBasePath, "kubepods.slice"),
		filepath.Join(config.CgroupBasePath, "system.slice"),
		filepath.Join(config.CgroupBasePath, "user.slice"),
	}

	var errFound = errors.New("podtrace: cgroup found")

	for _, basePath := range paths {
		if _, err := os.Stat(basePath); os.IsNotExist(err) {
			continue
		}

		var foundPath string
		found := false
		_ = filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if strings.Contains(path, containerID) || (len(containerID) >= 12 && strings.Contains(path, containerID[:12])) {
				foundPath = path
				found = true
				return errFound
			}
			return nil
		})

		if found && foundPath != "" {
			return foundPath, nil
		}
	}

	return "", NewCgroupNotFoundError(containerID)
}
