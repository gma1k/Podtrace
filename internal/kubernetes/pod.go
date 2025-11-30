package kubernetes

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/podtrace/podtrace/internal/validation"
)

// PodResolver resolves pod names to container IDs and cgroup paths
type PodResolver struct {
	clientset *kubernetes.Clientset
}

// NewPodResolver creates a new pod resolver
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
			return nil, fmt.Errorf("failed to get kubeconfig: %w", err)
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	return &PodResolver{clientset: clientset}, nil
}

// ResolvePod resolves a pod name and namespace to container information
func (r *PodResolver) ResolvePod(ctx context.Context, podName, namespace string) (*PodInfo, error) {
	pod, err := r.clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get pod: %w", err)
	}

	if len(pod.Status.ContainerStatuses) == 0 {
		return nil, fmt.Errorf("pod has no containers")
	}

	containerStatus := pod.Status.ContainerStatuses[0]
	containerID := containerStatus.ContainerID

	parts := strings.Split(containerID, "://")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid container ID format")
	}
	shortID := parts[1]

	if !validation.ValidateContainerID(shortID) {
		return nil, fmt.Errorf("invalid container ID")
	}

	cgroupPath, err := findCgroupPath(shortID)
	if err != nil {
		return nil, fmt.Errorf("failed to find cgroup path: %w", err)
	}

	return &PodInfo{
		PodName:       podName,
		Namespace:     namespace,
		ContainerID:   shortID,
		CgroupPath:    cgroupPath,
		ContainerName: pod.Spec.Containers[0].Name,
	}, nil
}

type PodInfo struct {
	PodName       string
	Namespace     string
	ContainerID   string
	CgroupPath    string
	ContainerName string
}

// findCgroupPath finds the cgroup path for a container ID
func findCgroupPath(containerID string) (string, error) {
	cgroupBase := "/sys/fs/cgroup"

	paths := []string{
		filepath.Join(cgroupBase, "kubepods.slice"),
		filepath.Join(cgroupBase, "system.slice"),
		filepath.Join(cgroupBase, "user.slice"),
	}

	for _, basePath := range paths {
		if _, err := os.Stat(basePath); os.IsNotExist(err) {
			continue
		}

		var foundPath string
		found := false
		filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if strings.Contains(path, containerID) || (len(containerID) >= 12 && strings.Contains(path, containerID[:12])) {
				foundPath = path
				found = true
				return fmt.Errorf("found")
			}
			return nil
		})

		if found && foundPath != "" {
			return foundPath, nil
		}
	}

	return "", fmt.Errorf("cgroup path not found for container")
}
