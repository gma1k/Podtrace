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

func (r *PodResolver) GetClientset() kubernetes.Interface {
	return r.clientset
}

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
		cgroupPathFromProc, procErr := findCgroupPathFromProc(shortID)
		if procErr == nil && cgroupPathFromProc != "" {
			cgroupPath = cgroupPathFromProc
		} else {
			return nil, NewCgroupNotFoundError(shortID)
		}
	}

	labels := make(map[string]string)
	if pod.Labels != nil {
		for k, v := range pod.Labels {
			labels[k] = v
		}
	}

	var ownerKind, ownerName string
	if len(pod.OwnerReferences) > 0 {
		ownerKind = pod.OwnerReferences[0].Kind
		ownerName = pod.OwnerReferences[0].Name
	}

	return &PodInfo{
		PodName:       podName,
		Namespace:     namespace,
		ContainerID:   shortID,
		CgroupPath:    cgroupPath,
		ContainerName: containerSpec.Name,
		Labels:        labels,
		PodIP:         pod.Status.PodIP,
		OwnerKind:     ownerKind,
		OwnerName:     ownerName,
	}, nil
}

type PodInfo struct {
	PodName       string
	Namespace     string
	ContainerID   string
	CgroupPath    string
	ContainerName string
	Labels        map[string]string
	PodIP         string
	OwnerKind     string
	OwnerName     string
}

func findCgroupPath(containerID string) (string, error) {
	isV2, _ := isCgroupV2(config.CgroupBasePath)

	if isV2 {
		return findCgroupPathV2(containerID)
	}

	return findCgroupPathV1(containerID)
}

func isCgroupV2(basePath string) (bool, error) {
	controllersPath := filepath.Join(basePath, "cgroup.controllers")
	if _, err := os.Stat(controllersPath); err == nil {
		return true, nil
	}
	return false, nil
}

func findCgroupPathV2(containerID string) (string, error) {
	basePaths := []string{
		filepath.Join(config.CgroupBasePath, "kubepods"),
		filepath.Join(config.CgroupBasePath, "kubepods.slice"),
		filepath.Join(config.CgroupBasePath, "kubepods-burstable"),
		filepath.Join(config.CgroupBasePath, "kubepods-burstable.slice"),
		filepath.Join(config.CgroupBasePath, "kubepods-besteffort"),
		filepath.Join(config.CgroupBasePath, "kubepods-besteffort.slice"),
		filepath.Join(config.CgroupBasePath, "system"),
		filepath.Join(config.CgroupBasePath, "system.slice"),
		filepath.Join(config.CgroupBasePath, "user"),
		filepath.Join(config.CgroupBasePath, "user.slice"),
		config.CgroupBasePath,
	}

	var errFound = errors.New("podtrace: cgroup found")
	shortID := containerID
	if len(containerID) >= 12 {
		shortID = containerID[:12]
	}

	for _, basePath := range basePaths {
		if _, err := os.Stat(basePath); os.IsNotExist(err) {
			continue
		}

		var foundPath string
		found := false
		_ = filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if !info.IsDir() {
				return nil
			}
			baseName := filepath.Base(path)
			pathStr := path
			if strings.Contains(pathStr, containerID) || strings.Contains(pathStr, shortID) || strings.Contains(baseName, containerID) || strings.Contains(baseName, shortID) {
				cgroupProcsPath := filepath.Join(path, "cgroup.procs")
				if _, err := os.Stat(cgroupProcsPath); err == nil {
					foundPath = path
					found = true
					return errFound
				}
			}
			return nil
		})

		if found && foundPath != "" {
			return foundPath, nil
		}
	}

	return "", NewCgroupNotFoundError(containerID)
}

func findCgroupPathV1(containerID string) (string, error) {
	paths := []string{
		filepath.Join(config.CgroupBasePath, "kubepods.slice"),
		filepath.Join(config.CgroupBasePath, "system.slice"),
		filepath.Join(config.CgroupBasePath, "user.slice"),
	}

	var errFound = errors.New("podtrace: cgroup found")
	shortID := containerID
	if len(containerID) >= 12 {
		shortID = containerID[:12]
	}

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
			if strings.Contains(path, containerID) || strings.Contains(path, shortID) {
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

func findCgroupPathFromProc(containerID string) (string, error) {
	procPath := config.ProcBasePath
	shortID := containerID
	if len(containerID) >= 12 {
		shortID = containerID[:12]
	}

	entries, err := os.ReadDir(procPath)
	if err != nil {
		return "", NewCgroupNotFoundError(containerID)
	}

	var foundPath string

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pidStr := entry.Name()
		if len(pidStr) == 0 || pidStr[0] < '0' || pidStr[0] > '9' {
			continue
		}

		cgroupFile := filepath.Join(procPath, pidStr, "cgroup")
		data, err := os.ReadFile(cgroupFile)
		if err != nil {
			continue
		}

		cgroupContent := string(data)
		if !strings.Contains(cgroupContent, containerID) && !strings.Contains(cgroupContent, shortID) {
			continue
		}

		lines := strings.Split(cgroupContent, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			if strings.HasPrefix(line, "0::") {
				cgroupPath := strings.TrimPrefix(line, "0::")
				if cgroupPath == "" || cgroupPath == "/" {
					fullPath := config.CgroupBasePath
					if _, err := os.Stat(fullPath); err == nil {
						if _, err := os.Stat(filepath.Join(fullPath, "cgroup.procs")); err == nil {
							foundPath = fullPath
							break
						}
					}
				} else {
					fullPath := filepath.Join(config.CgroupBasePath, cgroupPath)
					if _, err := os.Stat(fullPath); err == nil {
						if _, err := os.Stat(filepath.Join(fullPath, "cgroup.procs")); err == nil {
							foundPath = fullPath
							break
						}
					}
				}
			} else {
				parts := strings.Split(line, ":")
				if len(parts) >= 3 {
					cgroupPath := parts[2]
					if cgroupPath != "" && cgroupPath != "/" {
						fullPath := filepath.Join(config.CgroupBasePath, cgroupPath)
						if _, err := os.Stat(fullPath); err == nil {
							foundPath = fullPath
							break
						}
					}
				}
			}
		}

		if foundPath != "" {
			break
		}
	}

	if foundPath != "" {
		return foundPath, nil
	}

	return "", NewCgroupNotFoundError(containerID)
}
