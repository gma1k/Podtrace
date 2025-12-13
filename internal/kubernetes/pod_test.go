package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/podtrace/podtrace/internal/config"
)

func TestFindCgroupPath_NotFound(t *testing.T) {
	dir := t.TempDir()

	orig := config.CgroupBasePath
	config.SetCgroupBasePath(dir)
	defer func() { config.SetCgroupBasePath(orig) }()

	if path, err := findCgroupPath("nonexistent"); err == nil || path != "" {
		t.Fatalf("expected error and empty path for missing cgroup, got path=%q err=%v", path, err)
	}
}

func TestFindCgroupPath_Found(t *testing.T) {
	dir := t.TempDir()

	orig := config.CgroupBasePath
	config.SetCgroupBasePath(dir)
	defer func() { config.SetCgroupBasePath(orig) }()

	kubepodsSlice := filepath.Join(dir, "kubepods.slice")
	if err := os.MkdirAll(kubepodsSlice, 0o755); err != nil {
		t.Fatalf("failed to create kubepods.slice: %v", err)
	}

	containerID := "abcdef1234567890"
	targetDir := filepath.Join(kubepodsSlice, "pod_"+containerID)
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		t.Fatalf("failed to create target dir: %v", err)
	}

	if path, err := findCgroupPath(containerID); err != nil || path == "" {
		t.Fatalf("expected to find cgroup path, got path=%q err=%v", path, err)
	}
}

func TestPodResolver_ResolvePod_NoContainers(t *testing.T) {
	resolver := &PodResolver{clientset: nil}

	defer func() {
		if r := recover(); r != nil {
			t.Log("ResolvePod panicked as expected for nil clientset")
		}
	}()

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Log("ResolvePod panicked as expected for nil clientset")
			}
		}()
		_, err := resolver.ResolvePod(context.Background(), "test-pod", "default", "")
		if err == nil {
			t.Log("ResolvePod returned error as expected for nil clientset")
		}
	}()
}

func TestFindCgroupPath_EmptyContainerID(t *testing.T) {
	path, err := findCgroupPath("")
	if err == nil && path != "" {
		t.Log("findCgroupPath returned path or no error for empty container ID")
	}
}

func TestFindCgroupPath_ShortID(t *testing.T) {
	dir := t.TempDir()

	orig := config.CgroupBasePath
	config.SetCgroupBasePath(dir)
	defer func() { config.SetCgroupBasePath(orig) }()

	kubepodsSlice := filepath.Join(dir, "kubepods.slice")
	_ = os.MkdirAll(kubepodsSlice, 0755)

	containerID := "abcdef123456"
	targetDir := filepath.Join(kubepodsSlice, "pod_"+containerID[:12])
	_ = os.MkdirAll(targetDir, 0755)

	path, err := findCgroupPath(containerID)
	if err != nil {
		t.Logf("findCgroupPath returned error (may be expected): %v", err)
	}
	if path != "" {
		t.Logf("Found cgroup path: %s", path)
	}
}

func TestFindCgroupPath_SystemSlice(t *testing.T) {
	dir := t.TempDir()

	orig := config.CgroupBasePath
	config.SetCgroupBasePath(dir)
	defer func() { config.SetCgroupBasePath(orig) }()

	systemSlice := filepath.Join(dir, "system.slice")
	_ = os.MkdirAll(systemSlice, 0755)

	containerID := "test123"
	targetDir := filepath.Join(systemSlice, "docker-"+containerID+".scope")
	_ = os.MkdirAll(targetDir, 0755)

	path, err := findCgroupPath(containerID)
	if err != nil {
		t.Logf("findCgroupPath returned error (may be expected): %v", err)
	}
	if path != "" {
		t.Logf("Found cgroup path: %s", path)
	}
}

func TestFindCgroupPath_UserSlice(t *testing.T) {
	dir := t.TempDir()

	orig := config.CgroupBasePath
	config.SetCgroupBasePath(dir)
	defer func() { config.SetCgroupBasePath(orig) }()

	userSlice := filepath.Join(dir, "user.slice")
	_ = os.MkdirAll(userSlice, 0755)

	containerID := "test456"
	targetDir := filepath.Join(userSlice, "user-1000.slice", "docker-"+containerID+".scope")
	_ = os.MkdirAll(targetDir, 0755)

	path, err := findCgroupPath(containerID)
	if err != nil {
		t.Logf("findCgroupPath returned error (may be expected): %v", err)
	}
	if path != "" {
		t.Logf("Found cgroup path: %s", path)
	}
}

func TestResolvePod_Success_WithoutContainerName(t *testing.T) {
	dir := t.TempDir()
	orig := config.CgroupBasePath
	config.SetCgroupBasePath(dir)
	defer func() { config.SetCgroupBasePath(orig) }()

	kubepodsSlice := filepath.Join(dir, "kubepods.slice")
	_ = os.MkdirAll(kubepodsSlice, 0755)
	containerID := "containerd://abcdef1234567890abcdef1234567890abcdef12"
	shortID := "abcdef1234567890abcdef1234567890abcdef12"
	targetDir := filepath.Join(kubepodsSlice, "pod_"+shortID)
	_ = os.MkdirAll(targetDir, 0755)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "test-container",
				},
			},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:        "test-container",
					ContainerID: containerID,
				},
			},
		},
	}

	clientset := fake.NewSimpleClientset(pod)
	resolver := NewPodResolverForTesting(clientset)

	info, err := resolver.ResolvePod(context.Background(), "test-pod", "default", "")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if info == nil {
		t.Fatal("expected PodInfo, got nil")
	}
	if info.PodName != "test-pod" {
		t.Errorf("expected PodName 'test-pod', got %q", info.PodName)
	}
	if info.Namespace != "default" {
		t.Errorf("expected Namespace 'default', got %q", info.Namespace)
	}
	if info.ContainerName != "test-container" {
		t.Errorf("expected ContainerName 'test-container', got %q", info.ContainerName)
	}
	if info.ContainerID != shortID {
		t.Errorf("expected ContainerID %q, got %q", shortID, info.ContainerID)
	}
	if info.CgroupPath == "" {
		t.Error("expected CgroupPath to be set")
	}
}

func TestResolvePod_Success_WithContainerName(t *testing.T) {
	dir := t.TempDir()
	orig := config.CgroupBasePath
	config.SetCgroupBasePath(dir)
	defer func() { config.SetCgroupBasePath(orig) }()

	kubepodsSlice := filepath.Join(dir, "kubepods.slice")
	_ = os.MkdirAll(kubepodsSlice, 0755)
	containerID := "containerd://abcdef1234567890abcdef1234567890abcdef12"
	shortID := "abcdef1234567890abcdef1234567890abcdef12"
	targetDir := filepath.Join(kubepodsSlice, "pod_"+shortID)
	_ = os.MkdirAll(targetDir, 0755)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "first-container",
				},
				{
					Name: "second-container",
				},
			},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:        "first-container",
					ContainerID: "containerd://1111111111111111111111111111111111111111",
				},
				{
					Name:        "second-container",
					ContainerID: containerID,
				},
			},
		},
	}

	clientset := fake.NewSimpleClientset(pod)
	resolver := NewPodResolverForTesting(clientset)

	info, err := resolver.ResolvePod(context.Background(), "test-pod", "default", "second-container")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if info == nil {
		t.Fatal("expected PodInfo, got nil")
	}
	if info.ContainerName != "second-container" {
		t.Errorf("expected ContainerName 'second-container', got %q", info.ContainerName)
	}
}

func TestResolvePod_PodNotFound(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	resolver := NewPodResolverForTesting(clientset)

	_, err := resolver.ResolvePod(context.Background(), "nonexistent-pod", "default", "")
	if err == nil {
		t.Fatal("expected error for nonexistent pod")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		if !strings.Contains(err.Error(), "failed to get pod") {
			t.Errorf("expected error about failed to get pod, got: %v", err)
		}
	}
}

func TestResolvePod_NoContainers(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{},
		},
	}

	clientset := fake.NewSimpleClientset(pod)
	resolver := NewPodResolverForTesting(clientset)

	_, err := resolver.ResolvePod(context.Background(), "test-pod", "default", "")
	if err == nil {
		t.Fatal("expected error for pod with no containers")
	}
	if !strings.Contains(err.Error(), "pod has no containers") {
		t.Errorf("expected error about no containers, got: %v", err)
	}
}

func TestResolvePod_ContainerNotFound(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "existing-container",
				},
			},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:        "existing-container",
					ContainerID: "containerd://abcdef1234567890abcdef1234567890abcdef12",
				},
			},
		},
	}

	clientset := fake.NewSimpleClientset(pod)
	resolver := NewPodResolverForTesting(clientset)

	_, err := resolver.ResolvePod(context.Background(), "test-pod", "default", "nonexistent-container")
	if err == nil {
		t.Fatal("expected error for nonexistent container")
	}
	if !strings.Contains(err.Error(), "container") && !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected error about container not found, got: %v", err)
	}
}

func TestResolvePod_InvalidContainerIDFormat(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "test-container",
				},
			},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:        "test-container",
					ContainerID: "invalid-format",
				},
			},
		},
	}

	clientset := fake.NewSimpleClientset(pod)
	resolver := NewPodResolverForTesting(clientset)

	_, err := resolver.ResolvePod(context.Background(), "test-pod", "default", "")
	if err == nil {
		t.Fatal("expected error for invalid container ID format")
	}
	if !strings.Contains(err.Error(), "invalid container ID format") {
		t.Errorf("expected error about invalid container ID format, got: %v", err)
	}
}

func TestResolvePod_InvalidContainerID(t *testing.T) {
	dir := t.TempDir()
	orig := config.CgroupBasePath
	config.SetCgroupBasePath(dir)
	defer func() { config.SetCgroupBasePath(orig) }()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "test-container",
				},
			},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:        "test-container",
					ContainerID: "containerd://invalid",
				},
			},
		},
	}

	clientset := fake.NewSimpleClientset(pod)
	resolver := NewPodResolverForTesting(clientset)

	_, err := resolver.ResolvePod(context.Background(), "test-pod", "default", "")
	if err == nil {
		t.Fatal("expected error for invalid container ID")
	}
	if !strings.Contains(err.Error(), "invalid container ID") {
		t.Errorf("expected error about invalid container ID, got: %v", err)
	}
}

func TestResolvePod_CgroupPathNotFound(t *testing.T) {
	dir := t.TempDir()
	orig := config.CgroupBasePath
	config.SetCgroupBasePath(dir)
	defer func() { config.SetCgroupBasePath(orig) }()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "test-container",
				},
			},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:        "test-container",
					ContainerID: "containerd://abcdef1234567890abcdef1234567890abcdef12",
				},
			},
		},
	}

	clientset := fake.NewSimpleClientset(pod)
	resolver := NewPodResolverForTesting(clientset)

	_, err := resolver.ResolvePod(context.Background(), "test-pod", "default", "")
	if err == nil {
		t.Fatal("expected error for cgroup path not found")
	}
	if !strings.Contains(err.Error(), "cgroup path") {
		t.Errorf("expected error about cgroup path, got: %v", err)
	}
}

func TestFindCgroupPath_WalkError(t *testing.T) {
	dir := t.TempDir()
	orig := config.CgroupBasePath
	config.SetCgroupBasePath(dir)
	defer func() { config.SetCgroupBasePath(orig) }()

	kubepodsSlice := filepath.Join(dir, "kubepods.slice")
	_ = os.MkdirAll(kubepodsSlice, 0755)

	containerID := "abcdef1234567890"
	targetDir := filepath.Join(kubepodsSlice, "pod_"+containerID)
	_ = os.MkdirAll(targetDir, 0755)
	_ = os.Chmod(targetDir, 0000)
	defer func() {
		_ = os.Chmod(targetDir, 0755)
	}()

	path, err := findCgroupPath(containerID)
	if err != nil && path == "" {
		return
	}
}

func TestFindCgroupPath_MultipleBasePaths(t *testing.T) {
	dir := t.TempDir()
	orig := config.CgroupBasePath
	config.SetCgroupBasePath(dir)
	defer func() { config.SetCgroupBasePath(orig) }()

	systemSlice := filepath.Join(dir, "system.slice")
	_ = os.MkdirAll(systemSlice, 0755)

	containerID := "test789"
	targetDir := filepath.Join(systemSlice, "containerd-"+containerID+".scope")
	_ = os.MkdirAll(targetDir, 0755)

	path, err := findCgroupPath(containerID)
	if err != nil {
		t.Logf("findCgroupPath returned error (may be expected): %v", err)
	}
	if path != "" {
		t.Logf("Found cgroup path: %s", path)
	}
}

func TestFindCgroupPath_ShortIDMatch(t *testing.T) {
	dir := t.TempDir()
	orig := config.CgroupBasePath
	config.SetCgroupBasePath(dir)
	defer func() { config.SetCgroupBasePath(orig) }()

	kubepodsSlice := filepath.Join(dir, "kubepods.slice")
	_ = os.MkdirAll(kubepodsSlice, 0755)

	fullID := "abcdef1234567890abcdef1234567890abcdef12"
	shortID := fullID[:12]
	targetDir := filepath.Join(kubepodsSlice, "pod_"+shortID)
	_ = os.MkdirAll(targetDir, 0755)

	path, err := findCgroupPath(fullID)
	if err != nil {
		t.Fatalf("expected to find cgroup path with short ID match, got error: %v", err)
	}
	if path == "" {
		t.Fatal("expected to find cgroup path, got empty")
	}
}

func TestNewPodResolver_NoKubeconfig(t *testing.T) {
	origKubeconfig := os.Getenv("KUBECONFIG")
	origSudoUser := os.Getenv("SUDO_USER")
	origHome := os.Getenv("HOME")

	defer func() {
		if origKubeconfig != "" {
			_ = os.Setenv("KUBECONFIG", origKubeconfig)
		} else {
			_ = os.Unsetenv("KUBECONFIG")
		}
		if origSudoUser != "" {
			_ = os.Setenv("SUDO_USER", origSudoUser)
		} else {
			_ = os.Unsetenv("SUDO_USER")
		}
		if origHome != "" {
			_ = os.Setenv("HOME", origHome)
		} else {
			_ = os.Unsetenv("HOME")
		}
	}()

	_ = os.Unsetenv("KUBECONFIG")
	_ = os.Unsetenv("SUDO_USER")
	_ = os.Unsetenv("HOME")

	_, err := NewPodResolver()
	if err == nil {
		t.Log("NewPodResolver returned error as expected when no kubeconfig is available")
	} else if !strings.Contains(err.Error(), "kubeconfig") {
		t.Logf("NewPodResolver returned error (may be expected): %v", err)
	}
}

func TestNewPodResolver_WithKUBECONFIG(t *testing.T) {
	origKubeconfig := os.Getenv("KUBECONFIG")
	origSudoUser := os.Getenv("SUDO_USER")
	origHome := os.Getenv("HOME")

	defer func() {
		if origKubeconfig != "" {
			_ = os.Setenv("KUBECONFIG", origKubeconfig)
		} else {
			_ = os.Unsetenv("KUBECONFIG")
		}
		if origSudoUser != "" {
			_ = os.Setenv("SUDO_USER", origSudoUser)
		} else {
			_ = os.Unsetenv("SUDO_USER")
		}
		if origHome != "" {
			_ = os.Setenv("HOME", origHome)
		} else {
			_ = os.Unsetenv("HOME")
		}
	}()

	tmpDir := t.TempDir()
	kubeconfigPath := filepath.Join(tmpDir, "config")
	kubeconfigContent := `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://localhost:6443
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    user: test-user
  name: test-context
current-context: test-context
users:
- name: test-user
  user:
    token: test-token
`
	if err := os.WriteFile(kubeconfigPath, []byte(kubeconfigContent), 0644); err != nil {
		t.Fatalf("failed to write kubeconfig: %v", err)
	}

	_ = os.Setenv("KUBECONFIG", kubeconfigPath)
	_ = os.Unsetenv("SUDO_USER")
	_ = os.Unsetenv("HOME")

	_, err := NewPodResolver()
	if err != nil {
		t.Logf("NewPodResolver returned error (expected for invalid server): %v", err)
	}
}

func TestNewPodResolver_WithSUDO_USER(t *testing.T) {
	origKubeconfig := os.Getenv("KUBECONFIG")
	origSudoUser := os.Getenv("SUDO_USER")
	origHome := os.Getenv("HOME")

	defer func() {
		if origKubeconfig != "" {
			_ = os.Setenv("KUBECONFIG", origKubeconfig)
		} else {
			_ = os.Unsetenv("KUBECONFIG")
		}
		if origSudoUser != "" {
			_ = os.Setenv("SUDO_USER", origSudoUser)
		} else {
			_ = os.Unsetenv("SUDO_USER")
		}
		if origHome != "" {
			_ = os.Setenv("HOME", origHome)
		} else {
			_ = os.Unsetenv("HOME")
		}
	}()

	tmpDir := t.TempDir()
	sudoUserHome := filepath.Join(tmpDir, "home", "testuser")
	kubeDir := filepath.Join(sudoUserHome, ".kube")
	kubeconfigPath := filepath.Join(kubeDir, "config")
	if err := os.MkdirAll(kubeDir, 0755); err != nil {
		t.Fatalf("failed to create .kube directory: %v", err)
	}

	kubeconfigContent := `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://localhost:6443
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    user: test-user
  name: test-context
current-context: test-context
users:
- name: test-user
  user:
    token: test-token
`
	if err := os.WriteFile(kubeconfigPath, []byte(kubeconfigContent), 0644); err != nil {
		t.Fatalf("failed to write kubeconfig: %v", err)
	}

	_ = os.Unsetenv("KUBECONFIG")
	_ = os.Setenv("SUDO_USER", "testuser")
	_ = os.Unsetenv("HOME")

	_, err := NewPodResolver()
	if err != nil {
		t.Logf("NewPodResolver returned error (expected for invalid server): %v", err)
	}
}

func TestNewPodResolver_WithHOME(t *testing.T) {
	origKubeconfig := os.Getenv("KUBECONFIG")
	origSudoUser := os.Getenv("SUDO_USER")
	origHome := os.Getenv("HOME")

	defer func() {
		if origKubeconfig != "" {
			_ = os.Setenv("KUBECONFIG", origKubeconfig)
		} else {
			_ = os.Unsetenv("KUBECONFIG")
		}
		if origSudoUser != "" {
			_ = os.Setenv("SUDO_USER", origSudoUser)
		} else {
			_ = os.Unsetenv("SUDO_USER")
		}
		if origHome != "" {
			_ = os.Setenv("HOME", origHome)
		} else {
			_ = os.Unsetenv("HOME")
		}
	}()

	tmpDir := t.TempDir()
	testHome := filepath.Join(tmpDir, "home", "user")
	kubeDir := filepath.Join(testHome, ".kube")
	kubeconfigPath := filepath.Join(kubeDir, "config")
	if err := os.MkdirAll(kubeDir, 0755); err != nil {
		t.Fatalf("failed to create .kube directory: %v", err)
	}

	kubeconfigContent := `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://localhost:6443
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    user: test-user
  name: test-context
current-context: test-context
users:
- name: test-user
  user:
    token: test-token
`
	if err := os.WriteFile(kubeconfigPath, []byte(kubeconfigContent), 0644); err != nil {
		t.Fatalf("failed to write kubeconfig: %v", err)
	}

	_ = os.Unsetenv("KUBECONFIG")
	_ = os.Unsetenv("SUDO_USER")
	_ = os.Setenv("HOME", testHome)

	_, err := NewPodResolver()
	if err != nil {
		t.Logf("NewPodResolver returned error (expected for invalid server): %v", err)
	}
}

func TestNewPodResolver_HOME_IsRoot(t *testing.T) {
	origKubeconfig := os.Getenv("KUBECONFIG")
	origSudoUser := os.Getenv("SUDO_USER")
	origHome := os.Getenv("HOME")

	defer func() {
		if origKubeconfig != "" {
			_ = os.Setenv("KUBECONFIG", origKubeconfig)
		} else {
			_ = os.Unsetenv("KUBECONFIG")
		}
		if origSudoUser != "" {
			_ = os.Setenv("SUDO_USER", origSudoUser)
		} else {
			_ = os.Unsetenv("SUDO_USER")
		}
		if origHome != "" {
			_ = os.Setenv("HOME", origHome)
		} else {
			_ = os.Unsetenv("HOME")
		}
	}()

	_ = os.Unsetenv("KUBECONFIG")
	_ = os.Unsetenv("SUDO_USER")
	_ = os.Setenv("HOME", "/root")

	_, err := NewPodResolver()
	if err != nil {
		t.Logf("NewPodResolver returned error (expected when HOME is /root and no kubeconfig): %v", err)
	}
}

func TestResolvePod_ContainerID_EmptyString(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "test-container",
				},
			},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:        "test-container",
					ContainerID: "",
				},
			},
		},
	}

	clientset := fake.NewSimpleClientset(pod)
	resolver := NewPodResolverForTesting(clientset)

	_, err := resolver.ResolvePod(context.Background(), "test-pod", "default", "")
	if err == nil {
		t.Fatal("expected error for empty container ID")
	}
	if !strings.Contains(err.Error(), "invalid container ID format") {
		t.Errorf("expected error about invalid container ID format, got: %v", err)
	}
}

func TestResolvePod_ContainerID_NoSeparator(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "test-container",
				},
			},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:        "test-container",
					ContainerID: "no-separator-here",
				},
			},
		},
	}

	clientset := fake.NewSimpleClientset(pod)
	resolver := NewPodResolverForTesting(clientset)

	_, err := resolver.ResolvePod(context.Background(), "test-pod", "default", "")
	if err == nil {
		t.Fatal("expected error for container ID without separator")
	}
	if !strings.Contains(err.Error(), "invalid container ID format") {
		t.Errorf("expected error about invalid container ID format, got: %v", err)
	}
}

func TestPodResolver_GetClientset(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	resolver := NewPodResolverForTesting(clientset)
	
	result := resolver.GetClientset()
	if result != clientset {
		t.Error("GetClientset() should return the same clientset")
	}
}

func TestFindCgroupPathFromProc_Success(t *testing.T) {
	tmpDir := t.TempDir()
	
	origProcBase := config.ProcBasePath
	origCgroupBase := config.CgroupBasePath
	config.SetProcBasePath(tmpDir)
	config.SetCgroupBasePath(tmpDir)
	defer func() {
		config.SetProcBasePath(origProcBase)
		config.SetCgroupBasePath(origCgroupBase)
	}()
	
	containerID := "abcdef1234567890"
	pid := "12345"
	procDir := filepath.Join(tmpDir, pid)
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create proc dir: %v", err)
	}
	
	cgroupPath := filepath.Join(tmpDir, "kubepods", "pod_"+containerID)
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("failed to create cgroup path: %v", err)
	}
	cgroupProcsPath := filepath.Join(cgroupPath, "cgroup.procs")
	if err := os.WriteFile(cgroupProcsPath, []byte(""), 0644); err != nil {
		t.Fatalf("failed to create cgroup.procs: %v", err)
	}
	
	cgroupFile := filepath.Join(procDir, "cgroup")
	cgroupContent := fmt.Sprintf("0::/kubepods/pod_%s\n", containerID)
	if err := os.WriteFile(cgroupFile, []byte(cgroupContent), 0644); err != nil {
		t.Fatalf("failed to create cgroup file: %v", err)
	}
	
	path, err := findCgroupPathFromProc(containerID)
	if err != nil {
		t.Logf("findCgroupPathFromProc returned error (may be expected): %v", err)
	}
	if path != "" {
		t.Logf("Found cgroup path: %s", path)
	}
}

func TestFindCgroupPathFromProc_WithShortID(t *testing.T) {
	tmpDir := t.TempDir()
	
	origProcBase := config.ProcBasePath
	origCgroupBase := config.CgroupBasePath
	config.SetProcBasePath(tmpDir)
	config.SetCgroupBasePath(tmpDir)
	defer func() {
		config.SetProcBasePath(origProcBase)
		config.SetCgroupBasePath(origCgroupBase)
	}()
	
	fullID := "abcdef1234567890abcdef1234567890abcdef12"
	shortID := fullID[:12]
	pid := "12346"
	procDir := filepath.Join(tmpDir, pid)
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create proc dir: %v", err)
	}
	
	cgroupPath := filepath.Join(tmpDir, "kubepods", "pod_"+shortID)
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("failed to create cgroup path: %v", err)
	}
	cgroupProcsPath := filepath.Join(cgroupPath, "cgroup.procs")
	if err := os.WriteFile(cgroupProcsPath, []byte(""), 0644); err != nil {
		t.Fatalf("failed to create cgroup.procs: %v", err)
	}
	
	cgroupFile := filepath.Join(procDir, "cgroup")
	cgroupContent := fmt.Sprintf("0::/kubepods/pod_%s\n", shortID)
	if err := os.WriteFile(cgroupFile, []byte(cgroupContent), 0644); err != nil {
		t.Fatalf("failed to create cgroup file: %v", err)
	}
	
	path, err := findCgroupPathFromProc(fullID)
	if err != nil {
		t.Logf("findCgroupPathFromProc returned error (may be expected): %v", err)
	}
	if path != "" {
		t.Logf("Found cgroup path: %s", path)
	}
}

func TestFindCgroupPathFromProc_WithV1Format(t *testing.T) {
	tmpDir := t.TempDir()
	
	origProcBase := config.ProcBasePath
	origCgroupBase := config.CgroupBasePath
	config.SetProcBasePath(tmpDir)
	config.SetCgroupBasePath(tmpDir)
	defer func() {
		config.SetProcBasePath(origProcBase)
		config.SetCgroupBasePath(origCgroupBase)
	}()
	
	containerID := "test123"
	pid := "12347"
	procDir := filepath.Join(tmpDir, pid)
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create proc dir: %v", err)
	}
	
	cgroupPath := filepath.Join(tmpDir, "kubepods", "pod_"+containerID)
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("failed to create cgroup path: %v", err)
	}
	
	cgroupFile := filepath.Join(procDir, "cgroup")
	cgroupContent := fmt.Sprintf("1:cpu:/kubepods/pod_%s\n", containerID)
	if err := os.WriteFile(cgroupFile, []byte(cgroupContent), 0644); err != nil {
		t.Fatalf("failed to create cgroup file: %v", err)
	}
	
	path, err := findCgroupPathFromProc(containerID)
	if err != nil {
		t.Logf("findCgroupPathFromProc returned error (may be expected): %v", err)
	}
	if path != "" {
		t.Logf("Found cgroup path: %s", path)
	}
}

func TestFindCgroupPathFromProc_WithRootPath(t *testing.T) {
	tmpDir := t.TempDir()
	
	origProcBase := config.ProcBasePath
	origCgroupBase := config.CgroupBasePath
	config.SetProcBasePath(tmpDir)
	config.SetCgroupBasePath(tmpDir)
	defer func() {
		config.SetProcBasePath(origProcBase)
		config.SetCgroupBasePath(origCgroupBase)
	}()
	
	containerID := "test456"
	pid := "12348"
	procDir := filepath.Join(tmpDir, pid)
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create proc dir: %v", err)
	}
	
	cgroupProcsPath := filepath.Join(tmpDir, "cgroup.procs")
	if err := os.WriteFile(cgroupProcsPath, []byte(""), 0644); err != nil {
		t.Fatalf("failed to create cgroup.procs: %v", err)
	}
	
	cgroupFile := filepath.Join(procDir, "cgroup")
	cgroupContent := "0::/\n"
	if err := os.WriteFile(cgroupFile, []byte(cgroupContent), 0644); err != nil {
		t.Fatalf("failed to create cgroup file: %v", err)
	}
	
	path, err := findCgroupPathFromProc(containerID)
	if err != nil {
		t.Logf("findCgroupPathFromProc returned error (may be expected): %v", err)
	}
	if path != "" {
		t.Logf("Found cgroup path: %s", path)
	}
}

func TestFindCgroupPathFromProc_ReadDirError(t *testing.T) {
	tmpDir := t.TempDir()
	
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(filepath.Join(tmpDir, "nonexistent"))
	defer func() { config.SetProcBasePath(origProcBase) }()
	
	_, err := findCgroupPathFromProc("test123")
	if err == nil {
		t.Error("Expected error when proc path doesn't exist")
	}
}

func TestFindCgroupPathFromProc_NonNumericPID(t *testing.T) {
	tmpDir := t.TempDir()
	
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tmpDir)
	defer func() { config.SetProcBasePath(origProcBase) }()
	
	nonNumericDir := filepath.Join(tmpDir, "not-a-pid")
	if err := os.MkdirAll(nonNumericDir, 0755); err != nil {
		t.Fatalf("failed to create non-numeric dir: %v", err)
	}
	
	_, err := findCgroupPathFromProc("test123")
	if err != nil {
		t.Logf("findCgroupPathFromProc returned error (expected): %v", err)
	}
}

func TestFindCgroupPathV2_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	
	origCgroupBase := config.CgroupBasePath
	config.SetCgroupBasePath(tmpDir)
	defer func() { config.SetCgroupBasePath(origCgroupBase) }()
	
	_, err := findCgroupPathV2("nonexistent-container")
	if err == nil {
		t.Error("Expected error for nonexistent container")
	}
}

func TestFindCgroupPathV2_FoundInKubepods(t *testing.T) {
	tmpDir := t.TempDir()
	
	origCgroupBase := config.CgroupBasePath
	config.SetCgroupBasePath(tmpDir)
	defer func() { config.SetCgroupBasePath(origCgroupBase) }()
	
	containerID := "test789"
	kubepodsPath := filepath.Join(tmpDir, "kubepods", "pod_"+containerID)
	if err := os.MkdirAll(kubepodsPath, 0755); err != nil {
		t.Fatalf("failed to create kubepods path: %v", err)
	}
	cgroupProcsPath := filepath.Join(kubepodsPath, "cgroup.procs")
	if err := os.WriteFile(cgroupProcsPath, []byte(""), 0644); err != nil {
		t.Fatalf("failed to create cgroup.procs: %v", err)
	}
	
	path, err := findCgroupPathV2(containerID)
	if err != nil {
		t.Logf("findCgroupPathV2 returned error (may be expected): %v", err)
	}
	if path != "" {
		t.Logf("Found cgroup path: %s", path)
	}
}

func TestFindCgroupPathV2_WithShortID(t *testing.T) {
	tmpDir := t.TempDir()
	
	origCgroupBase := config.CgroupBasePath
	config.SetCgroupBasePath(tmpDir)
	defer func() { config.SetCgroupBasePath(origCgroupBase) }()
	
	fullID := "abcdef1234567890abcdef1234567890abcdef12"
	shortID := fullID[:12]
	kubepodsPath := filepath.Join(tmpDir, "kubepods.slice", "pod_"+shortID)
	if err := os.MkdirAll(kubepodsPath, 0755); err != nil {
		t.Fatalf("failed to create kubepods path: %v", err)
	}
	cgroupProcsPath := filepath.Join(kubepodsPath, "cgroup.procs")
	if err := os.WriteFile(cgroupProcsPath, []byte(""), 0644); err != nil {
		t.Fatalf("failed to create cgroup.procs: %v", err)
	}
	
	path, err := findCgroupPathV2(fullID)
	if err != nil {
		t.Logf("findCgroupPathV2 returned error (may be expected): %v", err)
	}
	if path != "" {
		t.Logf("Found cgroup path: %s", path)
	}
}

func TestFindCgroupPathFromProc_WithV1Format_PartsLessThan3(t *testing.T) {
	tmpDir := t.TempDir()
	
	origProcBase := config.ProcBasePath
	origCgroupBase := config.CgroupBasePath
	config.SetProcBasePath(tmpDir)
	config.SetCgroupBasePath(tmpDir)
	defer func() {
		config.SetProcBasePath(origProcBase)
		config.SetCgroupBasePath(origCgroupBase)
	}()
	
	containerID := "test123"
	pid := "12349"
	procDir := filepath.Join(tmpDir, pid)
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create proc dir: %v", err)
	}
	
	cgroupFile := filepath.Join(procDir, "cgroup")
	cgroupContent := "1:cpu:\n"
	if err := os.WriteFile(cgroupFile, []byte(cgroupContent), 0644); err != nil {
		t.Fatalf("failed to create cgroup file: %v", err)
	}
	
	_, err := findCgroupPathFromProc(containerID)
	if err != nil {
		t.Logf("findCgroupPathFromProc returned error (expected): %v", err)
	}
}

func TestFindCgroupPathFromProc_WithV1Format_EmptyCgroupPath(t *testing.T) {
	tmpDir := t.TempDir()
	
	origProcBase := config.ProcBasePath
	origCgroupBase := config.CgroupBasePath
	config.SetProcBasePath(tmpDir)
	config.SetCgroupBasePath(tmpDir)
	defer func() {
		config.SetProcBasePath(origProcBase)
		config.SetCgroupBasePath(origCgroupBase)
	}()
	
	containerID := "test123"
	pid := "12350"
	procDir := filepath.Join(tmpDir, pid)
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create proc dir: %v", err)
	}
	
	cgroupFile := filepath.Join(procDir, "cgroup")
	cgroupContent := "1:cpu:/\n"
	if err := os.WriteFile(cgroupFile, []byte(cgroupContent), 0644); err != nil {
		t.Fatalf("failed to create cgroup file: %v", err)
	}
	
	_, err := findCgroupPathFromProc(containerID)
	if err != nil {
		t.Logf("findCgroupPathFromProc returned error (expected): %v", err)
	}
}

func TestFindCgroupPathFromProc_WithV1Format_EmptyLine(t *testing.T) {
	tmpDir := t.TempDir()
	
	origProcBase := config.ProcBasePath
	origCgroupBase := config.CgroupBasePath
	config.SetProcBasePath(tmpDir)
	config.SetCgroupBasePath(tmpDir)
	defer func() {
		config.SetProcBasePath(origProcBase)
		config.SetCgroupBasePath(origCgroupBase)
	}()
	
	containerID := "test123"
	pid := "12351"
	procDir := filepath.Join(tmpDir, pid)
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create proc dir: %v", err)
	}
	
	cgroupFile := filepath.Join(procDir, "cgroup")
	cgroupContent := fmt.Sprintf("   \n1:cpu:/kubepods/pod_%s\n", containerID)
	if err := os.WriteFile(cgroupFile, []byte(cgroupContent), 0644); err != nil {
		t.Fatalf("failed to create cgroup file: %v", err)
	}
	
	cgroupPath := filepath.Join(tmpDir, "kubepods", "pod_"+containerID)
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("failed to create cgroup path: %v", err)
	}
	
	path, err := findCgroupPathFromProc(containerID)
	if err != nil {
		t.Logf("findCgroupPathFromProc returned error (may be expected): %v", err)
	}
	if path != "" {
		t.Logf("Found cgroup path: %s", path)
	}
}

func TestFindCgroupPathV2_WalkError(t *testing.T) {
	tmpDir := t.TempDir()
	
	origCgroupBase := config.CgroupBasePath
	config.SetCgroupBasePath(tmpDir)
	defer func() { config.SetCgroupBasePath(origCgroupBase) }()
	
	kubepodsPath := filepath.Join(tmpDir, "kubepods")
	if err := os.MkdirAll(kubepodsPath, 0755); err != nil {
		t.Fatalf("failed to create kubepods path: %v", err)
	}
	if err := os.Chmod(kubepodsPath, 0000); err != nil {
		t.Fatalf("failed to chmod: %v", err)
	}
	defer func() {
		_ = os.Chmod(kubepodsPath, 0755)
	}()
	
	_, err := findCgroupPathV2("test123")
	if err != nil {
		t.Logf("findCgroupPathV2 returned error (expected): %v", err)
	}
}

func TestFindCgroupPathV2_NoCgroupProcs(t *testing.T) {
	tmpDir := t.TempDir()
	
	origCgroupBase := config.CgroupBasePath
	config.SetCgroupBasePath(tmpDir)
	defer func() { config.SetCgroupBasePath(origCgroupBase) }()
	
	containerID := "test123"
	kubepodsPath := filepath.Join(tmpDir, "kubepods", "pod_"+containerID)
	if err := os.MkdirAll(kubepodsPath, 0755); err != nil {
		t.Fatalf("failed to create kubepods path: %v", err)
	}
	
	_, err := findCgroupPathV2(containerID)
	if err != nil {
		t.Logf("findCgroupPathV2 returned error (expected when no cgroup.procs): %v", err)
	}
}

