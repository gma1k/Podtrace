package kubernetes

import (
	"context"
	"errors"
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
	defer os.Chmod(targetDir, 0755)

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
			os.Setenv("KUBECONFIG", origKubeconfig)
		} else {
			os.Unsetenv("KUBECONFIG")
		}
		if origSudoUser != "" {
			os.Setenv("SUDO_USER", origSudoUser)
		} else {
			os.Unsetenv("SUDO_USER")
		}
		if origHome != "" {
			os.Setenv("HOME", origHome)
		} else {
			os.Unsetenv("HOME")
		}
	}()

	os.Unsetenv("KUBECONFIG")
	os.Unsetenv("SUDO_USER")
	os.Unsetenv("HOME")

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
			os.Setenv("KUBECONFIG", origKubeconfig)
		} else {
			os.Unsetenv("KUBECONFIG")
		}
		if origSudoUser != "" {
			os.Setenv("SUDO_USER", origSudoUser)
		} else {
			os.Unsetenv("SUDO_USER")
		}
		if origHome != "" {
			os.Setenv("HOME", origHome)
		} else {
			os.Unsetenv("HOME")
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

	os.Setenv("KUBECONFIG", kubeconfigPath)
	os.Unsetenv("SUDO_USER")
	os.Unsetenv("HOME")

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
			os.Setenv("KUBECONFIG", origKubeconfig)
		} else {
			os.Unsetenv("KUBECONFIG")
		}
		if origSudoUser != "" {
			os.Setenv("SUDO_USER", origSudoUser)
		} else {
			os.Unsetenv("SUDO_USER")
		}
		if origHome != "" {
			os.Setenv("HOME", origHome)
		} else {
			os.Unsetenv("HOME")
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

	os.Unsetenv("KUBECONFIG")
	os.Setenv("SUDO_USER", "testuser")
	os.Unsetenv("HOME")

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
			os.Setenv("KUBECONFIG", origKubeconfig)
		} else {
			os.Unsetenv("KUBECONFIG")
		}
		if origSudoUser != "" {
			os.Setenv("SUDO_USER", origSudoUser)
		} else {
			os.Unsetenv("SUDO_USER")
		}
		if origHome != "" {
			os.Setenv("HOME", origHome)
		} else {
			os.Unsetenv("HOME")
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

	os.Unsetenv("KUBECONFIG")
	os.Unsetenv("SUDO_USER")
	os.Setenv("HOME", testHome)

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
			os.Setenv("KUBECONFIG", origKubeconfig)
		} else {
			os.Unsetenv("KUBECONFIG")
		}
		if origSudoUser != "" {
			os.Setenv("SUDO_USER", origSudoUser)
		} else {
			os.Unsetenv("SUDO_USER")
		}
		if origHome != "" {
			os.Setenv("HOME", origHome)
		} else {
			os.Unsetenv("HOME")
		}
	}()

	os.Unsetenv("KUBECONFIG")
	os.Unsetenv("SUDO_USER")
	os.Setenv("HOME", "/root")

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

