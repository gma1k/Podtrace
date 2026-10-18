package kubernetes

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/cri"
	"github.com/gma1k/podtrace/internal/logger"
	"github.com/gma1k/podtrace/internal/procfs"
	"github.com/gma1k/podtrace/internal/sysfs"
	"github.com/gma1k/podtrace/internal/validation"
	"go.uber.org/zap"
)

// kubeletCgroupParent caches the value of kubelet's --cgroup-root or
// --cgroup-parent flag, detected once from /proc/<kubelet-pid>/cmdline.
var (
	kubeletCgroupParent     string
	kubeletCgroupParentOnce sync.Once
)

type PodResolver struct {
	clientset  kubernetes.Interface
	restConfig *rest.Config
	inCluster  bool
}

var _ PodResolverInterface = (*PodResolver)(nil)

func (r *PodResolver) GetClientset() kubernetes.Interface {
	return r.clientset
}

// GetRestConfig exposes the underlying client-go rest.Config so callers (like
// nodespawn) can build SPDY executors against the same cluster.
func (r *PodResolver) GetRestConfig() *rest.Config {
	return r.restConfig
}

func NamespaceFromContext() (string, bool) {
	return ClusterAccess{}.Namespace()
}

// NamespaceFromKubeconfig resolves the current context's namespace from an
// explicit kubeconfig path, falling back to the default loading rules when
// the path is empty. Callers that build their client from a --kubeconfig
// flag must resolve the namespace from the SAME file, or the namespace and
// the cluster can come from two different kubeconfigs.
func NamespaceFromKubeconfig(path string) (string, bool) {
	return ClusterAccess{Kubeconfig: path}.Namespace()
}

func NewPodResolver() (*PodResolver, error) {
	return NewPodResolverFor(ClusterAccess{})
}

// NewPodResolverFor builds a resolver against the cluster access names.
func NewPodResolverFor(access ClusterAccess) (*PodResolver, error) {
	config, inCluster, err := access.RESTConfig()
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, NewClientsetError(err)
	}

	return &PodResolver{clientset: clientset, restConfig: config, inCluster: inCluster}, nil
}

// InCluster reports whether the resolver uses the in-cluster ServiceAccount,
// meaning the process runs inside the cluster with no kubeconfig of its own.
func (r *PodResolver) InCluster() bool {
	return r.inCluster
}

func (r *PodResolver) ResolvePod(ctx context.Context, podName, namespace, containerName string) (*PodInfo, error) {
	pod, err := r.clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return nil, NewPodNotFoundError(podName, namespace, err)
	}

	if len(pod.Status.ContainerStatuses) == 0 {
		return nil, NewNoContainersError()
	}

	statuses := pickContainers(pod, containerName)
	if len(statuses) == 0 {
		name := containerName
		if name == "" && len(pod.Spec.Containers) > 0 {
			name = pod.Spec.Containers[0].Name
		}
		return nil, NewContainerNotFoundError(name)
	}

	targets := resolveContainerTargets(ctx, pod, statuses)
	if len(targets) == 0 {
		shortID, err := shortContainerID(statuses[0].ContainerID)
		if err != nil {
			return nil, err
		}
		return nil, NewCgroupNotFoundError(shortID)
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
		Containers:    targets,
		ContainerID:   targets[0].ID,
		CgroupPath:    targets[0].CgroupPath,
		ContainerName: targets[0].Name,
		Labels:        labels,
		PodIP:         pod.Status.PodIP,
		OwnerKind:     ownerKind,
		OwnerName:     ownerName,
	}, nil
}

// resolveContainerTargets turns picked container statuses into ContainerTargets
// with resolved cgroup paths. Containers whose ID or cgroup cannot be resolved
// are skipped with a warning; the caller decides whether an empty result is
// fatal.
func resolveContainerTargets(ctx context.Context, pod *corev1.Pod, statuses []corev1.ContainerStatus) []ContainerTarget {
	targets := make([]ContainerTarget, 0, len(statuses))
	for _, cs := range statuses {
		shortID, err := shortContainerID(cs.ContainerID)
		if err != nil {
			logger.Warn("Skipping container with unusable container ID",
				zap.String("pod", pod.Namespace+"/"+pod.Name),
				zap.String("container", cs.Name),
				zap.Error(err))
			continue
		}
		cgroupPath, err := resolveContainerCgroup(ctx, shortID)
		if err != nil {
			logger.Warn("Skipping container whose cgroup could not be resolved",
				zap.String("pod", pod.Namespace+"/"+pod.Name),
				zap.String("container", cs.Name),
				zap.String("container_id", shortID),
				zap.Error(err))
			continue
		}
		targets = append(targets, ContainerTarget{Name: cs.Name, ID: shortID, CgroupPath: cgroupPath})
	}
	return targets
}

// shortContainerID strips the runtime scheme from a status ContainerID and
// validates the remainder.
func shortContainerID(containerID string) (string, error) {
	parts := strings.Split(containerID, "://")
	if len(parts) != 2 {
		return "", NewInvalidContainerIDError("invalid container ID format")
	}
	shortID := parts[1]
	if !validation.ValidateContainerID(shortID) {
		return "", NewInvalidContainerIDError("validation failed")
	}
	return shortID, nil
}

// resolveContainerCgroup resolves one container's cgroup path via the
// CRI -> filesystem-scan -> /proc fallback chain.
func resolveContainerCgroup(ctx context.Context, shortID string) (string, error) {
	cgroupPath, err := resolveCgroupPathCRI(ctx, shortID)
	if err == nil && cgroupPath != "" {
		logger.Debug("Found cgroup path via CRI", zap.String("cgroup_path", cgroupPath))
		return cgroupPath, nil
	}
	logger.Debug("CRI cgroup resolution failed, trying filesystem scan", zap.Error(err), zap.String("container_id", shortID))
	cgroupPath, err = findCgroupPath(shortID)
	if err == nil && cgroupPath != "" {
		logger.Debug("Found cgroup path via filesystem scan", zap.String("cgroup_path", cgroupPath))
		return cgroupPath, nil
	}
	logger.Debug("Filesystem cgroup scan failed, trying /proc fallback", zap.Error(err), zap.String("container_id", shortID))
	cgroupPath, err = findCgroupPathFromProc(shortID)
	if err == nil && cgroupPath != "" {
		logger.Debug("Found cgroup path via /proc fallback", zap.String("cgroup_path", cgroupPath))
		return cgroupPath, nil
	}
	return "", NewCgroupNotFoundError(shortID)
}

// cgroupRootCandidates returns base paths to search when resolving cgroup paths.
// It covers:
//   - The configured cgroup base (default /sys/fs/cgroup)
//   - The systemd sub-hierarchy (cgroup v1 with systemd driver)
//   - A custom cgroup-root/cgroup-parent set via kubelet flags (GKE, AKS, EKS)
func cgroupRootCandidates() []string {
	base := config.CgroupBasePath
	seen := map[string]bool{base: true}
	candidates := []string{base}

	if systemdRoot := filepath.Join(base, "systemd"); dirExists(systemdRoot) {
		if !seen[systemdRoot] {
			seen[systemdRoot] = true
			candidates = append(candidates, systemdRoot)
		}
	}

	if kcp := detectKubeletCgroupParent(); kcp != "" {
		// kcp may be a relative path like "kubepods" or absolute.
		var full string
		if filepath.IsAbs(kcp) {
			full = kcp
		} else {
			full = filepath.Join(base, kcp)
		}
		if _, ok := sysfs.CgroupRelative(full); ok && dirExists(full) && !seen[full] {
			seen[full] = true
			candidates = append(candidates, full)
		}
	}

	return candidates
}

// detectKubeletCgroupParent finds the value of --cgroup-root or --cgroup-parent
// from the running kubelet process's command line. The result is cached.
func detectKubeletCgroupParent() string {
	kubeletCgroupParentOnce.Do(func() {
		kubeletCgroupParent = readKubeletCgroupFlag()
	})
	return kubeletCgroupParent
}

// readKubeletCgroupFlag reads /proc and finds the kubelet cmdline.
func readKubeletCgroupFlag() string {
	procPath := config.ProcBasePath
	entries, err := os.ReadDir(procPath)
	if err != nil {
		return ""
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid := entry.Name()
		if pid == "" || pid[0] < '1' || pid[0] > '9' {
			continue
		}

		comm, err := procfs.ReadFile(pid + "/comm")
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(comm)) != "kubelet" {
			continue
		}

		data, err := procfs.ReadFile(pid + "/cmdline")
		if err != nil {
			continue
		}

		args := strings.Split(string(data), "\x00")
		for i, arg := range args {
			for _, flag := range []string{"--cgroup-root", "--cgroup-parent"} {
				if arg == flag && i+1 < len(args) {
					v := strings.TrimSpace(args[i+1])
					if validCgroupFlagValue(v) {
						logger.Debug("Detected kubelet cgroup flag",
							zap.String("flag", flag), zap.String("value", v))
						return v
					}
				}
				if strings.HasPrefix(arg, flag+"=") {
					v := strings.TrimSpace(strings.TrimPrefix(arg, flag+"="))
					if validCgroupFlagValue(v) {
						logger.Debug("Detected kubelet cgroup flag",
							zap.String("flag", flag), zap.String("value", v))
						return v
					}
				}
			}
		}
	}
	return ""
}

// validCgroupFlagValue rejects a kubelet cgroup flag value that would escape
// the cgroup base — any ".." traversal or an absolute path outside the base.
func validCgroupFlagValue(v string) bool {
	if v == "" || strings.Contains(v, "..") {
		return false
	}
	if filepath.IsAbs(v) {
		_, ok := sysfs.CgroupRelative(v)
		return ok
	}
	return true
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// statCgroupDir returns true when path resolves to anything (file or
// dir) under the configured cgroup base.
func statCgroupDir(path string) bool {
	rel, ok := sysfs.CgroupRelative(path)
	if !ok {
		return false
	}
	_, err := sysfs.CgroupStat(rel)
	return err == nil
}

// statCgroupDirHasProcs is statCgroupDir plus a check that
// "<dir>/cgroup.procs" exists — used to confirm the directory is the
// terminal cgroup leaf rather than an intermediate slice.
func statCgroupDirHasProcs(path string) bool {
	rel, ok := sysfs.CgroupRelative(path)
	if !ok {
		return false
	}
	if _, err := sysfs.CgroupStat(rel); err != nil {
		return false
	}
	_, err := sysfs.CgroupStat(filepath.Join(rel, "cgroup.procs"))
	return err == nil
}

func resolveCgroupPathCRI(ctx context.Context, containerID string) (string, error) {
	if !config.CRIResolveEnabled() {
		return "", errors.New("podtrace: CRI resolution disabled")
	}
	r, err := cri.NewResolver()
	if err != nil {
		return "", err
	}
	defer func() { _ = r.Close() }()

	info, err := r.ResolveContainer(ctx, containerID)
	if err != nil {
		return "", err
	}
	if info == nil || info.CgroupsPath == "" {
		return "", errors.New("podtrace: CRI returned no cgroups path")
	}

	cg := info.CgroupsPath
	roots := cgroupRootCandidates()

	if strings.HasPrefix(cg, "/") {
		if statCgroupDirHasProcs(cg) {
			if cg != config.CgroupBasePath {
				return cg, nil
			}
		}
		for _, root := range roots {
			if strings.HasPrefix(cg, root+"/") {
				cg = strings.TrimPrefix(cg, root)
				break
			}
		}
	}

	if !strings.HasPrefix(cg, "/") {
		cg = "/" + cg
	}
	if cg == "/" {
		return "", errors.New("podtrace: CRI returned root cgroups path")
	}
	trimmed := strings.TrimPrefix(cg, "/")

	// Direct lookup: <root>/<trimmed>
	for _, root := range roots {
		fullPath := filepath.Join(root, trimmed)
		if fullPath == root {
			continue
		}
		if statCgroupDirHasProcs(fullPath) {
			return fullPath, nil
		}
	}

	for _, parent := range []string{"kubepods.slice", "kubepods"} {
		for _, root := range roots {
			fullPath := filepath.Join(root, parent, trimmed)
			if _, err := os.Stat(fullPath); err == nil {
				return fullPath, nil
			}
		}
	}

	return "", errors.New("podtrace: CRI cgroup path not found on filesystem")
}

// pickContainers selects the containers to trace: every running container
// with a container ID, regular, restartable-init (sidecar), and ephemeral,
// matching the agent's containerStatusIndex enumeration so both planes agree,
// when no name is given, or exactly the named one.
func pickContainers(pod *corev1.Pod, containerName string) []corev1.ContainerStatus {
	var out []corev1.ContainerStatus
	add := func(list []corev1.ContainerStatus) {
		for i := range list {
			cs := list[i]
			if cs.ContainerID == "" || cs.State.Running == nil {
				continue
			}
			if containerName != "" && cs.Name != containerName {
				continue
			}
			out = append(out, cs)
		}
	}
	add(pod.Status.ContainerStatuses)
	add(pod.Status.InitContainerStatuses)
	add(pod.Status.EphemeralContainerStatuses)
	return out
}

// ContainerTarget identifies one traced container of a resolved pod.
type ContainerTarget struct {
	Name       string
	ID         string
	CgroupPath string
}

type PodInfo struct {
	PodName       string
	Namespace     string
	Containers    []ContainerTarget
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

const maxCgroupWalkDepth = 8

// isConmonCgroup reports whether a cgroup directory belongs to CRI-O's
// conmon monitor rather than to the container.
func isConmonCgroup(name string) bool {
	return strings.HasPrefix(name, "crio-conmon-") || strings.HasPrefix(name, "conmon-")
}

// cgroupLineNamesContainer reports whether a /proc/<pid>/cgroup path is the
// container's own cgroup: it carries the ID and is not conmon's.
func cgroupLineNamesContainer(cgroupPath, containerID, shortID string) bool {
	if !strings.Contains(cgroupPath, containerID) && !strings.Contains(cgroupPath, shortID) {
		return false
	}
	return !isConmonCgroup(filepath.Base(cgroupPath))
}

// walkCgroupForContainer scans basePath for containerID's cgroup directory.
func walkCgroupForContainer(basePath, containerID, shortID string) (string, bool) {
	base := filepath.Clean(basePath)
	found := ""
	_ = filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		name := filepath.Base(path)
		if isConmonCgroup(name) {
			return filepath.SkipDir
		}
		if strings.Contains(path, containerID) || strings.Contains(path, shortID) {
			if _, err := os.Stat(filepath.Join(path, "cgroup.procs")); err == nil {
				found = path
				return filepath.SkipAll
			}
		}
		if path != base {
			if rel, rerr := filepath.Rel(base, path); rerr == nil &&
				strings.Count(rel, string(os.PathSeparator))+1 >= maxCgroupWalkDepth {
				return filepath.SkipDir
			}
		}
		return nil
	})
	return found, found != ""
}

func findCgroupPathV2(containerID string) (string, error) {
	roots := cgroupRootCandidates()
	var basePaths []string
	for _, root := range roots {
		basePaths = append(basePaths,
			filepath.Join(root, "kubepods"),
			filepath.Join(root, "kubepods.slice"),
			filepath.Join(root, "kubepods-burstable"),
			filepath.Join(root, "kubepods-burstable.slice"),
			filepath.Join(root, "kubepods-besteffort"),
			filepath.Join(root, "kubepods-besteffort.slice"),
			filepath.Join(root, "system"),
			filepath.Join(root, "system.slice"),
			filepath.Join(root, "user"),
			filepath.Join(root, "user.slice"),
		)
	}
	basePaths = append(basePaths, roots...)

	shortID := containerID
	if len(containerID) >= 12 {
		shortID = containerID[:12]
	}

	for _, basePath := range basePaths {
		if _, err := os.Stat(basePath); os.IsNotExist(err) {
			continue
		}
		if p, ok := walkCgroupForContainer(basePath, containerID, shortID); ok {
			return p, nil
		}
	}

	return "", NewCgroupNotFoundError(containerID)
}

func findCgroupPathV1(containerID string) (string, error) {
	var paths []string
	for _, root := range cgroupRootCandidates() {
		paths = append(paths,
			filepath.Join(root, "kubepods.slice"),
			filepath.Join(root, "system.slice"),
			filepath.Join(root, "user.slice"),
			filepath.Join(root, "kubepods"),
		)
	}
	for _, controllerRoot := range cgroupV1ControllerRoots() {
		paths = append(paths,
			filepath.Join(controllerRoot, "kubepods"),
			filepath.Join(controllerRoot, "kubepods.slice"),
		)
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
			if !info.IsDir() {
				return nil
			}
			if isConmonCgroup(filepath.Base(path)) {
				return filepath.SkipDir
			}
			if strings.Contains(path, containerID) || strings.Contains(path, shortID) {
				if _, err := os.Stat(filepath.Join(path, "cgroup.procs")); err == nil {
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

// cgroupV1ControllerRoots lists the first-level controller hierarchies
// mounted under the cgroup base.
func cgroupV1ControllerRoots() []string {
	if v2, _ := isCgroupV2(config.CgroupBasePath); v2 {
		return nil
	}
	entries, err := os.ReadDir(config.CgroupBasePath)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		out = append(out, filepath.Join(config.CgroupBasePath, e.Name()))
	}
	return out
}

// cgroupV1Controllers parses the controller field of a /proc/<pid>/cgroup
// v1 line ("cpu,cpuacct", "name=systemd") into mount directory names.
func cgroupV1Controllers(field string) []string {
	var out []string
	for _, c := range strings.Split(field, ",") {
		c = strings.TrimSpace(strings.TrimPrefix(c, "name="))
		if c != "" {
			out = append(out, c)
		}
	}
	return out
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

		data, err := procfs.ReadFile(pidStr + "/cgroup")
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
				if cgroupLineNamesContainer(cgroupPath, containerID, shortID) {
					for _, root := range cgroupRootCandidates() {
						fullPath := filepath.Join(root, strings.TrimPrefix(cgroupPath, "/"))
						if statCgroupDirHasProcs(fullPath) {
							foundPath = fullPath
							break
						}
					}
				}
			} else {
				parts := strings.SplitN(line, ":", 3)
				if len(parts) == 3 {
					cgroupPath := parts[2]
					if cgroupLineNamesContainer(cgroupPath, containerID, shortID) {
						trimmed := strings.TrimPrefix(cgroupPath, "/")
						for _, ctrl := range cgroupV1Controllers(parts[1]) {
							fullPath := filepath.Join(config.CgroupBasePath, ctrl, trimmed)
							if statCgroupDir(fullPath) {
								foundPath = fullPath
								break
							}
						}
						if foundPath == "" {
							for _, root := range cgroupRootCandidates() {
								fullPath := filepath.Join(root, trimmed)
								if statCgroupDir(fullPath) {
									foundPath = fullPath
									break
								}
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
			break
		}
	}

	if foundPath != "" {
		return foundPath, nil
	}

	return "", NewCgroupNotFoundError(containerID)
}
