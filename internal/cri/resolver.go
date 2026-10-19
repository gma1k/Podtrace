package cri

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"

	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"

	"github.com/gma1k/podtrace/internal/safeconv"
)

type ContainerInfo struct {
	PID         uint32
	CgroupsPath string
	Endpoint    string
}

type Resolver struct {
	endpoint string
	conn     *grpc.ClientConn
	client   runtimeapi.RuntimeServiceClient
}

func (r *Resolver) Endpoint() string {
	if r == nil {
		return ""
	}
	return r.endpoint
}

// DefaultCandidateEndpoints lists the CRI gRPC sockets probed when no
// endpoint is configured, most common first.
func DefaultCandidateEndpoints() []string {
	endpoints := []string{
		// Standard containerd (Debian, Ubuntu, GKE, AKS, EKS AL2023, Talos, Kind)
		"unix:///run/containerd/containerd.sock",
		"unix:///var/run/containerd/containerd.sock",
		// CRI-O (OpenShift, Fedora, RHEL)
		"unix:///run/crio/crio.sock",
		"unix:///var/run/crio/crio.sock",
		// k3s / RKE2 (Rancher)
		"unix:///run/k3s/containerd/containerd.sock",
		"unix:///var/run/k3s/containerd/containerd.sock",
		// MicroK8s
		"unix:///var/snap/microk8s/common/run/containerd.sock",
		// cri-dockerd (Docker Engine behind a CRI shim, e.g. Minikube docker runtime)
		"unix:///run/cri-dockerd.sock",
		"unix:///var/run/cri-dockerd.sock",
		// Legacy dockershim CRI socket; Bottlerocket links it to containerd
		"unix:///run/dockershim.sock",
		"unix:///var/run/dockershim.sock",
	}

	if os.Getenv("PODTRACE_CRI_ALLOW_PODMAN") == "1" {
		endpoints = append(endpoints,
			"unix:///run/podman/podman.sock",
			"unix:///var/run/podman/podman.sock",
		)
	}
	return endpoints
}

// existingEndpoints returns the candidates whose socket path exists, in
// order, collapsing aliases of the same file (/run vs /var/run).
func existingEndpoints(candidates []string) []string {
	var out []string
	var seen []os.FileInfo
	for _, ep := range candidates {
		path := strings.TrimPrefix(ep, "unix://")
		if path == "" {
			continue
		}
		fi, err := os.Stat(path)
		if err != nil {
			continue
		}
		dup := false
		for _, prev := range seen {
			if os.SameFile(prev, fi) {
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		seen = append(seen, fi)
		out = append(out, ep)
	}
	return out
}

var criDialTimeout = 2 * time.Second

func NewResolver() (*Resolver, error) {
	return NewResolverWithEndpoint(os.Getenv("PODTRACE_CRI_ENDPOINT"))
}

// NewResolverWithEndpoint connects to endpoint, or, when it is empty, to the
// first discovered candidate that answers the CRI Version RPC.
func NewResolverWithEndpoint(endpoint string) (*Resolver, error) {
	if endpoint != "" {
		return dialResolver(endpoint, false)
	}
	return newResolverFromCandidates(DefaultCandidateEndpoints())
}

func newResolverFromCandidates(candidates []string) (*Resolver, error) {
	existing := existingEndpoints(candidates)
	if len(existing) == 0 {
		return nil, errors.New("podtrace: CRI endpoint not found (set PODTRACE_CRI_ENDPOINT)")
	}
	var errs []error
	for _, ep := range existing {
		r, err := dialResolver(ep, true)
		if err == nil {
			return r, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

// dialResolver connects to one endpoint. With verify set it also requires the
// endpoint to answer the CRI Version RPC, so a socket that accepts
// connections but is not a CRI runtime is rejected.
func dialResolver(endpoint string, verify bool) (*Resolver, error) {
	dialCtx, cancel := context.WithTimeout(context.Background(), criDialTimeout)
	defer cancel()

	conn, err := grpc.NewClient(
		normalizeUnixTarget(endpoint),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("podtrace: failed to connect to CRI endpoint %q: %w", endpoint, err)
	}

	conn.Connect()
	if err := waitForReady(dialCtx, conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("podtrace: failed to connect to CRI endpoint %q: %w", endpoint, err)
	}

	client := runtimeapi.NewRuntimeServiceClient(conn)
	if verify {
		if _, err := client.Version(dialCtx, &runtimeapi.VersionRequest{}); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("podtrace: endpoint %q is not a CRI runtime service: %w", endpoint, err)
		}
	}

	return &Resolver{
		endpoint: endpoint,
		conn:     conn,
		client:   client,
	}, nil
}

func waitForReady(ctx context.Context, conn *grpc.ClientConn) error {
	if conn == nil {
		return errors.New("nil grpc conn")
	}
	for {
		state := conn.GetState()
		if state == connectivity.Ready {
			return nil
		}
		if state == connectivity.Shutdown {
			return errors.New("grpc connection shutdown")
		}
		if !conn.WaitForStateChange(ctx, state) {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return errors.New("grpc connection not ready")
		}
	}
}

func normalizeUnixTarget(endpoint string) string {
	if strings.HasPrefix(endpoint, "unix://") {
		return endpoint
	}
	if strings.HasPrefix(endpoint, "/") {
		return "unix://" + endpoint
	}
	return endpoint
}

func (r *Resolver) Close() error {
	if r == nil || r.conn == nil {
		return nil
	}
	return r.conn.Close()
}

func (r *Resolver) ResolveContainer(ctx context.Context, containerID string) (*ContainerInfo, error) {
	if r == nil || r.client == nil {
		return nil, errors.New("podtrace: CRI resolver not initialized")
	}
	if containerID == "" {
		return nil, errors.New("podtrace: empty container id")
	}

	req := &runtimeapi.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     true,
	}
	resp, err := r.client.ContainerStatus(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("podtrace: CRI ContainerStatus failed: %w", err)
	}

	info := &ContainerInfo{Endpoint: r.endpoint}

	// cgroupFieldPaths is the ordered list of dot-separated JSON paths searched
	// for the container's cgroup path in CRI info responses.
	// Extend at runtime via PODTRACE_CRI_CGROUP_FIELDS (comma-separated paths).
	cgroupFieldPaths := []string{
		// containerd standard fields
		"cgroupsPath",
		"cgroups_path",
		"cgroupPath",
		"cgroup_path",
		// containerd runtime spec (nested object)
		"runtimeSpec.linux.cgroupsPath",
		"runtime_spec.linux.cgroupsPath",
		// CRI-O: may nest under "info" or "status"
		"info.cgroupsPath",
		"info.cgroupPath",
		"status.cgroupsPath",
		// cgroup v1 multi-hierarchy
		"cgroup_paths.cgroupfs",
		"cgroup_paths.systemd",
	}
	if extra := os.Getenv("PODTRACE_CRI_CGROUP_FIELDS"); extra != "" {
		for _, f := range strings.Split(extra, ",") {
			if f = strings.TrimSpace(f); f != "" {
				cgroupFieldPaths = append(cgroupFieldPaths, f)
			}
		}
	}

	pidFieldPaths := []string{"pid", "Pid", "processPid", "process_pid"}

	for _, v := range resp.Info {
		if v == "" {
			continue
		}
		// tryParseJSON handles direct JSON objects and double-encoded JSON strings
		// (some runtimes encode the info value as a JSON string within the map).
		obj := tryParseJSON(v)
		if obj == nil {
			continue
		}

		if info.PID == 0 {
			if pid, ok := findJSONInt(obj, pidFieldPaths); ok && pid > 0 {
				info.PID = safeconv.Int64ToUint32(pid)
			}
		}
		if info.CgroupsPath == "" {
			if cg, ok := findJSONString(obj, cgroupFieldPaths); ok && cg != "" {
				info.CgroupsPath = cg
			}
		}
	}

	if info.CgroupsPath == "" {
		for _, v := range resp.Info {
			if strings.Contains(v, "cgroupsPath") || strings.Contains(v, "cgroup") {
				if cg := extractLooseCgroupsPath(v); cg != "" {
					info.CgroupsPath = cg
					break
				}
			}
		}
	}

	if info.CgroupsPath != "" {
		info.CgroupsPath = expandSystemdColonPath(info.CgroupsPath)
	}
	if info.CgroupsPath != "" && !strings.HasPrefix(info.CgroupsPath, "/") {
		info.CgroupsPath = "/" + info.CgroupsPath
	}

	return info, nil
}

// expandSystemdColonPath converts the systemd-driver colon form the CRI
// reports ("kubepods-burstable-pod<uid>.slice:cri-containerd:<id>") into
// the real filesystem layout
// ("kubepods.slice/kubepods-burstable.slice/.../cri-containerd-<id>.scope").
func expandSystemdColonPath(cg string) string {
	parts := strings.Split(cg, ":")
	if len(parts) != 3 {
		return cg
	}
	slice, runtimePrefix, id := strings.TrimPrefix(parts[0], "/"), parts[1], parts[2]
	if !strings.HasSuffix(slice, ".slice") || runtimePrefix == "" || id == "" {
		return cg
	}
	return expandSystemdSlice(slice) + "/" + runtimePrefix + "-" + id + ".scope"
}

// expandSystemdSlice unfolds a systemd slice name into its nested
// directory path: "a-b-c.slice" → "a.slice/a-b.slice/a-b-c.slice".
func expandSystemdSlice(slice string) string {
	name := strings.TrimSuffix(slice, ".slice")
	segments := strings.Split(name, "-")
	parts := make([]string, 0, len(segments))
	for i := range segments {
		parts = append(parts, strings.Join(segments[:i+1], "-")+".slice")
	}
	return strings.Join(parts, "/")
}

func extractLooseCgroupsPath(s string) string {
	const key = `"cgroupsPath":"`
	idx := strings.Index(s, key)
	if idx < 0 {
		return ""
	}
	rest := s[idx+len(key):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	val := rest[:end]
	var decoded string
	if err := json.Unmarshal([]byte(`"`+val+`"`), &decoded); err == nil && decoded != "" {
		val = decoded
	}
	val = strings.ReplaceAll(val, `\/`, `/`)
	val = filepath.Clean(val)
	if val == "." {
		return ""
	}
	return val
}
