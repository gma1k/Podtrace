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

func DefaultCandidateEndpoints() []string {
	allowPodman := os.Getenv("PODTRACE_CRI_ALLOW_PODMAN") == "1"
	endpoints := []string{
		"unix:///run/containerd/containerd.sock",
		"unix:///var/run/containerd/containerd.sock",
		"unix:///run/crio/crio.sock",
		"unix:///var/run/crio/crio.sock",
		"unix:///run/k3s/containerd/containerd.sock",
	}
	if allowPodman {
		endpoints = append(endpoints,
			"unix:///run/podman/podman.sock",
			"unix:///var/run/podman/podman.sock",
		)
	}
	return endpoints
}

func pickExistingEndpoint(candidates []string) string {
	for _, ep := range candidates {
		path := strings.TrimPrefix(ep, "unix://")
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			return ep
		}
	}
	return ""
}

func NewResolver() (*Resolver, error) {
	return NewResolverWithEndpoint(os.Getenv("PODTRACE_CRI_ENDPOINT"))
}

func NewResolverWithEndpoint(endpoint string) (*Resolver, error) {
	if endpoint == "" {
		endpoint = pickExistingEndpoint(DefaultCandidateEndpoints())
	}
	if endpoint == "" {
		return nil, errors.New("podtrace: CRI endpoint not found (set PODTRACE_CRI_ENDPOINT)")
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
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

	return &Resolver{
		endpoint: endpoint,
		conn:     conn,
		client:   runtimeapi.NewRuntimeServiceClient(conn),
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

	for _, v := range resp.Info {
		if v == "" {
			continue
		}
		var obj any
		if json.Unmarshal([]byte(v), &obj) == nil {
			if info.PID == 0 {
				if pid, ok := findJSONInt(obj, []string{"pid", "Pid", "processPid", "process_pid"}); ok && pid > 0 {
					info.PID = uint32(pid)
				}
			}
			if info.CgroupsPath == "" {
				if cg, ok := findJSONString(obj, []string{
					"cgroupsPath", "cgroups_path", "cgroupPath", "cgroup_path",
					"runtimeSpec.linux.cgroupsPath",
					"runtime_spec.linux.cgroupsPath",
					"info.cgroupsPath",
					"info.cgroupPath",
					"cgroup_paths.cgroupfs",
					"cgroup_paths.systemd",
				}); ok && cg != "" {
					info.CgroupsPath = cg
				}
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

	if info.CgroupsPath != "" && !strings.HasPrefix(info.CgroupsPath, "/") {
		info.CgroupsPath = "/" + info.CgroupsPath
	}

	return info, nil
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
