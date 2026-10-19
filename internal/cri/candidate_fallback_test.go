package cri

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

type versionedRuntimeServer struct {
	runtimeapi.UnimplementedRuntimeServiceServer
}

func (versionedRuntimeServer) Version(context.Context, *runtimeapi.VersionRequest) (*runtimeapi.VersionResponse, error) {
	return &runtimeapi.VersionResponse{RuntimeName: "fake"}, nil
}

func firstOf(eps []string) string {
	if len(eps) == 0 {
		return ""
	}
	return eps[0]
}

func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cri")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func serveUnix(t *testing.T, path string, register func(*grpc.Server)) {
	t.Helper()
	lis, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	if register != nil {
		register(srv)
	}
	go srv.Serve(lis) //nolint:errcheck
	t.Cleanup(srv.Stop)
}

func TestDefaultCandidateEndpointsExcludeDockerEngineSocket(t *testing.T) {
	for _, ep := range DefaultCandidateEndpoints() {
		if strings.HasSuffix(ep, "/docker.sock") {
			t.Errorf("Docker Engine API socket %q is not a CRI endpoint", ep)
		}
	}
}

func TestDefaultCandidateEndpointsPreferRealRuntimesOverShims(t *testing.T) {
	eps := DefaultCandidateEndpoints()
	containerd := slices.Index(eps, "unix:///run/containerd/containerd.sock")
	crio := slices.Index(eps, "unix:///run/crio/crio.sock")
	criDockerd := slices.Index(eps, "unix:///run/cri-dockerd.sock")
	dockershim := slices.Index(eps, "unix:///run/dockershim.sock")
	if containerd < 0 || crio < 0 || criDockerd < 0 || dockershim < 0 {
		t.Fatalf("missing expected candidates in %v", eps)
	}
	if containerd > criDockerd || crio > criDockerd || criDockerd > dockershim {
		t.Errorf("candidate order = %v, want containerd and CRI-O before cri-dockerd before dockershim", eps)
	}
}

func TestResolverFallsBackPastANonCRISocket(t *testing.T) {
	original := criDialTimeout
	criDialTimeout = 2 * time.Second
	t.Cleanup(func() { criDialTimeout = original })

	dir := shortSocketDir(t)
	notCRI := filepath.Join(dir, "a.sock")
	realCRI := filepath.Join(dir, "b.sock")
	serveUnix(t, notCRI, nil)
	serveUnix(t, realCRI, func(s *grpc.Server) {
		runtimeapi.RegisterRuntimeServiceServer(s, versionedRuntimeServer{})
	})

	r, err := newResolverFromCandidates([]string{
		"unix://" + filepath.Join(dir, "missing.sock"),
		"unix://" + notCRI,
		"unix://" + realCRI,
	})
	if err != nil {
		t.Fatalf("newResolverFromCandidates: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if r.Endpoint() != "unix://"+realCRI {
		t.Errorf("endpoint = %q, want the CRI socket %q", r.Endpoint(), "unix://"+realCRI)
	}
}

func TestResolverReportsEveryFailedCandidate(t *testing.T) {
	original := criDialTimeout
	criDialTimeout = 500 * time.Millisecond
	t.Cleanup(func() { criDialTimeout = original })

	dir := shortSocketDir(t)
	first := filepath.Join(dir, "a.sock")
	second := filepath.Join(dir, "b.sock")
	serveUnix(t, first, nil)
	if err := os.WriteFile(second, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := newResolverFromCandidates([]string{"unix://" + first, "unix://" + second})
	if err == nil {
		t.Fatal("expected an error when no candidate is a CRI runtime")
	}
	if !strings.Contains(err.Error(), first) || !strings.Contains(err.Error(), second) {
		t.Errorf("error %q must name every failed candidate", err)
	}
}

func TestExistingEndpointsCollapseAliasesOfTheSameSocket(t *testing.T) {
	dir := shortSocketDir(t)
	target := filepath.Join(dir, "real.sock")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias.sock")
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	got := existingEndpoints([]string{"unix://" + target, "unix://" + alias})
	if len(got) != 1 || got[0] != "unix://"+target {
		t.Errorf("existingEndpoints = %v, want only %q", got, "unix://"+target)
	}
}
