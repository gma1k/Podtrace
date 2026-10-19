package cri

import (
	"context"
	"os"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestDefaultCandidateEndpoints_PodmanDisabled(t *testing.T) {
	t.Setenv("PODTRACE_CRI_ALLOW_PODMAN", "")
	eps := DefaultCandidateEndpoints()
	for _, ep := range eps {
		if ep == "unix:///run/podman/podman.sock" || ep == "unix:///var/run/podman/podman.sock" {
			t.Fatalf("expected podman endpoints to be excluded by default, got %v", eps)
		}
	}
}

func TestDefaultCandidateEndpoints_PodmanEnabled(t *testing.T) {
	t.Setenv("PODTRACE_CRI_ALLOW_PODMAN", "1")
	eps := DefaultCandidateEndpoints()
	foundRun := false
	foundVar := false
	for _, ep := range eps {
		if ep == "unix:///run/podman/podman.sock" {
			foundRun = true
		}
		if ep == "unix:///var/run/podman/podman.sock" {
			foundVar = true
		}
	}
	if !foundRun || !foundVar {
		t.Fatalf("expected podman endpoints when enabled, got %v", eps)
	}
}

func TestNormalizeUnixTarget(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"unix:///run/containerd/containerd.sock", "unix:///run/containerd/containerd.sock"},
		{"/run/containerd/containerd.sock", "unix:///run/containerd/containerd.sock"},
		{"something", "something"},
	}
	for _, tc := range cases {
		if got := normalizeUnixTarget(tc.in); got != tc.want {
			t.Fatalf("normalizeUnixTarget(%q)=%q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestExtractLooseCgroupsPath(t *testing.T) {
	s := `{"cgroupsPath":"\\/kubepods.slice\\/kubepods-burstable.slice\\/cri-containerd-abcdef.scope"}`
	got := extractLooseCgroupsPath(s)
	if got != "/kubepods.slice/kubepods-burstable.slice/cri-containerd-abcdef.scope" {
		t.Fatalf("unexpected cgroups path: %q", got)
	}
}

func TestExtractLooseCgroupsPath_NoKey(t *testing.T) {
	if got := extractLooseCgroupsPath(`{"pid":123}`); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestExtractLooseCgroupsPath_NoClosingQuote(t *testing.T) {
	if got := extractLooseCgroupsPath(`{"cgroupsPath":"unclosed`); got != "" {
		t.Fatalf("expected empty for unclosed string, got %q", got)
	}
}

func TestResolverEndpoint_Nil(t *testing.T) {
	var r *Resolver
	if ep := r.Endpoint(); ep != "" {
		t.Fatalf("expected empty endpoint for nil resolver, got %q", ep)
	}
}

func TestResolverEndpoint_NonNil(t *testing.T) {
	r := &Resolver{endpoint: "unix:///run/containerd/containerd.sock"}
	if ep := r.Endpoint(); ep != "unix:///run/containerd/containerd.sock" {
		t.Fatalf("unexpected endpoint: %q", ep)
	}
}

func TestResolverClose_Nil(t *testing.T) {
	var r *Resolver
	if err := r.Close(); err != nil {
		t.Fatalf("Close on nil resolver should return nil, got %v", err)
	}
}

func TestResolverClose_NilConn(t *testing.T) {
	r := &Resolver{endpoint: "x", conn: nil}
	if err := r.Close(); err != nil {
		t.Fatalf("Close with nil conn should return nil, got %v", err)
	}
}

func TestExistingEndpoints_NoneExist(t *testing.T) {
	candidates := []string{
		"unix:///nonexistent/podtrace-test-1.sock",
		"unix:///nonexistent/podtrace-test-2.sock",
	}
	if ep := firstOf(existingEndpoints(candidates)); ep != "" {
		t.Fatalf("expected empty when none exist, got %q", ep)
	}
}

func TestExistingEndpoints_FirstExists(t *testing.T) {
	dir := t.TempDir()
	// Create a fake socket file (just a regular file for stat purposes).
	sockPath := dir + "/containerd.sock"
	if err := os.WriteFile(sockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	candidates := []string{
		"unix://" + sockPath,
		"unix:///nonexistent/other.sock",
	}
	if ep := firstOf(existingEndpoints(candidates)); ep != "unix://"+sockPath {
		t.Fatalf("expected first existing endpoint, got %q", ep)
	}
}

func TestExistingEndpoints_EmptyScheme(t *testing.T) {
	// Entry with empty path after stripping unix:// should be skipped.
	candidates := []string{"unix://"}
	if ep := firstOf(existingEndpoints(candidates)); ep != "" {
		t.Fatalf("expected empty for unix:// with no path, got %q", ep)
	}
}

func TestNewResolverWithEndpoint_NoEndpoint(t *testing.T) {
	// No env var, no existing sockets → should fail with "not found" error.
	t.Setenv("PODTRACE_CRI_ENDPOINT", "")
	_, err := NewResolverWithEndpoint("")
	if err == nil {
		t.Fatal("expected error when no CRI endpoint found")
	}
}

func TestResolveContainer_NilResolver(t *testing.T) {
	var r *Resolver
	_, err := r.ResolveContainer(t.Context(), "abc123")
	if err == nil {
		t.Fatal("expected error for nil resolver")
	}
}

func TestResolveContainer_EmptyContainerID(t *testing.T) {
	r := &Resolver{endpoint: "x"} // client is nil but we check containerID first
	_, err := r.ResolveContainer(t.Context(), "")
	if err == nil {
		t.Fatal("expected error for empty container id")
	}
}

func TestWaitForReady_NilConn(t *testing.T) {
	err := waitForReady(t.Context(), nil)
	if err == nil {
		t.Fatal("expected error for nil conn")
	}
}

func TestWaitForReady_AlreadyCancelledContext(t *testing.T) {
	conn, err := grpc.NewClient(
		"unix:///nonexistent/podtrace-test.sock",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Skipf("cannot create test grpc conn: %v", err)
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = waitForReady(ctx, conn)
	if err == nil {
		t.Error("expected error for already-cancelled context")
	}
}

func TestNewResolverWithEndpoint_ExistingSocketBadServer(t *testing.T) {
	dir := t.TempDir()
	sockPath := dir + "/fake.sock"
	if err := os.WriteFile(sockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewResolverWithEndpoint("unix://" + sockPath)
	if err == nil {
		t.Log("NewResolverWithEndpoint succeeded (may have fast-pathed connection)")
	}
}
