package cri

import (
	"testing"
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



