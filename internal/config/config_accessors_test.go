package config

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestGetDockerContainerRootfs_CleanPathTraversal(t *testing.T) {
	original := DockerBasePath
	t.Cleanup(func() { DockerBasePath = original })

	DockerBasePath = ".."
	_, err := GetDockerContainerRootfs("abc123")
	if err == nil {
		t.Fatal("expected an error for a base path that resolves to a traversal, got nil")
		return
	}
	if !strings.Contains(err.Error(), "traversal sequence") {
		t.Errorf("error = %v, want it to mention the traversal sequence guard", err)
	}
}

func TestArtifactBaseDir(t *testing.T) {
	t.Run("unset returns empty", func(t *testing.T) {
		t.Setenv(EnvArtifactBaseDir, "")
		if got := ArtifactBaseDir(); got != "" {
			t.Errorf("ArtifactBaseDir() = %q, want empty when unset", got)
		}
	})
	t.Run("returns configured directory", func(t *testing.T) {
		t.Setenv(EnvArtifactBaseDir, "/var/run/podtrace/artifacts")
		if got := ArtifactBaseDir(); got != "/var/run/podtrace/artifacts" {
			t.Errorf("ArtifactBaseDir() = %q, want /var/run/podtrace/artifacts", got)
		}
	})
}

func TestExporterAllowInsecureNonLoopback(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"", false},
		{"1", true},
		{"true", true},
		{"TRUE", true},
		{"0", false},
		{"garbage", false},
	}
	for _, c := range cases {
		t.Setenv("PODTRACE_EXPORTER_INSECURE", c.value)
		if got := ExporterAllowInsecureNonLoopback(); got != c.want {
			t.Errorf("ExporterAllowInsecureNonLoopback() with %q = %v, want %v", c.value, got, c.want)
		}
	}
}

func TestWebhookAllowHTTP(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"", false},
		{"1", true},
		{"true", true},
		{"0", false},
		{"nonsense", false},
	}
	for _, c := range cases {
		t.Setenv("PODTRACE_ALERT_WEBHOOK_ALLOW_HTTP", c.value)
		if got := WebhookAllowHTTP(); got != c.want {
			t.Errorf("WebhookAllowHTTP() with %q = %v, want %v", c.value, got, c.want)
		}
	}
}

func TestCaptureHeaderList(t *testing.T) {
	original := CaptureHeaders
	t.Cleanup(func() { CaptureHeaders = original })

	t.Run("empty yields nil", func(t *testing.T) {
		CaptureHeaders = ""
		if got := CaptureHeaderList(); got != nil {
			t.Errorf("CaptureHeaderList() = %v, want nil for empty CaptureHeaders", got)
		}
	})

	t.Run("parses and normalizes the configured list", func(t *testing.T) {
		CaptureHeaders = " X-Request-Id , Content-Type "
		want := []string{"x-request-id", "content-type"}
		if got := CaptureHeaderList(); !reflect.DeepEqual(got, want) {
			t.Errorf("CaptureHeaderList() = %v, want %v", got, want)
		}
	})
}

func TestAllowedAgentImageRepos_DefaultsToTrustedImage(t *testing.T) {
	if _, set := os.LookupEnv("PODTRACE_ALLOWED_AGENT_IMAGE_REPOS"); set {
		t.Skip("PODTRACE_ALLOWED_AGENT_IMAGE_REPOS set in environment")
	}
	got := AllowedAgentImageRepos()
	if len(got) != 1 || got[0] != Image {
		t.Errorf("default AllowedAgentImageRepos = %v, want [%s]", got, Image)
	}
}

func TestAllowedAgentImageRepos_WidenedViaEnv(t *testing.T) {
	t.Setenv("PODTRACE_ALLOWED_AGENT_IMAGE_REPOS", "ghcr.io/gma1k/podtrace, registry.internal:5000/mirror , ")
	got := AllowedAgentImageRepos()
	want := []string{"ghcr.io/gma1k/podtrace", "registry.internal:5000/mirror"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("AllowedAgentImageRepos = %v, want %v", got, want)
	}
}

func TestAllowedAgentImageRepos_EmptyFailsClosedToTrustedImage(t *testing.T) {
	for _, raw := range []string{"", " ", " , ", ",,"} {
		t.Setenv("PODTRACE_ALLOWED_AGENT_IMAGE_REPOS", raw)
		got := AllowedAgentImageRepos()
		if len(got) != 1 || got[0] != Image {
			t.Errorf("AllowedAgentImageRepos(%q) = %v, want [%s]", raw, got, Image)
		}
	}
}

func TestAllowedAgentImageRepos_ExplicitWildcardIsPassedThrough(t *testing.T) {
	t.Setenv("PODTRACE_ALLOWED_AGENT_IMAGE_REPOS", "*")
	got := AllowedAgentImageRepos()
	if len(got) != 1 || got[0] != "*" {
		t.Errorf("AllowedAgentImageRepos = %v, want [*]", got)
	}
}
