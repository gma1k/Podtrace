package chart_test

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	"sigs.k8s.io/yaml"
)

const releaseDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func operatorImage(t *testing.T, flags ...string) string {
	t.Helper()
	var deploy appsv1.Deployment
	mustFindObject(t, renderChart(t, flags...), "Deployment", "podtrace-operator").decode(t, &deploy)
	return deploy.Spec.Template.Spec.Containers[0].Image
}

func TestReleaseDigestPinsOnlyTheDefaultImageReference(t *testing.T) {
	pinned := "image.appVersionDigest=" + releaseDigest
	for name, tt := range map[string]struct {
		flags []string
		want  string
	}{
		"released chart":      {[]string{pinned}, ":" + chartAppVersion(t) + "@" + releaseDigest},
		"chosen tag":          {[]string{pinned, "image.tag=0.1.0"}, "ghcr.io/gma1k/podtrace:0.1.0"},
		"chosen digest":       {[]string{pinned, "image.digest=sha256:" + strings.Repeat("2", 64)}, "@sha256:" + strings.Repeat("2", 64)},
		"mirror repository":   {[]string{pinned, "image.repository=mirror.example/podtrace"}, "mirror.example/podtrace:" + chartAppVersion(t)},
		"unreleased checkout": {nil, "ghcr.io/gma1k/podtrace:" + chartAppVersion(t)},
	} {
		t.Run(name, func(t *testing.T) {
			got := operatorImage(t, tt.flags...)
			if !strings.HasSuffix(got, tt.want) {
				t.Errorf("image = %q, want it to end in %q", got, tt.want)
			}
			if name != "released chart" && strings.Contains(got, releaseDigest) {
				t.Errorf("image = %q: the release digest overrode an explicit choice", got)
			}
		})
	}
}

func TestReleaseDigestReachesTheAgentsAndSessions(t *testing.T) {
	tc := bootstrapTracerConfig(t, "--set", "image.appVersionDigest="+releaseDigest)
	if !strings.HasSuffix(tc.Spec.Image, "@"+releaseDigest) {
		t.Errorf("TracerConfig image = %q; the root, CAP_SYS_ADMIN agents are the workload the "+
			"pin exists for", tc.Spec.Image)
	}
}

func chartAppVersion(t *testing.T) string {
	t.Helper()
	raw := readRepoFile(t, "deploy", "charts", "podtrace", "Chart.yaml")
	var chart struct {
		AppVersion string `json:"appVersion"`
	}
	if err := yaml.Unmarshal(raw, &chart); err != nil || chart.AppVersion == "" {
		t.Fatalf("Chart.yaml appVersion: %q, %v", chart.AppVersion, err)
	}
	return chart.AppVersion
}
