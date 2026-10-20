//go:build envtest
// +build envtest

package agent

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/pkg/tracer"
)

const (
	runHealthAddr  = "127.0.0.1:19191"
	runMetricsAddr = "127.0.0.1:19192"
	runInspectAddr = "127.0.0.1:19193"
)

func probe(t *testing.T, addr, path string) (int, string) {
	t.Helper()
	response, err := http.Get("http://" + addr + path)
	if err != nil {
		return 0, err.Error()
	}
	defer func() { _ = response.Body.Close() }()
	body, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(body)
}

func waitForProbe(t *testing.T, path string, want int, done <-chan error) string {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var lastCode int
	var lastBody string
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			t.Fatalf("Run exited before %s returned %d: %v", path, want, err)
		default:
		}
		lastCode, lastBody = probe(t, runHealthAddr, path)
		if lastCode == want {
			return lastBody
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s never returned %d; last was %d %q", path, want, lastCode, lastBody)
	return ""
}

func TestAgentRunBootsServesAndShutsDownCleanly(t *testing.T) {
	_, c := setupSharedEnvtest(t)
	systemNS := ensureSystemNamespace(t, c)
	ns := freshNamespace(t, c)

	workloadMetrics, alerting := config.WorkloadMetricsEnabled, config.AlertingEnabled
	config.WorkloadMetricsEnabled, config.AlertingEnabled = true, true
	t.Cleanup(func() {
		config.WorkloadMetricsEnabled, config.AlertingEnabled = workloadMetrics, alerting
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := c.Create(ctx, &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "boot", Namespace: ns, UID: "uid-boot"},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			Filters:     []podtracev1alpha1.EventFilter{podtracev1alpha1.FilterDNS},
			ExporterRef: corev1.LocalObjectReference{Name: "ignored"},
		},
	}); err != nil {
		t.Fatalf("create PodTrace: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			NodeName:             "test-node",
			SystemNamespace:      systemNS,
			TracerConfigName:     "default",
			MetricsAddr:          runMetricsAddr,
			HealthAddr:           runHealthAddr,
			InspectAddr:          runInspectAddr,
			StatusReportInterval: time.Second,
			RestConfig:           testEnv.Config,
			BackendFactory: func() (tracer.TracerBackend, error) {
				return nil, errors.New("load ebpf program: truncated object")
			},
		})
	}()

	reason := waitForProbe(t, "/readyz", http.StatusServiceUnavailable, done)
	if reason != "degraded: collection_failed" {
		t.Errorf("/readyz body = %q, want %q. A loader failure is the likeliest real fault, so "+
			"it is the one that must name itself rather than reporting unknown",
			reason, "degraded: collection_failed")
	}

	if code, _ := probe(t, runHealthAddr, "/healthz"); code != http.StatusOK {
		t.Errorf("/healthz = %d, want 200. A degraded agent must be held out of service, not "+
			"restarted — killing it destroys the logs and metrics needed to diagnose it", code)
	}

	if code, _ := probe(t, runMetricsAddr, "/metrics"); code != http.StatusOK {
		t.Errorf("/metrics = %d, want 200. An agent that boots but never serves its registry is "+
			"invisible to the scrape that is supposed to prove it is working", code)
	}

	if code, body := probe(t, runInspectAddr, "/issues"); body == "404 page not found\n" {
		t.Errorf("/issues on the inspect port = %d %q; the operator and kubectl podtrace status "+
			"read issues there", code, body)
	}
	if code, body := probe(t, runMetricsAddr, "/issues"); code != http.StatusNotFound || body != "404 page not found\n" {
		t.Errorf("/issues on the metrics port = %d %q, want unrouted: any scraper reaches that port", code, body)
	}

	waitForReconcile(t, done)

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v on a cancelled context, want nil. A non-nil return makes "+
				"an ordinary pod shutdown look like a crash loop", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
}

func TestAgentRunRejectsIncompleteOptions(t *testing.T) {
	cases := []struct {
		name string
		opts Options
	}{
		{"no node name", Options{SystemNamespace: "podtrace-system"}},
		{"no system namespace", Options{NodeName: "n"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := Run(context.Background(), tc.opts); err == nil {
				t.Fatal("Run accepted incomplete options. Booting without them yields an agent " +
					"that watches the wrong node or namespace and reports healthy while doing it")
			}
		})
	}
}

func waitForReconcile(t *testing.T, done <-chan error) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			t.Fatalf("Run exited before reconciling: %v", err)
		default:
		}
		_, body := probe(t, runMetricsAddr, "/metrics")
		for _, line := range strings.Split(body, "\n") {
			if !strings.HasPrefix(line, "podtrace_agent_reconcile_total") {
				continue
			}
			if fields := strings.Fields(line); len(fields) == 2 && fields[1] != "0" {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("the agent never reconciled the PodTrace it was given. Reconciles only start once " +
		"the informer cache has synced, so this is the agent failing to finish booting")
}
