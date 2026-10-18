package status

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func limitedCluster(t *testing.T, body string, max int64) *KubeCluster {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	cfg := &rest.Config{Host: srv.URL}
	LimitResponses(cfg, max)
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &KubeCluster{Client: cs, SystemNamespace: "podtrace-system"}
}

func TestAnOversizedAgentResponseIsRefused(t *testing.T) {
	k := limitedCluster(t, `{"issues":[`+strings.Repeat(`{"id":"x"},`, 1000)+`{"id":"x"}]}`, 1024)
	_, err := k.ActiveIssues(t.Context(), Agent{Name: "a", Port: 9090})
	if err == nil || !strings.Contains(err.Error(), "larger than 1024 bytes") {
		t.Fatalf("expected a size-limit error, got %v", err)
	}
}

func TestAResponseWithinTheLimitIsRead(t *testing.T) {
	k := limitedCluster(t, `{"issues":[{"id":"l7.error_rate"}]}`, 1024)
	issues, err := k.ActiveIssues(t.Context(), Agent{Name: "a", Port: 9090})
	if err != nil || len(issues) != 1 || issues[0].ID != "l7.error_rate" {
		t.Fatalf("got %v, %v", issues, err)
	}
}

func TestAResponseOfExactlyTheLimitIsRead(t *testing.T) {
	body := `{"issues":[]}`
	k := limitedCluster(t, body, int64(len(body)))
	if _, err := k.ActiveIssues(t.Context(), Agent{Name: "a", Port: 9090}); err != nil {
		t.Fatalf("a body of exactly the limit must be read, got %v", err)
	}
}
