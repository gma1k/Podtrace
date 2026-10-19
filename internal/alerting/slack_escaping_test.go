package alerting

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSlackPayloadEscapesControlSequences(t *testing.T) {
	var payload SlackPayload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &payload)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sender := &SlackSender{webhookURL: server.URL, channel: "#a", client: server.Client()}
	alert := &Alert{
		Severity:        SeverityCritical,
		Title:           "<!here> title",
		Message:         "boom <!channel> see <https://evil.example|docs> & more",
		Timestamp:       time.Now(),
		Source:          "<@U123>",
		PodName:         "pod<x>",
		Namespace:       "ns&",
		ErrorCode:       "<!everyone>",
		Recommendations: []string{"open <https://evil.example|runbook>", "second"},
	}
	if err := sender.Send(context.Background(), alert); err != nil {
		t.Fatal(err)
	}
	attachment := payload.Attachments[0]
	if attachment.Text != "boom &lt;!channel&gt; see &lt;https://evil.example|docs&gt; &amp; more" {
		t.Errorf("text = %q", attachment.Text)
	}
	if attachment.Title != "&lt;!here&gt; title" {
		t.Errorf("title = %q", attachment.Title)
	}
	for _, field := range attachment.Fields {
		if strings.ContainsAny(field.Value, "<>") {
			t.Errorf("field %q value not escaped: %q", field.Title, field.Value)
		}
		if field.Title == "Recommendations" && field.Value != "open &lt;https://evil.example|runbook&gt;\nsecond" {
			t.Errorf("recommendations = %q", field.Value)
		}
		if field.Title == "Namespace" && field.Value != "ns&amp;" {
			t.Errorf("namespace = %q", field.Value)
		}
	}
}
