package export

import (
	"bytes"
	"encoding/csv"
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func TestCSVFieldsReadBackUnchanged(t *testing.T) {
	var buf bytes.Buffer
	err := ExportCSV(csvDiagnostician(
		&events.Event{Type: events.EventOpen, ProcessName: `my"proc`, Target: "a,b"},
		&events.Event{Type: events.EventOpen, ProcessName: "nginx", Target: "line1\nline2"},
		&events.Event{Type: events.EventOpen, ProcessName: "sh", Target: "=HYPERLINK(\"x\")"},
	), &buf)
	if err != nil {
		t.Fatal(err)
	}

	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("got %d rows, want header + 3", len(rows))
	}
	for i, want := range []struct{ process, target string }{
		{`my"proc`, "a,b"},
		{"nginx", "line1\nline2"},
		{"sh", "'=HYPERLINK(\"x\")"},
	} {
		row := rows[i+1]
		if row[2] != want.process || row[6] != want.target {
			t.Errorf("row %d = (%q, %q), want (%q, %q)", i+1, row[2], row[6], want.process, want.target)
		}
	}
}
