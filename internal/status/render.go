package status

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/gma1k/podtrace/internal/sanitize"
)

const messageWidth = 90

const causeWidth = 160

// RenderJSON writes the report as JSON: indented for one-off output, one
// compact object per line for --watch, so the stream stays line-delimited.
func RenderJSON(w io.Writer, r Report, indent bool) error {
	enc := json.NewEncoder(w)
	if indent {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(r)
}

// RenderText writes the report as tables for a terminal.
func RenderText(w io.Writer, r Report) error {
	b := &strings.Builder{}
	fmt.Fprintf(b, "podtrace status · %s", r.GeneratedAt.Local().Format("2006-01-02 15:04:05"))
	if r.WindowSeconds > 0 {
		fmt.Fprintf(b, " · rates over %s", formatDuration(time.Duration(r.WindowSeconds*float64(time.Second))))
	}
	fmt.Fprintf(b, "\n%s · %s\n", healthLine(r), r.Summary)
	if len(r.Problems) > 0 {
		b.WriteString("\nPROBLEMS\n")
		for _, problem := range r.Problems {
			fmt.Fprintf(b, "✗ %s\n", clean(problem, 160))
		}
	}

	if len(r.Components) > 0 {
		b.WriteString("\nCOMPONENTS\n")
		components := [][]string{{"KIND", "NAME", "READY", "UPDATED", "STATE"}}
		for _, c := range r.Components {
			components = append(components, []string{c.Kind, c.Name,
				fmt.Sprintf("%d/%d", c.Ready, c.Desired), fmt.Sprintf("%d/%d", c.Updated, c.Desired), c.State})
		}
		writeTable(b, components)
	}

	b.WriteString("\nAGENTS\n")
	agents := [][]string{{"NODE", "POD", "STATE", "RESTARTS", "WORKLOADS"}}
	for _, a := range r.Agents {
		state := a.State
		if a.Reason != "" {
			state += " (" + clean(a.Reason, messageWidth) + ")"
		}
		agents = append(agents, []string{a.Node, a.Pod, state, fmt.Sprint(a.Restarts), fmt.Sprint(a.Workloads)})
	}
	writeTable(b, agents)

	b.WriteString("\nISSUES\n")
	if len(r.Issues) == 0 {
		b.WriteString("No active issues.\n")
	} else {
		issues := [][]string{{"SEVERITY", "ISSUE", "WORKLOAD", "POD", "SINCE", "MESSAGE"}}
		for _, is := range r.Issues {
			since := "-"
			if is.Since != nil {
				since = formatDuration(r.GeneratedAt.Sub(*is.Since))
			}
			issues = append(issues, []string{is.Severity, is.ID, is.Namespace + "/" + is.Workload,
				orDash(clean(is.Pod, messageWidth)), since, orDash(clean(is.Message, messageWidth))})
		}
		writeTable(b, issues)
		writeLikelyCauses(b, r.Issues)
	}

	b.WriteString("\nWORKLOADS\n")
	if len(r.Workloads) == 0 {
		b.WriteString("No application traffic observed in the window.\n")
	} else {
		workloads := [][]string{{"NAMESPACE", "WORKLOAD", "REQ/S", "ERRORS", "P95", "ISSUES"}}
		for _, wl := range r.Workloads {
			errs, p95 := "-", "-"
			if wl.ErrorPercent != nil {
				errs = fmt.Sprintf("%.1f%%", *wl.ErrorPercent)
			}
			if wl.P95Milliseconds != nil {
				p95 = formatDuration(time.Duration(*wl.P95Milliseconds * float64(time.Millisecond)))
			}
			workloads = append(workloads, []string{wl.Namespace, wl.Workload,
				fmt.Sprintf("%.1f", wl.RequestsPerSecond), errs, p95, fmt.Sprint(wl.Issues)})
		}
		writeTable(b, workloads)
	}

	if p := r.Profile; p != nil {
		fmt.Fprintf(b, "\nPROFILE %s/%s", p.Namespace, p.Workload)
		if p.Source != "" {
			fmt.Fprintf(b, " · %s", p.Source)
		}
		fmt.Fprintf(b, " · %d samples on %d node(s)", p.Samples, p.Nodes)
		if p.SchedulerFrames > 0 {
			fmt.Fprintf(b, " · %d samples ended in the Go scheduler and are charged to its caller", p.SchedulerFrames)
		}
		b.WriteString("\n")
		if len(p.Frames) == 0 {
			b.WriteString("No frames captured yet.\n")
		}
		writeHotFrames(b, p.Frames)
		if s := p.SlowRequests; s != nil {
			renderSlowRequests(b, s)
		}
	}

	if len(r.Warnings) > 0 {
		b.WriteString("\nWARNINGS\n")
		for _, warning := range r.Warnings {
			fmt.Fprintf(b, "! %s\n", sanitize.TerminalLine(warning))
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func healthLine(r Report) string {
	if r.Healthy {
		return "podtrace is healthy"
	}
	return "podtrace is NOT healthy"
}

// writeTable aligns rows into columns. It writes into a strings.Builder,
// which cannot fail, so the writer's errors carry nothing.
func writeTable(b *strings.Builder, rows [][]string) {
	tw := tabwriter.NewWriter(b, 0, 0, 2, ' ', 0)
	for _, row := range rows {
		_, _ = io.WriteString(tw, strings.Join(row, "\t")+"\n")
	}
	_ = tw.Flush()
}

// clean makes attacker-influenced text safe to print: an Event message or a
// symbol name can carry terminal control sequences.
func clean(s string, width int) string {
	s = sanitize.TerminalLine(s)
	if r := []rune(s); len(r) > width {
		s = string(r[:width-1]) + "…"
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func formatDuration(d time.Duration) string {
	switch {
	case d < 0:
		return "0s"
	case d < time.Millisecond:
		return fmt.Sprintf("%.2fms", float64(d)/float64(time.Millisecond))
	case d < time.Second:
		return fmt.Sprintf("%.0fms", float64(d)/float64(time.Millisecond))
	case d < time.Minute:
		return fmt.Sprintf("%.1fs", d.Seconds())
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

func writeHotFrames(b *strings.Builder, frames []HotFrame) {
	for _, f := range frames {
		fmt.Fprintf(b, "%6.1f%%  %s\n", f.Percent, clean(f.Frame, 160))
	}
}

// renderSlowRequests prints where the slowest requests spent their CPU.
func renderSlowRequests(b *strings.Builder, s *SlowRequestFrames) {
	threshold := formatDuration(time.Duration(s.ThresholdMinMilliseconds * float64(time.Millisecond)))
	if s.ThresholdMaxMilliseconds > s.ThresholdMinMilliseconds {
		threshold += "–" + formatDuration(time.Duration(s.ThresholdMaxMilliseconds*float64(time.Millisecond)))
	}
	fmt.Fprintf(b, "\nSLOWEST %s OF REQUESTS · ≥%s · %d of %d requests caught on CPU · %d samples\n",
		formatQuantileShare(s.Quantile), threshold, s.SampledRequests, s.Requests, s.Samples)
	if s.Samples == 0 {
		b.WriteString("No slow request was caught running: they spent their time waiting, not on a CPU.\n")
		return
	}
	writeHotFrames(b, s.Frames)
}

// formatQuantileShare turns 0.99 into "1%", the share of requests above it.
func formatQuantileShare(q float64) string {
	return strconv.FormatFloat(math.Round((1-q)*1000)/10, 'f', -1, 64) + "%"
}

// writeLikelyCauses lists, once per workload issue, what likely caused it.
func writeLikelyCauses(b *strings.Builder, issues []Issue) {
	rows := [][]string{{"WORKLOAD", "ISSUE", "LIKELY CAUSE"}}
	seen := map[string]bool{}
	for _, is := range issues {
		for _, c := range is.Causes {
			key := is.Namespace + "/" + is.Workload + "|" + is.ID + "|" + c.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			rows = append(rows, []string{is.Namespace + "/" + is.Workload, is.ID, clean(c.String(), causeWidth)})
		}
	}
	if len(rows) == 1 {
		return
	}
	b.WriteString("\nLIKELY CAUSES\n")
	writeTable(b, rows)
}
