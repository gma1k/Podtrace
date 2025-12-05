package tracker

import (
	"fmt"
	"os"
	"testing"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
)

func TestAnalyzeProcessActivity_UsesProcessNameFromEvents(t *testing.T) {
	evs := []*events.Event{
		{PID: 1234, ProcessName: "proc-a"},
		{PID: 1234, ProcessName: "proc-a"},
		{PID: 5678, ProcessName: "proc-b"},
	}

	pids := AnalyzeProcessActivity(evs)
	if len(pids) != 2 {
		t.Fatalf("expected 2 pid entries, got %d", len(pids))
	}
	if pids[0].Name == "" || pids[1].Name == "" {
		t.Fatalf("expected names to be populated from events")
	}
}

func TestAnalyzeProcessActivity_Empty(t *testing.T) {
	result := AnalyzeProcessActivity([]*events.Event{})
	if len(result) != 0 {
		t.Errorf("Expected empty result, got %d items", len(result))
	}
}

func TestAnalyzeProcessActivity_SinglePID(t *testing.T) {
	events := []*events.Event{
		{PID: 1234, ProcessName: "test", Type: events.EventDNS},
		{PID: 1234, ProcessName: "test", Type: events.EventConnect},
		{PID: 1234, ProcessName: "test", Type: events.EventRead},
	}

	result := AnalyzeProcessActivity(events)
	if len(result) != 1 {
		t.Errorf("Expected 1 PID, got %d", len(result))
	}
	if result[0].Pid != 1234 {
		t.Errorf("Expected PID 1234, got %d", result[0].Pid)
	}
	if result[0].Count != 3 {
		t.Errorf("Expected 3 events, got %d", result[0].Count)
	}
	if result[0].Percentage != 100.0 {
		t.Errorf("Expected 100%%, got %.2f", result[0].Percentage)
	}
}

func TestAnalyzeProcessActivity_MultiplePIDs(t *testing.T) {
	events := []*events.Event{
		{PID: 1234, ProcessName: "test1", Type: events.EventDNS},
		{PID: 1234, ProcessName: "test1", Type: events.EventConnect},
		{PID: 5678, ProcessName: "test2", Type: events.EventRead},
	}

	result := AnalyzeProcessActivity(events)
	if len(result) != 2 {
		t.Errorf("Expected 2 PIDs, got %d", len(result))
	}
	if result[0].Count < result[1].Count {
		t.Error("Results should be sorted by count descending")
	}
}

func TestAnalyzeProcessActivity_NoProcessName(t *testing.T) {
	events := []*events.Event{
		{PID: 1234, Type: events.EventDNS},
	}

	result := AnalyzeProcessActivity(events)
	if len(result) != 1 {
		t.Errorf("Expected 1 PID, got %d", len(result))
	}
	if result[0].Name == "" {
		t.Log("Process name is empty (may be expected if /proc not accessible)")
	}
}

func TestGetProcessNameFromProc_InvalidPID(t *testing.T) {
	result := getProcessNameFromProc(0)
	if result != "" {
		t.Errorf("Expected empty string for invalid PID, got %q", result)
	}
}

func TestGetProcessNameFromProc_FromStat(t *testing.T) {
	dir := t.TempDir()
	origProcBasePath := config.ProcBasePath
	defer func() { config.SetProcBasePath(origProcBasePath) }()

	pid := uint32(1234)
	statPath := fmt.Sprintf("%s/%d/stat", dir, pid)
	os.MkdirAll(fmt.Sprintf("%s/%d", dir, pid), 0755)
	statContent := "1234 (test-process) S 1 1234 1234 0 -1 4194304"
	os.WriteFile(statPath, []byte(statContent), 0644)

	config.SetProcBasePath(dir)
	result := getProcessNameFromProc(pid)
	if result != "test-process" {
		t.Errorf("Expected 'test-process' from stat, got %q", result)
	}
}

func TestGetProcessNameFromProc_FromComm(t *testing.T) {
	dir := t.TempDir()
	origProcBasePath := config.ProcBasePath
	defer func() { config.SetProcBasePath(origProcBasePath) }()

	pid := uint32(1234)
	commPath := fmt.Sprintf("%s/%d/comm", dir, pid)
	os.MkdirAll(fmt.Sprintf("%s/%d", dir, pid), 0755)
	os.WriteFile(commPath, []byte("test-process\n"), 0644)

	config.SetProcBasePath(dir)
	result := getProcessNameFromProc(pid)
	if result != "test-process" {
		t.Errorf("Expected 'test-process' from comm, got %q", result)
	}
}

func TestGetProcessNameFromProc_FromCmdline(t *testing.T) {
	dir := t.TempDir()
	origProcBasePath := config.ProcBasePath
	defer func() { config.SetProcBasePath(origProcBasePath) }()

	pid := uint32(1234)
	cmdlinePath := fmt.Sprintf("%s/%d/cmdline", dir, pid)
	os.MkdirAll(fmt.Sprintf("%s/%d", dir, pid), 0755)
	cmdlineContent := []byte("/usr/bin/test-process\x00arg1\x00arg2")
	os.WriteFile(cmdlinePath, cmdlineContent, 0644)

	config.SetProcBasePath(dir)
	result := getProcessNameFromProc(pid)
	if result != "test-process" {
		t.Errorf("Expected 'test-process' from cmdline, got %q", result)
	}
}

func TestGetProcessNameFromProc_FromCmdlineNoSlash(t *testing.T) {
	dir := t.TempDir()
	origProcBasePath := config.ProcBasePath
	defer func() { config.SetProcBasePath(origProcBasePath) }()

	pid := uint32(1234)
	cmdlinePath := fmt.Sprintf("%s/%d/cmdline", dir, pid)
	os.MkdirAll(fmt.Sprintf("%s/%d", dir, pid), 0755)
	cmdlineContent := []byte("test-process\x00arg1")
	os.WriteFile(cmdlinePath, cmdlineContent, 0644)

	config.SetProcBasePath(dir)
	result := getProcessNameFromProc(pid)
	if result != "test-process" {
		t.Errorf("Expected 'test-process' from cmdline, got %q", result)
	}
}

func TestGetProcessNameFromProc_FromExe(t *testing.T) {
	dir := t.TempDir()
	origProcBasePath := config.ProcBasePath
	defer func() { config.SetProcBasePath(origProcBasePath) }()

	pid := uint32(1234)
	exePath := fmt.Sprintf("%s/%d/exe", dir, pid)
	os.MkdirAll(fmt.Sprintf("%s/%d", dir, pid), 0755)
	os.Symlink("/usr/bin/test-process", exePath)

	config.SetProcBasePath(dir)
	result := getProcessNameFromProc(pid)
	if result != "test-process" {
		t.Errorf("Expected 'test-process' from exe, got %q", result)
	}
}

func TestGetProcessNameFromProc_FromExeNoSlash(t *testing.T) {
	dir := t.TempDir()
	origProcBasePath := config.ProcBasePath
	defer func() { config.SetProcBasePath(origProcBasePath) }()

	pid := uint32(1234)
	exePath := fmt.Sprintf("%s/%d/exe", dir, pid)
	os.MkdirAll(fmt.Sprintf("%s/%d", dir, pid), 0755)
	os.Symlink("test-process", exePath)

	config.SetProcBasePath(dir)
	result := getProcessNameFromProc(pid)
	if result != "test-process" {
		t.Errorf("Expected 'test-process' from exe, got %q", result)
	}
}

func TestGetProcessNameFromProc_FromStatus(t *testing.T) {
	dir := t.TempDir()
	origProcBasePath := config.ProcBasePath
	defer func() { config.SetProcBasePath(origProcBasePath) }()

	pid := uint32(1234)
	statusPath := fmt.Sprintf("%s/%d/status", dir, pid)
	os.MkdirAll(fmt.Sprintf("%s/%d", dir, pid), 0755)
	statusContent := "Name:\ttest-process\nState:\tS\n"
	os.WriteFile(statusPath, []byte(statusContent), 0644)

	config.SetProcBasePath(dir)
	result := getProcessNameFromProc(pid)
	if result != "test-process" {
		t.Errorf("Expected 'test-process' from status, got %q", result)
	}
}

func TestGetProcessNameFromProc_StatError(t *testing.T) {
	dir := t.TempDir()
	origProcBasePath := config.ProcBasePath
	defer func() { config.SetProcBasePath(origProcBasePath) }()

	pid := uint32(1234)
	commPath := fmt.Sprintf("%s/%d/comm", dir, pid)
	os.MkdirAll(fmt.Sprintf("%s/%d", dir, pid), 0755)
	os.WriteFile(commPath, []byte("test-process\n"), 0644)

	config.SetProcBasePath(dir)
	result := getProcessNameFromProc(pid)
	if result != "test-process" {
		t.Errorf("Expected 'test-process' from comm when stat fails, got %q", result)
	}
}

func TestGetProcessNameFromProc_StatInvalidFormat(t *testing.T) {
	dir := t.TempDir()
	origProcBasePath := config.ProcBasePath
	defer func() { config.SetProcBasePath(origProcBasePath) }()

	pid := uint32(1234)
	statPath := fmt.Sprintf("%s/%d/stat", dir, pid)
	commPath := fmt.Sprintf("%s/%d/comm", dir, pid)
	os.MkdirAll(fmt.Sprintf("%s/%d", dir, pid), 0755)
	os.WriteFile(statPath, []byte("invalid format"), 0644)
	os.WriteFile(commPath, []byte("test-process\n"), 0644)

	config.SetProcBasePath(dir)
	result := getProcessNameFromProc(pid)
	if result != "test-process" {
		t.Errorf("Expected 'test-process' from comm when stat invalid, got %q", result)
	}
}

func TestGetProcessNameFromProc_StatNoParentheses(t *testing.T) {
	dir := t.TempDir()
	origProcBasePath := config.ProcBasePath
	defer func() { config.SetProcBasePath(origProcBasePath) }()

	pid := uint32(1234)
	statPath := fmt.Sprintf("%s/%d/stat", dir, pid)
	commPath := fmt.Sprintf("%s/%d/comm", dir, pid)
	os.MkdirAll(fmt.Sprintf("%s/%d", dir, pid), 0755)
	os.WriteFile(statPath, []byte("1234 test-process S 1"), 0644)
	os.WriteFile(commPath, []byte("test-process\n"), 0644)

	config.SetProcBasePath(dir)
	result := getProcessNameFromProc(pid)
	if result != "test-process" {
		t.Errorf("Expected 'test-process' from comm when stat has no parentheses, got %q", result)
	}
}

func TestGetProcessNameFromProc_CmdlineEmpty(t *testing.T) {
	dir := t.TempDir()
	origProcBasePath := config.ProcBasePath
	defer func() { config.SetProcBasePath(origProcBasePath) }()

	pid := uint32(1234)
	cmdlinePath := fmt.Sprintf("%s/%d/cmdline", dir, pid)
	exePath := fmt.Sprintf("%s/%d/exe", dir, pid)
	os.MkdirAll(fmt.Sprintf("%s/%d", dir, pid), 0755)
	os.WriteFile(cmdlinePath, []byte(""), 0644)
	os.Symlink("/usr/bin/test-process", exePath)

	config.SetProcBasePath(dir)
	result := getProcessNameFromProc(pid)
	if result != "test-process" {
		t.Errorf("Expected 'test-process' from exe when cmdline empty, got %q", result)
	}
}

func TestGetProcessNameFromProc_StatusInvalidFormat(t *testing.T) {
	dir := t.TempDir()
	origProcBasePath := config.ProcBasePath
	defer func() { config.SetProcBasePath(origProcBasePath) }()

	pid := uint32(1234)
	statusPath := fmt.Sprintf("%s/%d/status", dir, pid)
	os.MkdirAll(fmt.Sprintf("%s/%d", dir, pid), 0755)
	statusContent := "Name:\nState:\tS\n"
	os.WriteFile(statusPath, []byte(statusContent), 0644)

	config.SetProcBasePath(dir)
	result := getProcessNameFromProc(pid)
	if result == "" {
		t.Log("Expected empty result when status format invalid")
	}
}

func TestGetProcessNameFromProc_AllPathsFail(t *testing.T) {
	dir := t.TempDir()
	origProcBasePath := config.ProcBasePath
	defer func() { config.SetProcBasePath(origProcBasePath) }()

	pid := uint32(999999)
	config.SetProcBasePath(dir)
	result := getProcessNameFromProc(pid)
	if result != "" {
		t.Errorf("Expected empty string when all paths fail, got %q", result)
	}
}
