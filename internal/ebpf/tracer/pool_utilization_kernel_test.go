//go:build bpf_loadtest && linux

package tracer

import (
	"bufio"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/ebpf/probes"
	"github.com/gma1k/podtrace/internal/events"
)

const poolWorkerShape = "PODTRACE_POOL_WORKER_SHAPE"

type sleepDriver struct{ query time.Duration }
type sleepConn struct{ query time.Duration }
type sleepStmt struct{ query time.Duration }
type noRows struct{}

func (d sleepDriver) Open(string) (driver.Conn, error)       { return sleepConn(d), nil }
func (c sleepConn) Prepare(string) (driver.Stmt, error)      { return sleepStmt(c), nil }
func (sleepConn) Close() error                               { return nil }
func (sleepConn) Begin() (driver.Tx, error)                  { return nil, errors.New("no transactions") }
func (sleepStmt) Close() error                               { return nil }
func (sleepStmt) NumInput() int                              { return -1 }
func (sleepStmt) Exec([]driver.Value) (driver.Result, error) { return nil, errors.New("no exec") }
func (s sleepStmt) Query([]driver.Value) (driver.Rows, error) {
	time.Sleep(s.query)
	return noRows{}, nil
}
func (noRows) Columns() []string         { return []string{"x"} }
func (noRows) Close() error              { return nil }
func (noRows) Next([]driver.Value) error { return io.EOF }

func TestKernelPoolWorker(t *testing.T) {
	shape := os.Getenv(poolWorkerShape)
	if shape == "" {
		t.Skip("only runs as the child of the pool utilization kernel test")
	}
	query, workers, pause := time.Millisecond, 1, 5*time.Millisecond
	switch shape {
	case "starved":
		query, workers, pause = 20*time.Millisecond, 8, 0
	case "shared":
		query, workers, pause = time.Millisecond, 8, 50*time.Millisecond
	}
	sql.Register("sleep-"+shape, sleepDriver{query: query})
	db, err := sql.Open("sleep-"+shape, "")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	fmt.Println("ready")
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3500 * time.Millisecond)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				rows, err := db.QueryContext(context.Background(), "select 1")
				if err == nil {
					_ = rows.Close()
				}
				time.Sleep(pause)
			}
		}()
	}
	wg.Wait()
	fmt.Println("done")
}

type poolCollector struct {
	mu       sync.Mutex
	readings map[uint32][]int32
}

func collectPoolReadings(ctx context.Context, ch chan *events.Event) *poolCollector {
	c := &poolCollector{readings: map[uint32][]int32{}}
	go func() {
		for {
			select {
			case ev := <-ch:
				if ev.Type == events.EventDBPoolStats {
					c.mu.Lock()
					c.readings[ev.PID] = append(c.readings[ev.PID], ev.Error)
					c.mu.Unlock()
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return c
}

func (c *poolCollector) of(pid uint32) []int32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int32(nil), c.readings[pid]...)
}

func poolReadings(t *testing.T, tr *Tracer, c *poolCollector, w fsWorker, shape string) []int32 {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestKernelPoolWorker$")
	cmd.Env = append(os.Environ(), poolWorkerShape+"="+shape)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	lines := bufio.NewScanner(stdout)
	if !lines.Scan() || lines.Text() != "ready" {
		t.Fatalf("the worker did not start: %q", lines.Text())
	}
	pid := uint32(cmd.Process.Pid)
	if err := os.WriteFile(w.cgroup+"/cgroup.procs", []byte(strconv.Itoa(cmd.Process.Pid)), 0o644); err != nil {
		t.Fatalf("move the worker into its cgroup: %v", err)
	}
	links := probes.AttachPoolProbesWithPID(tr.collection, "", pid, nil)
	t.Cleanup(func() {
		for _, l := range links {
			_ = l.Close()
		}
	})
	if len(links) == 0 {
		t.Fatal("no pool probe attached to the worker")
	}
	if _, err := io.WriteString(stdin, "go\n"); err != nil {
		t.Fatal(err)
	}
	for lines.Scan() && lines.Text() != "done" {
	}
	time.Sleep(500 * time.Millisecond)
	return c.of(pid)
}

func TestKernelPoolUtilizationCountsConnectionsInUseNotOpen(t *testing.T) {
	w := newFSWorker(t, "pool")
	tr := fsTracer(t, "fentry", w)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ch := make(chan *events.Event, 1<<16)
	collector := collectPoolReadings(ctx, ch)
	if err := tr.Start(ctx, ch); err != nil {
		t.Fatalf("Start: %v", err)
	}

	idle := poolReadings(t, tr, collector, w, "idle")
	if len(idle) == 0 {
		t.Fatal("the idle pool reported no utilization at all")
	}
	for _, pct := range idle {
		if pct > 10 {
			t.Errorf("a pool whose one connection sits idle between fast queries read %d%%: %v", pct, idle)
			break
		}
	}

	starved := poolReadings(t, tr, collector, w, "starved")
	if len(starved) == 0 {
		t.Fatal("the starved pool reported no utilization at all")
	}
	highest := int32(0)
	for _, pct := range starved {
		highest = max(highest, pct)
	}
	if highest < 80 {
		t.Errorf("a pool eight callers queue on read at most %d%%: %v", highest, starved)
	}
	shared := poolReadings(t, tr, collector, w, "shared")
	if len(shared) == 0 {
		t.Fatal("the shared pool reported no utilization at all")
	}
	for _, pct := range shared {
		if pct > 60 {
			t.Errorf("a pool eight callers share for 1ms every 50ms read %d%%: %v", pct, shared)
			break
		}
	}

	for _, pct := range append(append(idle, starved...), shared...) {
		if pct < 0 || pct > 100 {
			t.Errorf("a utilization of %d%%: concurrent acquisitions must never push the mean past 100", pct)
		}
	}
	t.Logf("idle %v, starved %v, shared %v", idle, starved, shared)
}
