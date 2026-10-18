package status

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/google/pprof/profile"

	"github.com/gma1k/podtrace/internal/profiling"
)

// StackFormat is a flame-graph format an agent's /profile serves.
type StackFormat string

const (
	StackFormatFolded StackFormat = "folded"
	StackFormatPprof  StackFormat = "pprof"
)

// ErrNoStacks reports that no agent had stacks for the workload asked for.
var ErrNoStacks = errors.New("no agent has stacks for this workload yet")

// WriteStacks reads one workload's whole stacks from every agent, merges the
// nodes, and writes them in format: folded lines summed stack by stack, or
// one pprof profile merged from each node's.
func (c *Collector) WriteStacks(ctx context.Context, w io.Writer, format StackFormat, sel profiling.StackSelection) ([]string, error) {
	agents, err := c.agents(ctx)
	if err != nil {
		return nil, fmt.Errorf("list podtrace agents: %w", err)
	}
	var (
		mu     sync.Mutex
		bodies [][]byte
		failed []string
	)
	sem := c.semaphore()
	var wg sync.WaitGroup
	for _, a := range agents {
		wg.Add(1)
		go func(a Agent) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			actx, cancel := context.WithTimeout(ctx, orDefault(c.ProfileWait, defaultProfileWait))
			defer cancel()
			raw, err := c.Cluster.ProfileStacks(actx, a, format, sel)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed = append(failed, fmt.Sprintf("no stacks from %s on %s: %s", a.Name, a.Node, oneLine(err.Error())))
				return
			}
			bodies = append(bodies, raw)
		}(a)
	}
	wg.Wait()

	if format == StackFormatPprof {
		return failed, writeMergedPprof(w, bodies)
	}
	return failed, writeMergedFolded(w, bodies)
}

func writeMergedFolded(w io.Writer, bodies [][]byte) error {
	stacks, err := profiling.ParseFolded(bytes.NewReader(bytes.Join(bodies, []byte("\n"))))
	if err != nil {
		return fmt.Errorf("read folded stacks: %w", err)
	}
	if len(stacks) == 0 {
		return ErrNoStacks
	}
	return profiling.WriteFolded(w, stacks)
}

func writeMergedPprof(w io.Writer, bodies [][]byte) error {
	var profiles []*profile.Profile
	for _, raw := range bodies {
		if len(raw) == 0 {
			continue
		}
		p, err := profile.ParseData(raw)
		if err != nil {
			return fmt.Errorf("read pprof profile: %w", err)
		}
		if len(p.Sample) > 0 {
			profiles = append(profiles, p)
		}
	}
	if len(profiles) == 0 {
		return ErrNoStacks
	}
	merged, err := profile.Merge(profiles)
	if err != nil {
		return fmt.Errorf("merge pprof profiles: %w; nodes whose profiles come from different sources cannot be merged, use -o folded", err)
	}
	return merged.Write(w)
}
