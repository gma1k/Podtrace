package tracer

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"github.com/gma1k/podtrace/internal/events"
)

// Config tunes Engine behaviour. Defaults are applied by NewEngine when a
// zero value is passed. Every field is operationally significant:
type Config struct {
	EventBufferSize int

	ExportBatchSize int

	ExportFlushInterval time.Duration

	ShutdownFlushTimeout time.Duration

	Observer EngineObserver
}

// EngineStats is a point-in-time counter snapshot. Thread-safe snapshot is
// exposed via Engine.Stats.
type EngineStats struct {
	EventsReceived  int64
	EventsExported  int64
	EventsDropped   int64
	ActiveTargets   int
	ExporterFailure int64
	AttachFailure   int64
	CgroupsAttached int64
	CgroupsDetached int64
}

// Engine orchestrates a TracerBackend + Exporters over a stream of
// TargetSet snapshots.
type Engine interface {
	Run(ctx context.Context, targets <-chan TargetSet) error

	Stats() EngineStats
}

// cgroupState is the engine's remembered identity for an attached cgroup
// path.
type cgroupState struct {
	containerID  string
	containerPID uint32
}

type engine struct {
	backend   TracerBackend
	exporters []Exporter
	cfg       Config

	mu              sync.RWMutex
	activeCgroups   map[string]cgroupState
	uprobeRetry     map[string]struct{}
	eventsReceived  int64
	eventsExported  int64
	eventsDropped   int64
	exporterFailure int64
	attachFailure   int64
	cgroupsAttached int64
	cgroupsDetached int64
}

// attachError pairs a backend reconcile stage with the error it produced, so
// the engine can report both to a TargetErrorObserver after releasing its
// lock.
type attachError struct {
	stage string
	err   error
}

// NewEngine composes a backend and a set of exporters into a runnable
// engine. At least one exporter is required; backend must be non-nil.
func NewEngine(backend TracerBackend, exporters []Exporter, cfg Config) (Engine, error) {
	if backend == nil {
		return nil, errors.New("tracer: backend is required")
	}
	if len(exporters) == 0 {
		return nil, errors.New("tracer: at least one exporter is required")
	}
	if cfg.EventBufferSize <= 0 {
		cfg.EventBufferSize = 10_000
	}
	if cfg.ExportBatchSize <= 0 {
		cfg.ExportBatchSize = 256
	}
	if cfg.ExportFlushInterval <= 0 {
		cfg.ExportFlushInterval = time.Second
	}
	if cfg.ShutdownFlushTimeout <= 0 {
		cfg.ShutdownFlushTimeout = 10 * time.Second
	}
	return &engine{
		backend:       backend,
		exporters:     exporters,
		cfg:           cfg,
		activeCgroups: make(map[string]cgroupState),
		uprobeRetry:   make(map[string]struct{}),
	}, nil
}

func (e *engine) Run(ctx context.Context, targets <-chan TargetSet) error {
	if targets == nil {
		return errors.New("tracer: targets channel is required")
	}

	dispatchCtx, cancelDispatch := context.WithCancel(context.WithoutCancel(ctx))

	eventCh := make(chan *events.Event, e.cfg.EventBufferSize)
	if edo, ok := e.cfg.Observer.(EventDropObserver); ok {
		if dr, ok := e.backend.(DropReporter); ok {
			dr.SetDropReporter(edo.OnEventsDropped)
		}
	}
	if err := e.backend.Start(ctx, eventCh); err != nil {
		cancelDispatch()
		return fmt.Errorf("tracer: backend start: %w", err)
	}

	dispatchDone := make(chan struct{})
	go func() {
		defer close(dispatchDone)
		e.dispatchLoop(dispatchCtx, eventCh)
	}()

	shutdown := func() {
		_ = e.backend.Stop()
		cancelDispatch()
		<-dispatchDone
		e.closeExporters()
	}

	for {
		select {
		case <-ctx.Done():
			shutdown()
			return nil
		case set, ok := <-targets:
			if !ok {
				shutdown()
				return nil
			}
			_ = e.applyTargets(set)
		}
	}
}

// applyTargets reconciles the engine's view of attached cgroups with the
// requested TargetSet via a single backend snapshot replace.
func (e *engine) applyTargets(set TargetSet) error {
	desired := make(map[string]Target, len(set))
	snapshot := make([]CgroupTarget, 0, len(set))
	for _, t := range set {
		if t.CgroupPath == "" {
			continue
		}
		if _, dup := desired[t.CgroupPath]; dup {
			continue
		}
		desired[t.CgroupPath] = t
		snapshot = append(snapshot, CgroupTarget{
			CgroupPath:  t.CgroupPath,
			ContainerID: t.ContainerID,
			PodName:     t.PodName,
			Namespace:   t.Namespace,
		})
	}

	e.mu.Lock()
	added, removed, changed, retry := 0, 0, 0, 0
	for path, t := range desired {
		prev, ok := e.activeCgroups[path]
		if !ok {
			added++
			continue
		}
		if prev.containerID != t.ContainerID || prev.containerPID != t.ContainerPID {
			changed++
		}
	}
	for path := range e.activeCgroups {
		if _, ok := desired[path]; !ok {
			removed++
		}
	}
	for _, t := range desired {
		if _, ok := e.uprobeRetry[t.ContainerID]; ok && t.ContainerID != "" {
			retry++
		}
	}
	e.mu.Unlock()

	cgroupsChanged := added != 0 || removed != 0 || changed != 0
	if !cgroupsChanged && retry == 0 {
		return nil
	}

	var attachErrs []attachError
	failedIDs := make(map[string]struct{})

	if cgroupsChanged {
		if err := e.backend.SetCgroups(snapshot); err != nil {
			e.mu.Lock()
			e.attachFailure++
			e.mu.Unlock()
			e.reportAttachErrors([]attachError{{stage: "set_cgroups", err: err}})
			return err
		}
	}

	if rec, ok := e.backend.(ContainerUprobeReconciler); ok {
		seen := make(map[string]struct{}, len(desired))
		cts := make([]ContainerUprobeTarget, 0, len(desired))
		for _, t := range desired {
			if t.ContainerID == "" {
				continue
			}
			if _, dup := seen[t.ContainerID]; dup {
				continue
			}
			seen[t.ContainerID] = struct{}{}
			cts = append(cts, ContainerUprobeTarget{ContainerID: t.ContainerID, PID: t.ContainerPID})
		}
		if err := rec.SetContainerTargets(cts); err != nil {
			attachErrs = append(attachErrs, attachError{stage: "set_container_targets", err: err})
			for _, ct := range cts {
				failedIDs[ct.ContainerID] = struct{}{}
			}
		}
	} else {
		seen := make(map[string]struct{}, len(desired))
		ids := make([]string, 0, len(desired))
		for _, t := range desired {
			if t.ContainerID == "" {
				continue
			}
			if _, dup := seen[t.ContainerID]; dup {
				continue
			}
			seen[t.ContainerID] = struct{}{}
			ids = append(ids, t.ContainerID)
		}
		if len(ids) > 0 {
			if multi, ok := e.backend.(interface {
				SetContainerIDs(containerIDs []string) error
			}); ok {
				if err := multi.SetContainerIDs(ids); err != nil {
					attachErrs = append(attachErrs, attachError{stage: "set_container_ids", err: err})
					for _, id := range ids {
						failedIDs[id] = struct{}{}
					}
				}
			} else {
				for _, id := range ids {
					if err := e.backend.SetContainerID(id); err != nil {
						attachErrs = append(attachErrs, attachError{stage: "set_container_id", err: err})
						failedIDs[id] = struct{}{}
					}
				}
			}
		}
	}

	next := make(map[string]cgroupState, len(desired))
	for path, t := range desired {
		next[path] = cgroupState{containerID: t.ContainerID, containerPID: t.ContainerPID}
	}
	e.mu.Lock()
	e.activeCgroups = next
	e.uprobeRetry = failedIDs
	e.cgroupsAttached += int64(added)
	e.cgroupsDetached += int64(removed)
	e.attachFailure += int64(len(attachErrs))
	e.mu.Unlock()

	e.reportAttachErrors(attachErrs)
	if obs := e.cfg.Observer; obs != nil {
		if added > 0 {
			obs.OnCgroupsAttached(added)
		}
		if removed > 0 {
			obs.OnCgroupsDetached(removed)
		}
	}
	return nil
}

// reportAttachErrors forwards each attach failure to the Observer if it
// implements TargetErrorObserver.
func (e *engine) reportAttachErrors(errs []attachError) {
	if len(errs) == 0 {
		return
	}
	teo, ok := e.cfg.Observer.(TargetErrorObserver)
	if !ok {
		return
	}
	for _, ae := range errs {
		teo.OnTargetError(ae.stage, ae.err)
	}
}

// exportRecovered hands one batch to one exporter, turning a panic into a
// failed export.
func (e *engine) exportRecovered(ctx context.Context, ex Exporter, batch []*events.Event) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("exporter %s panicked: %v", ex.Name(), r)
			if po, ok := e.cfg.Observer.(ExporterPanicObserver); ok {
				po.OnExporterPanic(ex.Name(), r, debug.Stack())
			}
		}
	}()
	return ex.Export(ctx, batch)
}

func (e *engine) dispatchLoop(ctx context.Context, eventCh <-chan *events.Event) {
	batch := make([]*events.Event, 0, e.cfg.ExportBatchSize)
	flush := func(flushCtx context.Context) {
		if len(batch) == 0 {
			return
		}
		delivered := len(e.exporters) == 0
		for _, ex := range e.exporters {
			if err := e.exportRecovered(flushCtx, ex, batch); err != nil {
				e.mu.Lock()
				e.exporterFailure++
				e.mu.Unlock()
			} else {
				delivered = true
			}
		}
		e.mu.Lock()
		if delivered {
			e.eventsExported += int64(len(batch))
		} else {
			e.eventsDropped += int64(len(batch))
		}
		e.mu.Unlock()
		batch = batch[:0]
	}

	shutdownFlush := func() {
		flushCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), e.cfg.ShutdownFlushTimeout)
		defer cancel()

	drain:
		for {
			select {
			case ev, ok := <-eventCh:
				if !ok {
					break drain
				}
				e.mu.Lock()
				e.eventsReceived++
				e.mu.Unlock()
				batch = append(batch, ev)
				if len(batch) >= e.cfg.ExportBatchSize {
					flush(flushCtx)
				}
			default:
				break drain
			}
		}
		flush(flushCtx)
	}

	ticker := time.NewTicker(e.cfg.ExportFlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			shutdownFlush()
			return
		case <-ticker.C:
			// Time-based flush so a partial batch from a low-traffic pod
			// is delivered promptly instead of waiting to reach
			// ExportBatchSize.
			flush(ctx)
		case ev, ok := <-eventCh:
			if !ok {
				shutdownFlush()
				return
			}
			e.mu.Lock()
			e.eventsReceived++
			e.mu.Unlock()
			batch = append(batch, ev)
			if len(batch) >= e.cfg.ExportBatchSize {
				flush(ctx)
			}
		}
	}
}

func (e *engine) closeExporters() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, ex := range e.exporters {
		_ = ex.Close(ctx)
	}
}

func (e *engine) Stats() EngineStats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return EngineStats{
		EventsReceived:  e.eventsReceived,
		EventsExported:  e.eventsExported,
		EventsDropped:   e.eventsDropped,
		ActiveTargets:   len(e.activeCgroups),
		ExporterFailure: e.exporterFailure,
		AttachFailure:   e.attachFailure,
		CgroupsAttached: e.cgroupsAttached,
		CgroupsDetached: e.cgroupsDetached,
	}
}
