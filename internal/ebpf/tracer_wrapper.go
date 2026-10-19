package ebpf

import (
	"github.com/gma1k/podtrace/internal/ebpf/tracer"
)

type TracerInterface = tracer.TracerInterface

// Option re-exports the tracer's startup options so callers outside this
// package can gate probe groups before the ring-buffer reader starts.
type Option = tracer.Option

var WithInitialCategories = tracer.WithInitialCategories

type ContainerProbeTarget = tracer.ContainerProbeTarget

type CgroupOwner = tracer.CgroupOwner

func NewTracer(opts ...Option) (TracerInterface, error) {
	return tracer.NewTracer(opts...)
}

func WaitForInterrupt() {
	tracer.WaitForInterrupt()
}
