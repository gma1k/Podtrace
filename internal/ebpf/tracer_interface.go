package ebpf

import (
	"context"

	"github.com/podtrace/podtrace/internal/events"
)

type TracerInterface interface {
	AttachToCgroup(cgroupPath string) error
	SetContainerID(containerID string) error
	Start(ctx context.Context, eventChan chan<- *events.Event) error
	Stop() error
}

