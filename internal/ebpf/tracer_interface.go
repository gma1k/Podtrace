package ebpf

import "github.com/podtrace/podtrace/internal/events"

type TracerInterface interface {
	AttachToCgroup(cgroupPath string) error
	SetContainerID(containerID string) error
	Start(eventChan chan<- *events.Event) error
	Stop() error
}

