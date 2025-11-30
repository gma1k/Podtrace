package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"
)

func loadPodtrace() (*ebpf.CollectionSpec, error) {
	spec, err := ebpf.LoadCollectionSpec("bpf/podtrace.bpf.o")
	if err != nil {
		spec, err = ebpf.LoadCollectionSpec("../bpf/podtrace.bpf.o")
		if err != nil {
			return nil, fmt.Errorf("failed to load eBPF program: %w", err)
		}
	}

	return spec, nil
}
