package loader

import (
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/podtrace/podtrace/internal/config"
)

func LoadPodtrace() (*ebpf.CollectionSpec, error) {
	spec, err := ebpf.LoadCollectionSpec(config.BPFObjectPath)
	if err != nil {
		spec, err = ebpf.LoadCollectionSpec("../" + config.BPFObjectPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load eBPF program: %w", err)
		}
	}

	return spec, nil
}

