package loader

import (
	"github.com/cilium/ebpf"

	"github.com/podtrace/podtrace/internal/config"
)

func LoadPodtrace() (*ebpf.CollectionSpec, error) {
	spec, err := ebpf.LoadCollectionSpec(config.BPFObjectPath)
	if err != nil {
		spec, err = ebpf.LoadCollectionSpec("../" + config.BPFObjectPath)
		if err != nil {
			return nil, NewLoadError(config.BPFObjectPath, err)
		}
	}

	return spec, nil
}
