package loader

import (
	"bytes"

	"github.com/cilium/ebpf"

	podtrace "github.com/podtrace/podtrace"
	"github.com/podtrace/podtrace/internal/config"
)

func LoadPodtrace() (*ebpf.CollectionSpec, error) {
	spec, err := ebpf.LoadCollectionSpec(config.BPFObjectPath)
	if err != nil {
		spec, err = ebpf.LoadCollectionSpec("../" + config.BPFObjectPath)
		if err != nil {
			if config.BPFObjectPath == "bpf/podtrace.bpf.o" && len(podtrace.EmbeddedPodtraceBPFObj) > 0 {
				if embeddedSpec, embeddedErr := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(podtrace.EmbeddedPodtraceBPFObj)); embeddedErr == nil {
					return embeddedSpec, nil
				}
			}
			return nil, NewLoadError(config.BPFObjectPath, err)
		}
	}

	return spec, nil
}
