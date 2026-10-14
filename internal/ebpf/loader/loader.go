package loader

import (
	"bytes"
	"errors"

	"github.com/cilium/ebpf"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/ebpf/embedded"
)

var errOverrideUnderSecureExec = errors.New("PODTRACE_BPF_OBJECT is not honoured when podtrace runs with file capabilities or setuid; " +
	"run it as root to load a different object")

var embeddedObject = embedded.EmbeddedPodtraceBPFObj

var errNoEmbeddedUnderSecureExec = errors.New("this build has no embedded BPF object and will not load one from the working directory " +
	"while running with file capabilities or setuid; build with -tags embed_bpf (make build)")

// LoadPodtrace returns the podtrace BPF collection spec.
func LoadPodtrace() (*ebpf.CollectionSpec, error) {
	path := config.BPFObjectPath
	explicit := path != config.DefaultBPFObjectPath()

	if explicit {
		if secureExec() {
			return nil, NewLoadError(path, errOverrideUnderSecureExec)
		}
		return loadFile(path)
	}
	if len(embeddedObject) > 0 {
		spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(embeddedObject))
		if err != nil {
			return nil, NewLoadError("the embedded object", err)
		}
		return spec, nil
	}
	if secureExec() {
		return nil, NewLoadError(path, errNoEmbeddedUnderSecureExec)
	}
	return loadFile(path)
}

func loadFile(path string) (*ebpf.CollectionSpec, error) {
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, NewLoadError(path, err)
	}
	return spec, nil
}
