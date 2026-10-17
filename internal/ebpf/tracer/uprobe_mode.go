package tracer

import (
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/logger"
)

var haveUprobeMulti = func() bool { return features.HaveBPFLinkUprobeMulti() == nil }

// isUprobeProgram reports whether the spec is attached as a uprobe or a
// uretprobe.
func isUprobeProgram(p *ebpf.ProgramSpec) bool {
	if p == nil || p.Type != ebpf.Kprobe {
		return false
	}
	return strings.HasPrefix(p.SectionName, "uprobe") || strings.HasPrefix(p.SectionName, "uretprobe")
}

// wantUprobeMulti reports whether uprobe programs should be loaded for
// uprobe_multi links: PODTRACE_UPROBE_MULTI allows it and the kernel has them.
func wantUprobeMulti() bool {
	return config.UprobeMultiEnabled && haveUprobeMulti()
}

// setUprobeAttachType loads every uprobe program for uprobe_multi links, or
// back for classic ones. The kernel binds a program to its attach type at
// load, so this must run before the collection is created.
func setUprobeAttachType(spec *ebpf.CollectionSpec, multi bool) int {
	n := 0
	for _, p := range spec.Programs {
		if !isUprobeProgram(p) {
			continue
		}
		if multi {
			p.AttachType = ebpf.AttachTraceUprobeMulti
		} else {
			p.AttachType = ebpf.AttachNone
		}
		n++
	}
	return n
}

// newCollectionForUprobeMode creates the collection with uprobe programs
// loaded for uprobe_multi links when the kernel supports them. A load that
// fails in that mode is retried with classic uprobes, so a kernel that
// advertises uprobe_multi but refuses a program for it still gets an agent.
func newCollectionForUprobeMode(spec *ebpf.CollectionSpec, opts ebpf.CollectionOptions, create func(*ebpf.CollectionSpec, ebpf.CollectionOptions) (*ebpf.Collection, error)) (*ebpf.Collection, bool, error) {
	if wantUprobeMulti() && setUprobeAttachType(spec, true) > 0 {
		coll, err := create(spec, opts)
		if err == nil {
			return coll, true, nil
		}
		logger.Warn("Loading uprobe programs for uprobe_multi links failed; loading classic uprobes instead",
			zap.Error(err))
		setUprobeAttachType(spec, false)
	}
	coll, err := create(spec, opts)
	return coll, false, err
}
