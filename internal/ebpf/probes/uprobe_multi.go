package probes

import (
	"sync/atomic"

	"github.com/cilium/ebpf/link"
)

var uprobeMulti atomic.Bool

// SetUprobeMulti selects the attach path. The tracer calls it once, after it
// knows which attach type its uprobe programs were loaded with.
func SetUprobeMulti(on bool) { uprobeMulti.Store(on) }

// UprobeMultiEnabled reports whether uprobes are attached as uprobe_multi
// links.
func UprobeMultiEnabled() bool { return uprobeMulti.Load() }

// uprobeMultiArgs translates the classic attach arguments into the
// single-site uprobe_multi call that probes the same instruction: an explicit
// address plus offset, or a symbol plus offset, with the same reference
// counter offset, cookie and PID filter.
func uprobeMultiArgs(symbol string, opts *link.UprobeOptions) ([]string, *link.UprobeMultiOptions) {
	multi := &link.UprobeMultiOptions{}
	if opts == nil {
		return []string{symbol}, multi
	}
	var symbols []string
	if opts.Address != 0 {
		multi.Addresses = []uint64{opts.Address + opts.Offset}
	} else {
		symbols = []string{symbol}
		if opts.Offset != 0 {
			multi.Offsets = []uint64{opts.Offset}
		}
	}
	if opts.RefCtrOffset != 0 {
		multi.RefCtrOffsets = []uint64{opts.RefCtrOffset}
	}
	if opts.Cookie != 0 {
		multi.Cookies = []uint64{opts.Cookie}
	}
	if opts.PID > 0 {
		multi.PID = uint32(opts.PID)
	}
	return symbols, multi
}
