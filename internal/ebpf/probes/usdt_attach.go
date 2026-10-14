package probes

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/ebpf/safeelf"
	"github.com/gma1k/podtrace/internal/logger"
	"github.com/gma1k/podtrace/internal/usdt"
)

// usdtArgValue mirrors `struct usdt_arg` in bpf/maps.h (16 bytes with the
// 4-byte pad the C compiler inserts before the 8-byte disp).
type usdtArgValue struct {
	Size   int8
	Kind   uint8
	RegOff uint16
	_      [4]byte
	Disp   int64
}

// usdtProbeValue mirrors `struct usdt_probe` in bpf/maps.h. Field sizes MUST
// match USDT_PROVIDER_LEN / USDT_NAME_LEN / USDT_MAX_ARGS there (200 bytes).
type usdtProbeValue struct {
	Provider [64]byte
	Name     [64]byte
	NArgs    uint8
	_        [7]byte
	Args     [usdt.MaxArgs]usdtArgValue
}

var usdtCookieSeq atomic.Uint64

// usdtCookie names one probe site. It is derived from the file and the probe
// address, so every container attaching the same probe in the same binary
// arrives at the same uprobe site and shares it.
func usdtCookie(exe *executable, addr uint64) uint64 {
	if !exe.shared {
		return usdtCookieSeq.Add(1) | 1<<63
	}
	h := fnv.New64a()
	var buf [32]byte
	binary.LittleEndian.PutUint64(buf[0:], exe.id.ino)
	binary.LittleEndian.PutUint64(buf[8:], uint64(exe.id.size))     // #nosec G115 -- hashed, not interpreted.
	binary.LittleEndian.PutUint64(buf[16:], uint64(exe.id.mtimeNs)) // #nosec G115 -- hashed, not interpreted.
	binary.LittleEndian.PutUint64(buf[24:], addr)
	_, _ = h.Write(buf[:])
	_, _ = h.Write([]byte(exe.id.buildID))
	return h.Sum64() &^ (1 << 63)
}

const maxUSDTProbesPerBinary = 256

// AttachUSDTProbes discovers the USDT probes in the target pid's executable and
// attaches uprobe_usdt at each probe PC, enabling the SDT semaphore when one is
// present (and the kernel supports ref_ctr_offset).
func AttachUSDTProbes(coll *ebpf.Collection, pid uint32) []link.Link {
	defer safeelf.RecoverParse("probes.AttachUSDTProbes")

	var links []link.Link
	if pid == 0 || !config.USDTEnabled {
		return links
	}
	prog := coll.Programs["uprobe_usdt"]
	pmap := usdtSpecMapOf(coll)
	if prog == nil || pmap == nil {
		return links
	}

	exePath := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "exe")
	f, err := safeelf.Open(exePath)
	if err != nil {
		return links
	}
	defer func() { _ = f.Close() }()

	found, err := usdt.ScanFile(f)
	if err != nil || len(found) == 0 {
		return links
	}

	exe, err := openExecutable(exePath)
	if err != nil {
		return links
	}
	defer func() { _ = exe.Close() }()

	semSupported := uprobeRefCtrOffsetSupported()
	for i := range found {
		if len(links) >= maxUSDTProbesPerBinary {
			logger.Debug("usdt probe cap reached; remaining probes skipped",
				zap.Uint32("pid", pid), zap.Int("cap", maxUSDTProbesPerBinary))
			break
		}
		p := found[i]
		addr, ok := vaddrToFileOffset(f, p.PC)
		if !ok {
			continue
		}

		cookie := usdtCookie(exe, addr)
		val := usdtProbeValue{}
		copyCString(val.Provider[:], p.Provider)
		copyCString(val.Name[:], p.Name)
		nargs := len(p.Args)
		if nargs > usdt.MaxArgs {
			nargs = usdt.MaxArgs
		}
		val.NArgs = uint8(nargs)
		for j := 0; j < nargs; j++ {
			val.Args[j] = usdtArgValue{
				Size:   p.Args[j].Size,
				Kind:   uint8(p.Args[j].Kind),
				RegOff: p.Args[j].RegOff,
				Disp:   p.Args[j].Disp,
			}
		}
		hooks := siteHooks{
			setup:    func() error { return usdtSpecs.hold(pmap, cookie, &val) },
			teardown: func() { usdtSpecs.release(pmap, cookie) },
		}

		opts := &link.UprobeOptions{Address: addr, Cookie: cookie}
		if p.SemAddr != 0 && semSupported {
			if semOff, ok := vaddrToFileOffset(f, p.SemAddr); ok {
				opts.RefCtrOffset = semOff
			}
		}

		l, err := exe.uprobeWithHooks(prog, opts, hooks)
		if err != nil && opts.RefCtrOffset != 0 {
			opts.RefCtrOffset = 0
			l, err = exe.uprobeWithHooks(prog, opts, hooks)
		}
		if err != nil {
			logger.Debug("usdt uprobe not attached",
				zap.Uint32("pid", pid), zap.String("probe", p.Provider+":"+p.Name), zap.Error(err))
			continue
		}
		links = append(links, l)
		logger.Debug("usdt uprobe attached",
			zap.Uint32("pid", pid), zap.String("probe", p.Provider+":"+p.Name),
			zap.Uint64("offset", addr), zap.Bool("semaphore", opts.RefCtrOffset != 0))
	}
	return links
}

// usdtSpecTable counts the uprobe sites using each usdt_probes entry, so an
// entry is deleted with the last site that reads it and never while one
// still does. Two sites share a cookie when the semaphore attach is retried
// without one.
type usdtSpecMap interface {
	Update(key, value any, flags ebpf.MapUpdateFlags) error
	Delete(key any) error
}

type usdtSpecTable struct {
	mu    sync.Mutex
	users map[uint64]int
}

var usdtSpecs = &usdtSpecTable{users: map[uint64]int{}}

// usdtSpecMapOf returns the collection's usdt_probes map, or nil.
var usdtSpecMapOf = func(coll *ebpf.Collection) usdtSpecMap {
	if m := coll.Maps["usdt_probes"]; m != nil {
		return m
	}
	return nil
}

func (t *usdtSpecTable) hold(pmap usdtSpecMap, cookie uint64, val *usdtProbeValue) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.users[cookie] == 0 {
		if err := pmap.Update(cookie, val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("usdt map update: %w", err)
		}
	}
	t.users[cookie]++
	return nil
}

func (t *usdtSpecTable) release(pmap usdtSpecMap, cookie uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.users[cookie]--
	if t.users[cookie] > 0 {
		return
	}
	delete(t.users, cookie)
	_ = pmap.Delete(cookie)
}

// copyCString copies s into dst as a NUL-terminated C string, reserving the
// final byte for the terminator and truncating longer names.
func copyCString(dst []byte, s string) {
	if len(dst) == 0 {
		return
	}
	n := copy(dst[:len(dst)-1], s)
	dst[n] = 0
}

var (
	refCtrOnce      sync.Once
	refCtrSupported bool
)

// uprobeRefCtrOffsetSupported reports whether the kernel exposes SDT semaphore
// (ref_ctr_offset) management for uprobes. Checked once.
func uprobeRefCtrOffsetSupported() bool {
	refCtrOnce.Do(func() {
		_, err := os.Stat("/sys/bus/event_source/devices/uprobe/format/ref_ctr_offset")
		refCtrSupported = err == nil
	})
	return refCtrSupported
}
