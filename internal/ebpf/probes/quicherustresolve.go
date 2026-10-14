package probes

import (
	"debug/elf"
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/logger"
)

var quicheRustSendRequestPattern = []string{"6quiche", "2h3", "12send_request"}

const maxQuicheRustAttachments = 4

// findSymbolsContaining returns the virtual addresses of up to max defined
// function symbols whose names contain every given substring.
func findSymbolsContaining(f *elf.File, max int, subs ...string) []uint64 {
	if !symbolSectionWithinCap(f, ".symtab") {
		return nil
	}
	syms, err := f.Symbols()
	if err != nil {
		return nil
	}
	var out []uint64
	for i := range syms {
		if syms[i].Value == 0 || elf.ST_TYPE(syms[i].Info) != elf.STT_FUNC {
			continue
		}
		if nameContainsAll(syms[i].Name, subs...) {
			out = append(out, syms[i].Value)
			if len(out) >= max {
				break
			}
		}
	}
	return out
}

// AttachQuicheRustProbes attaches a uprobe on
// quiche::h3::Connection::send_request in a statically-linked Rust binary.
func AttachQuicheRustProbes(coll *ebpf.Collection, pid uint32) (links []link.Link) {
	defer recoverParse("AttachQuicheRustProbes")
	if pid == 0 || runtime.GOARCH != "amd64" {
		return links
	}
	prog := coll.Programs["uprobe_quiche_rs_send_request"]
	if prog == nil {
		return links
	}

	exePath := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "exe")
	f, err := openELFCapped(exePath)
	if err != nil {
		return links
	}
	defer func() { _ = f.Close() }()
	if !elfIsRust(f) {
		return links
	}

	vaddrs := findSymbolsContaining(f, maxQuicheRustAttachments, quicheRustSendRequestPattern...)
	if len(vaddrs) == 0 {
		if dbg, src := openDebugInfo(f, pid); dbg != nil {
			defer func() { _ = dbg.Close() }()
			vaddrs = findSymbolsContaining(dbg, maxQuicheRustAttachments, quicheRustSendRequestPattern...)
			if len(vaddrs) > 0 {
				logger.Debug("quiche crate symbols resolved via debug file",
					zap.Uint32("pid", pid), zap.String("source", src))
			}
		}
	}
	if len(vaddrs) == 0 {
		return links
	}

	exe, err := openExecutable(exePath)
	if err != nil {
		return links
	}
	defer func() { _ = exe.Close() }()
	for _, vaddr := range vaddrs {
		off, ok := vaddrToFileOffset(f, vaddr)
		if !ok {
			continue
		}
		if l, err := exe.Uprobe("", prog, &link.UprobeOptions{Address: off}); err == nil {
			links = append(links, l)
			logger.Debug("quiche crate send_request uprobe attached",
				zap.Uint32("pid", pid), zap.Uint64("offset", off))
		} else {
			logger.Debug("quiche crate send_request uprobe not attached",
				zap.Uint32("pid", pid), zap.Error(err))
		}
	}
	return links
}
