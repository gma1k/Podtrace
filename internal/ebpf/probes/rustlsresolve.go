package probes

import (
	"bytes"
	"debug/elf"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/logger"
)

// elfIsRust reports whether an ELF was produced by rustc, detected via the
// ".comment" section.
func elfIsRust(f *elf.File) bool {
	data, err := sectionDataCapped(f.Section(".comment"))
	if err != nil {
		return false
	}
	return bytes.Contains(data, []byte("rustc"))
}

// findSymbolContaining returns the virtual address of the first defined function
// symbol whose name contains every given substring.
func nameContainsAll(name string, subs ...string) bool {
	for _, s := range subs {
		if !strings.Contains(name, s) {
			return false
		}
	}
	return true
}

func findSymbolContaining(f *elf.File, subs ...string) (uint64, bool) {
	if !symbolSectionWithinCap(f, ".symtab") {
		return 0, false
	}
	syms, err := f.Symbols()
	if err != nil {
		return 0, false
	}
	for i := range syms {
		if syms[i].Value == 0 || elf.ST_TYPE(syms[i].Info) != elf.STT_FUNC {
			continue
		}
		if nameContainsAll(syms[i].Name, subs...) {
			return syms[i].Value, true
		}
	}
	return 0, false
}

var (
	rustlsWriteSymbolPattern = []string{"rustls", "Writer", "5write"}
	rustlsReadSymbolPattern  = []string{"rustls", "Reader", "4read"}
)

// AttachRustlsProbes attaches uprobes on rustls' plaintext boundary in a
// statically-linked Rust binary: <rustls::conn::Writer as io::Write>::write
// (outbound) and <rustls::conn::Reader as io::Read>::read (inbound), capturing
// HTTP/1.x, HTTP/2 and gRPC L7 over rustls TLS before encryption / after
// decryption.
func AttachRustlsProbes(coll *ebpf.Collection, pid uint32) (links []link.Link) {
	defer recoverParse("AttachRustlsProbes")
	if pid == 0 {
		return links
	}
	writeProg := coll.Programs["uprobe_rustls_write"]
	readProg := coll.Programs["uprobe_rustls_read"]
	readRetProg := coll.Programs["uretprobe_rustls_read"]
	if writeProg == nil || readProg == nil || readRetProg == nil {
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

	writeVaddr, okW := findSymbolContaining(f, rustlsWriteSymbolPattern...)
	readVaddr, okR := findSymbolContaining(f, rustlsReadSymbolPattern...)
	if !okW && !okR {
		if dbg, src := openDebugInfo(f, pid); dbg != nil {
			defer func() { _ = dbg.Close() }()
			writeVaddr, okW = findSymbolContaining(dbg, rustlsWriteSymbolPattern...)
			readVaddr, okR = findSymbolContaining(dbg, rustlsReadSymbolPattern...)
			if okW || okR {
				logger.Debug("rustls symbols resolved via debug file",
					zap.Uint32("pid", pid), zap.String("source", src))
			}
		}
	}
	if !okW && !okR {
		return links
	}

	exe, err := openExecutable(exePath)
	if err != nil {
		return links
	}
	defer func() { _ = exe.Close() }()

	if okW {
		if off, ok := vaddrToFileOffset(f, writeVaddr); ok {
			if l, err := exe.Uprobe("", writeProg, &link.UprobeOptions{Address: off}); err == nil {
				links = append(links, l)
				logger.Debug("rustls write uprobe attached", zap.Uint32("pid", pid), zap.Uint64("offset", off))
			} else {
				logger.Debug("rustls write uprobe not attached", zap.Uint32("pid", pid), zap.Error(err))
			}
		}
	}
	if okR {
		if off, ok := vaddrToFileOffset(f, readVaddr); ok {
			if l, err := exe.Uprobe("", readProg, &link.UprobeOptions{Address: off}); err == nil {
				links = append(links, l)
			}
			if l, err := exe.Uretprobe("", readRetProg, &link.UprobeOptions{Address: off}); err == nil {
				links = append(links, l)
			}
			logger.Debug("rustls read uprobes attached", zap.Uint32("pid", pid), zap.Uint64("offset", off))
		}
	}
	return links
}
