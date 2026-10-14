package probes

import (
	"bytes"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/logger"
)

// sslOffsets holds the file offsets (within the target executable) of the TLS
// read/write entry points, suitable for link.UprobeOptions.Address, plus a
// label describing how they were resolved.
type sslOffsets struct {
	write  uint64
	read   uint64
	source string
}

// resolveSSLOffsets locates SSL_write/SSL_read in a statically-linked,
// symbol-stripped executable that executableExportsSSL could not gate (no
// SSL_write in .symtab/.dynsym).
func resolveSSLOffsets(exePath string, pid uint32) (off sslOffsets, ok bool) {
	defer recoverParse("resolveSSLOffsets")
	target, err := openELFCapped(exePath)
	if err != nil {
		return sslOffsets{}, false
	}
	defer func() { _ = target.Close() }()

	dbg, source := openDebugInfo(target, pid)
	if dbg == nil {
		return sslOffsets{}, false
	}
	defer func() { _ = dbg.Close() }()

	wv, okW := symbolVaddr(dbg, "SSL_write")
	rv, okR := symbolVaddr(dbg, "SSL_read")
	if !okW || !okR {
		return sslOffsets{}, false
	}
	wOff, okW := vaddrToFileOffset(target, wv)
	rOff, okR := vaddrToFileOffset(target, rv)
	if !okW || !okR {
		return sslOffsets{}, false
	}
	return sslOffsets{write: wOff, read: rOff, source: source}, true
}

// symbolVaddr returns the virtual address of a defined symbol from either the
// static or dynamic symbol table.
func symbolVaddr(f *elf.File, name string) (uint64, bool) {
	if symbolSectionWithinCap(f, ".symtab") {
		if syms, err := f.Symbols(); err == nil {
			for i := range syms {
				if syms[i].Name == name && syms[i].Value != 0 {
					return syms[i].Value, true
				}
			}
		}
	}
	if symbolSectionWithinCap(f, ".dynsym") {
		if syms, err := f.DynamicSymbols(); err == nil {
			for i := range syms {
				if syms[i].Name == name && syms[i].Value != 0 {
					return syms[i].Value, true
				}
			}
		}
	}
	return 0, false
}

// openDebugInfo finds and opens a separate debug file for pid's executable
// within pid's own rootfs, returning the opened ELF and a source label, or
// (nil, "") if none is found. Every candidate is resolved inside that root,
// the executable's directory as the target itself sees it.
func openDebugInfo(target *elf.File, pid uint32) (*elf.File, string) {
	if pid == 0 {
		return nil, ""
	}
	root := procRoot(pid)

	if buildID := elfBuildID(target); len(buildID) > 2 {
		rel := filepath.Join("usr/lib/debug/.build-id", buildID[:2], buildID[2:]+".debug")
		if f, err := openELFWithinRoot(root, rel); err == nil {
			return f, "debug-buildid"
		}
	}
	if name := debugLink(target); safeDebugName(name) {
		var candidates []string
		if dir := executableDirInTarget(pid); dir != "" {
			candidates = append(candidates,
				filepath.Join(dir, name),
				filepath.Join(dir, ".debug", name),
				filepath.Join("usr/lib/debug", dir, name),
			)
		}
		candidates = append(candidates, filepath.Join("usr/lib/debug", name))
		for _, rel := range candidates {
			if f, err := openELFWithinRoot(root, rel); err == nil {
				return f, "debug-link"
			}
		}
	}
	return nil, ""
}

// executableDirInTarget returns the directory of pid's executable as the
// target sees it in its own mount namespace, or "" when it cannot be read.
func executableDirInTarget(pid uint32) string {
	target, err := os.Readlink(filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "exe"))
	if err != nil {
		return ""
	}
	target = strings.TrimSuffix(target, " (deleted)")
	if !filepath.IsAbs(target) {
		return ""
	}
	return filepath.Dir(target)
}

// elfBuildID parses the GNU build-id (.note.gnu.build-id) into a lowercase hex
// string, or "" if absent.
func elfBuildID(f *elf.File) string {
	data, err := sectionDataCapped(f.Section(".note.gnu.build-id"))
	if err != nil || len(data) < 12 {
		return ""
	}
	namesz := f.ByteOrder.Uint32(data[0:4])
	descsz := f.ByteOrder.Uint32(data[4:8])
	nameEnd := 12 + int((namesz+3)&^uint32(3))
	if descsz == 0 || nameEnd+int(descsz) > len(data) {
		return ""
	}
	return hex.EncodeToString(data[nameEnd : nameEnd+int(descsz)])
}

// debugLink returns the filename recorded in .gnu_debuglink, or "".
func debugLink(f *elf.File) string {
	data, err := sectionDataCapped(f.Section(".gnu_debuglink"))
	if err != nil {
		return ""
	}
	if i := bytes.IndexByte(data, 0); i > 0 {
		return string(data[:i])
	}
	return ""
}

// attachSSLByOffset attaches the SSL_write/SSL_read uprobes (and the SSL_read
// uretprobe) to the target executable at resolved file offsets, used when no
// symbol is available for the linker to bind against.
func attachSSLByOffset(coll *ebpf.Collection, exePath string, off sslOffsets) []link.Link {
	exe, err := openExecutable(exePath)
	if err != nil {
		return nil
	}
	defer func() { _ = exe.Close() }()
	var links []link.Link
	attach := func(progName string, addr uint64, ret bool) {
		prog := coll.Programs[progName]
		if prog == nil {
			return
		}
		var l link.Link
		var aerr error
		if ret {
			l, aerr = exe.Uretprobe("", prog, &link.UprobeOptions{Address: addr})
		} else {
			l, aerr = exe.Uprobe("", prog, &link.UprobeOptions{Address: addr})
		}
		if aerr == nil {
			links = append(links, l)
		} else {
			logger.Debug("TLS offset attach failed", zap.String("prog", progName), zap.Error(aerr))
		}
	}
	attach("uprobe_SSL_write", off.write, false)
	attach("uretprobe_SSL_write", off.write, true)
	attach("uprobe_SSL_read", off.read, false)
	attach("uretprobe_SSL_read", off.read, true)
	return links
}
