// Package safeelf parses attacker-controlled ELF binaries, a traced pod's
// own executable and debug files, within hard resource caps and with panic
// recovery, so a hostile binary cannot OOM or crash the privileged agent.
package safeelf

import (
	"debug/elf"
	"fmt"
	"os"
	"strings"
	"syscall"

	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/logger"
)

const (
	MaxFileSize = int64(1) << 30 // 1 GiB

	MaxSectionSize = uint64(512) << 20 // 512 MiB

	MaxDWARFTotalSize = uint64(512) << 20 // 512 MiB

	// MaxSymbolTableSize bounds .symtab and .dynsym, which debug/elf expands
	// to roughly four times their size as []elf.Symbol.
	MaxSymbolTableSize = uint64(64) << 20 // 64 MiB
)

// OpenRegular opens path for reading only when it is a regular file within
// MaxFileSize. The open is non-blocking, so a FIFO or device planted under a
// library's name cannot hang the caller.
func OpenRegular(path string) (*os.File, os.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0) // #nosec G304 -- callers pass paths already confined to the target's rootfs; this open only checks the file type.
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, fmt.Errorf("%q is not a regular file", path)
	}
	if fi.Size() > MaxFileSize {
		_ = f.Close()
		return nil, nil, fmt.Errorf("elf %q too large to parse safely: %d bytes", path, fi.Size())
	}
	return f, fi, nil
}

// Open opens a fixed-path ELF (e.g. /proc/<pid>/exe) after rejecting
// oversized and non-regular files. The ELF is parsed from the file that was
// checked, not from a second lookup of path.
func Open(path string) (*elf.File, error) {
	f, _, err := OpenRegular(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return elf.Open(PinnedPath(f, path))
}

// SectionData returns sec.Data only when the section's declared size is within
// MaxSectionSize, so a lying/huge section header cannot drive a multi-GB
// allocation.
func SectionData(sec *elf.Section) ([]byte, error) {
	if sec == nil {
		return nil, nil
	}
	if sec.Size > MaxSectionSize {
		return nil, fmt.Errorf("section %q too large: %d bytes", sec.Name, sec.Size)
	}
	return sec.Data()
}

// SymbolSectionWithinCap reports whether the named symbol table is small
// enough to parse.
func SymbolSectionWithinCap(f *elf.File, section string) bool {
	sec := f.Section(section)
	return sec != nil && sec.Size <= MaxSymbolTableSize
}

// SymbolTablesWithinCap reports whether every symbol table f carries is small
// enough to parse; a file without one passes.
func SymbolTablesWithinCap(f *elf.File) bool {
	for _, name := range []string{".symtab", ".dynsym"} {
		if sec := f.Section(name); sec != nil && sec.Size > MaxSymbolTableSize {
			return false
		}
	}
	return true
}

// DWARFWithinCap reports whether the combined DWARF sections are within cap,
// bounding DWARF() memory (including decompression of .zdebug_*).
func DWARFWithinCap(f *elf.File) bool {
	var total uint64
	for _, s := range f.Sections {
		if strings.HasPrefix(s.Name, ".debug_") || strings.HasPrefix(s.Name, ".zdebug_") {
			total += s.Size
			if total > MaxDWARFTotalSize {
				return false
			}
		}
	}
	return true
}

// SafeDebugName reports whether a .gnu_debuglink filename is a plain basename.
func SafeDebugName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	return !strings.ContainsRune(name, '/') && !strings.ContainsRune(name, 0)
}

// RecoverParse converts a panic from an ELF/DWARF/gosym parser on a malformed
// untrusted binary into a logged warning so a hostile pod cannot crash the
// agent.
func RecoverParse(where string) {
	if r := recover(); r != nil {
		logger.Warn("recovered from panic parsing untrusted binary",
			zap.String("where", where), zap.Any("panic", r))
	}
}
