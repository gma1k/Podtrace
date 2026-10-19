// Package usdt provides ELF USDT (Userspace Statically Defined Tracing) probe
// discovery by parsing .note.stapsdt sections in ELF binaries.
package usdt

import (
	"debug/elf"
	"encoding/binary"
	"fmt"

	"github.com/gma1k/podtrace/internal/ebpf/safeelf"
)

// Probe represents a single USDT probe found in an ELF binary.
type Probe struct {
	Provider string
	Name     string
	PC       uint64
	SemAddr  uint64
	Args     []Arg
}

const maxScannedProbes = 4096

// Scan parses the .note.stapsdt section of exePath and returns all USDT probes.
// Returns nil, nil when no USDT probes are present.
func Scan(exePath string) (probes []Probe, err error) {
	defer safeelf.RecoverParse("usdt.Scan")

	f, err := safeelf.Open(exePath)
	if err != nil {
		return nil, fmt.Errorf("usdt: open %q: %w", exePath, err)
	}
	defer func() { _ = f.Close() }()

	return ScanFile(f)
}

// ScanFile parses the .note.stapsdt notes of an already-open ELF and returns
// its USDT probes.
func ScanFile(f *elf.File) ([]Probe, error) {
	data, err := safeelf.SectionData(f.Section(".note.stapsdt"))
	if err != nil {
		return nil, fmt.Errorf("usdt: read .note.stapsdt: %w", err)
	}
	if data == nil {
		return nil, nil
	}
	return parseStapsdtNotes(data, f.ByteOrder, argArchForMachine(f.Machine)), nil
}

// parseStapsdtNotes walks the .note.stapsdt note stream and returns the USDT
// probes it declares. data is attacker-controlled.
func parseStapsdtNotes(data []byte, order binary.ByteOrder, arch argArch) []Probe {
	var probes []Probe
	dlen := uint64(len(data))
	var offset uint64
	for offset+12 <= dlen {
		if len(probes) >= maxScannedProbes {
			break
		}
		nameSz := uint64(order.Uint32(data[offset:]))
		descSz := uint64(order.Uint32(data[offset+4:]))
		noteType := order.Uint32(data[offset+8:])
		offset += 12

		namePad := align4(nameSz)
		descPad := align4(descSz)
		if offset+namePad+descPad > dlen {
			break
		}
		rawName := data[offset : offset+nameSz]
		if nameSz > 0 && rawName[nameSz-1] == 0 {
			rawName = rawName[:nameSz-1]
		}
		offset += namePad

		desc := data[offset : offset+descSz]
		offset += descPad

		if noteType != 3 || string(rawName) != "stapsdt" {
			continue
		}
		if len(desc) < 24 {
			continue
		}

		pc := order.Uint64(desc[0:])
		semAddr := order.Uint64(desc[16:])

		provider, rest, ok := cstring(desc[24:])
		if !ok {
			continue
		}
		probeName, rest, ok := cstring(rest)
		if !ok {
			continue
		}
		argDesc, _, _ := cstring(rest)

		probes = append(probes, Probe{
			Provider: provider,
			Name:     probeName,
			PC:       pc,
			SemAddr:  semAddr,
			Args:     parseArgDescFor(argDesc, arch),
		})
	}
	return probes
}

// align4 rounds n up to the next multiple of 4 in the uint64 domain. n is at
// most a uint32 promoted to uint64, so n+3 cannot overflow.
func align4(n uint64) uint64 {
	return (n + 3) &^ 3
}

func cstring(b []byte) (string, []byte, bool) {
	for i, c := range b {
		if c == 0 {
			return string(b[:i]), b[i+1:], true
		}
	}
	return "", nil, false
}
