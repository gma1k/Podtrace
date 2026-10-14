package probes

import (
	"debug/buildinfo"
	"debug/dwarf"
	"fmt"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/ebpf/safeelf"
	"github.com/gma1k/podtrace/internal/logger"
)

// h3FieldOffsets mirrors struct h3_field_offsets in bpf/events.h: the offsets of
// the net/http fields the HTTP/3 uprobes read.
type h3FieldOffsets struct {
	Method uint32 // net/http.Request.Method
	URL    uint32 // net/http.Request.URL
	Path   uint32 // net/url.URL.Path
	Status uint32 // net/http.Response.StatusCode
}

// h3DefaultOffsets are the offsets for the supported Go range (1.17-1.26); they
// double as the in-BPF compile-time default and the version-table fallback.
var h3DefaultOffsets = h3FieldOffsets{Method: 0, URL: 16, Path: 56, Status: 16}

// h3GoMinMinor / h3GoMaxMinor bound the Go versions whose offsets we've verified.
const (
	h3GoMinMinor = 17
	h3GoMaxMinor = 26
)

const maxStructFieldOffset = 1 << 20

// resolveH3FieldOffsets resolves the field offsets for a target binary,
// preferring DWARF (exact for any Go version) and falling back to the
// version-keyed defaults for stripped binaries.
func resolveH3FieldOffsets(exePath string, pid uint32) (h3FieldOffsets, string) {
	if off, ok := h3OffsetsFromDWARF(exePath, pid); ok {
		return off, "dwarf"
	}
	return h3OffsetsForGoVersion(exePath)
}

// h3OffsetsFromDWARF reads the four field offsets from the binary's DWARF (or a
// build-id debug-info file).
func h3OffsetsFromDWARF(exePath string, pid uint32) (result h3FieldOffsets, ok bool) {
	defer recoverParse("h3OffsetsFromDWARF")
	target, err := openELFCapped(exePath)
	if err != nil {
		return h3FieldOffsets{}, false
	}
	defer func() { _ = target.Close() }()

	var d *dwarf.Data
	if dwarfWithinCap(target) {
		d, err = target.DWARF()
	} else {
		err = fmt.Errorf("dwarf sections exceed cap")
	}
	if err != nil {
		if dbg, _ := openDebugInfo(target, pid); dbg != nil && dbg != target {
			defer func() { _ = dbg.Close() }()
			if dwarfWithinCap(dbg) {
				d, err = dbg.DWARF()
			}
		}
		if err != nil || d == nil {
			return h3FieldOffsets{}, false
		}
	}

	type want struct {
		dst   *uint32
		found bool
	}
	fields := map[string]map[string]*want{
		"net/http.Request":  {"Method": {dst: nil}, "URL": {dst: nil}},
		"net/url.URL":       {"Path": {dst: nil}},
		"net/http.Response": {"StatusCode": {dst: nil}},
	}
	var off h3FieldOffsets
	fields["net/http.Request"]["Method"].dst = &off.Method
	fields["net/http.Request"]["URL"].dst = &off.URL
	fields["net/url.URL"]["Path"].dst = &off.Path
	fields["net/http.Response"]["StatusCode"].dst = &off.Status

	r := d.Reader()
	for {
		ent, err := r.Next()
		if err != nil || ent == nil {
			break
		}
		if ent.Tag != dwarf.TagStructType {
			continue
		}
		name, _ := ent.Val(dwarf.AttrName).(string)
		members, ok := fields[name]
		if !ok {
			continue
		}
		if decl, _ := ent.Val(dwarf.AttrDeclaration).(bool); decl {
			continue
		}
		for {
			c, err := r.Next()
			if err != nil || c == nil || c.Tag == 0 {
				break
			}
			if c.Tag != dwarf.TagMember {
				continue
			}
			mn, _ := c.Val(dwarf.AttrName).(string)
			w, ok := members[mn]
			if !ok {
				continue
			}
			loc, _ := c.Val(dwarf.AttrDataMemberLoc).(int64)
			if loc < 0 || loc > maxStructFieldOffset {
				continue
			}
			if w.found {
				if *w.dst != uint32(loc) {
					return h3FieldOffsets{}, false
				}
				continue
			}
			*w.dst = uint32(loc)
			w.found = true
		}
	}
	for _, members := range fields {
		for _, w := range members {
			if !w.found {
				return h3FieldOffsets{}, false
			}
		}
	}
	return off, true
}

// h3OffsetsForGoVersion returns the version-keyed offsets (currently constant
// across the supported range) and logs when the binary's Go version is outside
// the verified window.
func h3OffsetsForGoVersion(exePath string) (h3FieldOffsets, string) {
	bi, ok := readGoBuildInfo(exePath)
	if !ok {
		return h3DefaultOffsets, "default"
	}
	if minor, ok := goMinorVersion(bi.GoVersion); ok && (minor < h3GoMinMinor || minor > h3GoMaxMinor) {
		logger.Debug("HTTP/3 offsets: Go version outside verified range, using best-known offsets",
			zap.String("go_version", bi.GoVersion))
	}
	return h3DefaultOffsets, "version:" + bi.GoVersion
}

// readGoBuildInfo reads a Go executable's build information from a regular
// file within the ELF size cap.
func readGoBuildInfo(exePath string) (info *buildinfo.BuildInfo, ok bool) {
	defer recoverParse("readGoBuildInfo")
	f, _, err := safeelf.OpenRegular(exePath)
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	bi, err := buildinfo.Read(f)
	if err != nil {
		return nil, false
	}
	return bi, true
}

// goMinorVersion parses the minor version from a "go1.23.4" string.
func goMinorVersion(v string) (int, bool) {
	v = strings.TrimPrefix(v, "go")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return 0, false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, false
	}
	return minor, true
}
