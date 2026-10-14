package probes

import (
	"debug/dwarf"
	"fmt"

	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/logger"
)

// poolFieldOffsets mirrors struct pool_field_offsets in bpf/events.h: the
// offsets of the database/sql.DB fields the pool uprobe reads.
type poolFieldOffsets struct {
	NumOpen  uint32 // database/sql.DB.numOpen  — connections currently open
	MaxOpen  uint32 // database/sql.DB.maxOpen  — SetMaxOpenConns, 0 means unlimited
	FreeConn uint32 // database/sql.DB.freeConn — the idle connections, a slice
}

// resolvePoolFieldOffsets reads the three field offsets from the target
// binary's DWARF. Utilization is the connections in use, open minus idle:
// counting open connections alone reads an idle pool at its ceiling as full.
//
// DWARF only, deliberately — unlike resolveH3FieldOffsets, there is no
// version-table fallback for stripped binaries. The h3 fields are strings and
// a wrong offset yields visible garbage; these are integers, and a wrong
// offset yields a plausible connection count that nothing downstream can
// tell from a real one. Reporting no utilization is recoverable; reporting a
// confident wrong number is not.
//
// Go keeps DWARF by default, so this covers any binary not built with
// -ldflags=-w, on any Go version, without a table to maintain.
func resolvePoolFieldOffsets(exePath string, pid uint32) (poolFieldOffsets, bool) {
	off, ok := poolOffsetsFromDWARF(exePath, pid)
	if !ok {
		logger.Debug("Pool utilization: no DWARF in target binary, utilization not reported",
			zap.String("path", exePath))
		return poolFieldOffsets{}, false
	}
	return off, true
}

// poolOffsetsFromDWARF reads database/sql.DB's field offsets from the
// binary's DWARF, or from a separate build-id debug-info file.
func poolOffsetsFromDWARF(exePath string, pid uint32) (result poolFieldOffsets, ok bool) {
	defer recoverParse("poolOffsetsFromDWARF")

	target, err := openELFCapped(exePath)
	if err != nil {
		return poolFieldOffsets{}, false
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
			return poolFieldOffsets{}, false
		}
	}

	var off poolFieldOffsets
	foundNumOpen, foundMaxOpen, foundFreeConn := false, false, false

	r := d.Reader()
	for {
		ent, err := r.Next()
		if err != nil || ent == nil {
			break
		}
		if ent.Tag != dwarf.TagStructType {
			continue
		}
		if name, _ := ent.Val(dwarf.AttrName).(string); name != "database/sql.DB" {
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
			loc, _ := c.Val(dwarf.AttrDataMemberLoc).(int64)
			if loc < 0 || loc > maxStructFieldOffset {
				continue
			}
			switch mn {
			case "numOpen":
				off.NumOpen, foundNumOpen = uint32(loc), true
			case "maxOpen":
				off.MaxOpen, foundMaxOpen = uint32(loc), true
			case "freeConn":
				off.FreeConn, foundFreeConn = uint32(loc), true
			}
		}
		break
	}

	if !foundNumOpen || !foundMaxOpen || !foundFreeConn {
		return poolFieldOffsets{}, false
	}
	return off, true
}
