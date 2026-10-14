package probes

import (
	"debug/dwarf"
	"strings"
)

// h3PeerStep / h3PeerPath / h3PeerPaths mirror the structs of the same name in
// bpf/events.h: a DWARF-resolved pointer walk from a hooked Go receiver to the
// quic connection's remote *net.UDPAddr.
type h3PeerStep struct {
	Off   uint32
	Iface uint8
	_     [3]uint8
}

const h3PeerMaxSteps = 6

type h3PeerPath struct {
	NSteps  uint8
	_       [3]uint8
	IPOff   uint32
	PortOff uint32
	Steps   [h3PeerMaxSteps]h3PeerStep
}

type h3PeerPaths struct {
	Client h3PeerPath
	Server h3PeerPath
}

const (
	h3ServerRootType = "github.com/quic-go/quic-go/http3.responseWriter"
	udpAddrType      = "net.UDPAddr"
)

// memberOffset32 validates a DWARF member offset and narrows it to the
// BPF-side u32, rejecting negative or implausibly large offsets rather than
// silently producing a wrong pointer-walk step.
func memberOffset32(off int64) (uint32, bool) {
	if off < 0 || off > maxStructFieldOffset {
		return 0, false
	}
	return uint32(off), true
}

// quicConnImplTypes are the concrete types behind quic-go's client connection
// when the hooked receiver holds it as an interface.
var quicConnImplTypes = []string{
	"github.com/quic-go/quic-go.Conn",
	"github.com/quic-go/quic-go.connection",
}

// sendConnImplTypes are the concrete types behind quic-go's internal sendConn
// interface.
var sendConnImplTypes = []string{"github.com/quic-go/quic-go.sconn"}

// resolveH3PeerPaths builds the client and server peer walks for a target
// binary.
func resolveH3PeerPaths(exePath string, pid uint32, clientRootType string) (paths h3PeerPaths, resolved bool) {
	defer recoverParse("resolveH3PeerPaths")
	d, closeFn, ok := openDWARF(exePath, pid)
	if !ok {
		return h3PeerPaths{}, false
	}
	defer closeFn()

	idx := indexDWARFStructs(d)

	if clientRootType != "" {
		clientPrefix := []string{"conn"}
		if strings.HasSuffix(clientRootType, ".SingleDestinationRoundTripper") {
			clientPrefix = []string{"Connection"}
		}
		if p, ok := buildH3PeerPath(d, idx, clientRootType, clientPrefix); ok {
			paths.Client = p
			resolved = true
		}
	}
	if p, ok := buildH3PeerPath(d, idx, h3ServerRootType, []string{"conn"}); ok {
		paths.Server = p
		resolved = true
	}
	return paths, resolved
}

// openDWARF opens the binary's DWARF, falling back to a build-id /
// .gnu_debuglink debug file.
func openDWARF(exePath string, pid uint32) (data *dwarf.Data, cleanup func(), ok bool) {
	defer recoverParse("openDWARF")
	target, err := openELFCapped(exePath)
	if err != nil {
		return nil, nil, false
	}
	if dwarfWithinCap(target) {
		if d, err := target.DWARF(); err == nil {
			return d, func() { _ = target.Close() }, true
		}
	}
	if dbg, _ := openDebugInfo(target, pid); dbg != nil && dbg != target {
		if dwarfWithinCap(dbg) {
			if d, err := dbg.DWARF(); err == nil {
				return d, func() { _ = dbg.Close(); _ = target.Close() }, true
			}
		}
		_ = dbg.Close()
	}
	_ = target.Close()
	return nil, nil, false
}

// indexDWARFStructs maps struct type names to their DWARF offsets.
func indexDWARFStructs(d *dwarf.Data) map[string]dwarf.Offset {
	idx := make(map[string]dwarf.Offset)
	r := d.Reader()
	for {
		ent, err := r.Next()
		if err != nil || ent == nil {
			break
		}
		if ent.Tag != dwarf.TagStructType {
			continue
		}
		if name, _ := ent.Val(dwarf.AttrName).(string); name != "" {
			if _, seen := idx[name]; !seen {
				idx[name] = ent.Offset
			}
		}
	}
	return idx
}

func structByName(d *dwarf.Data, idx map[string]dwarf.Offset, name string) *dwarf.StructType {
	off, ok := idx[name]
	if !ok {
		return nil
	}
	t, err := d.Type(off)
	if err != nil {
		return nil
	}
	st, _ := t.(*dwarf.StructType)
	return st
}

// buildH3PeerPath walks from a root receiver struct to net.UDPAddr. prefix is
// the member chain to reach the quic connection struct; nil means the single
// member "conn" on the root.
func buildH3PeerPath(d *dwarf.Data, idx map[string]dwarf.Offset, rootType string,
	prefix []string) (h3PeerPath, bool) {
	root := structByName(d, idx, rootType)
	if root == nil {
		return h3PeerPath{}, false
	}
	if prefix == nil {
		prefix = []string{"conn"}
	}

	var steps []h3PeerStep
	cur := root
	for hop := 0; hop < 3 && cur != nil && !hasMember(cur, "conn", isGoInterfaceType); hop++ {
		name := "conn"
		if hop < len(prefix) {
			name = prefix[hop]
		}
		next, step, ok := followMember(d, idx, cur, name, quicConnImplTypes)
		if !ok {
			return h3PeerPath{}, false
		}
		steps = append(steps, step)
		cur = next
	}
	if cur == nil || !hasMember(cur, "conn", isGoInterfaceType) {
		return h3PeerPath{}, false
	}

	sconn, step, ok := followMember(d, idx, cur, "conn", sendConnImplTypes)
	if !ok {
		return h3PeerPath{}, false
	}
	steps = append(steps, step)

	udp := structByName(d, idx, udpAddrType)
	if udp == nil {
		return h3PeerPath{}, false
	}
	if f := findMember(sconn, "remoteAddrInfo"); f != nil {
		vOff, inner, ok := atomicPointerInfo(f.Type)
		if !ok {
			return h3PeerPath{}, false
		}
		fOff, ok := memberOffset32(f.ByteOffset)
		if !ok {
			return h3PeerPath{}, false
		}
		steps = append(steps, h3PeerStep{Off: fOff + vOff})
		rai := structByName(d, idx, inner)
		if rai == nil {
			return h3PeerPath{}, false
		}
		addr := findMember(rai, "addr")
		if addr == nil || !isGoInterfaceType(addr.Type) {
			return h3PeerPath{}, false
		}
		addrOff, ok := memberOffset32(addr.ByteOffset)
		if !ok {
			return h3PeerPath{}, false
		}
		steps = append(steps, h3PeerStep{Off: addrOff, Iface: 1})
	} else if f := findMember(sconn, "remoteAddr"); f != nil && isGoInterfaceType(f.Type) {
		fOff, ok := memberOffset32(f.ByteOffset)
		if !ok {
			return h3PeerPath{}, false
		}
		steps = append(steps, h3PeerStep{Off: fOff, Iface: 1})
	} else {
		return h3PeerPath{}, false
	}

	nsteps := len(steps)
	if nsteps <= 0 || nsteps > h3PeerMaxSteps {
		return h3PeerPath{}, false
	}
	ipField := findMember(udp, "IP")
	portField := findMember(udp, "Port")
	if ipField == nil || portField == nil {
		return h3PeerPath{}, false
	}
	ipOff, ok := memberOffset32(ipField.ByteOffset)
	if !ok {
		return h3PeerPath{}, false
	}
	portOff, ok := memberOffset32(portField.ByteOffset)
	if !ok {
		return h3PeerPath{}, false
	}

	var p h3PeerPath
	p.NSteps = uint8(nsteps)
	p.IPOff = ipOff
	p.PortOff = portOff
	copy(p.Steps[:], steps)
	return p, true
}

// followMember resolves one hop: a pointer member is followed to its target
// struct; an interface member is followed to the first implementing candidate
// present in the binary.
func followMember(d *dwarf.Data, idx map[string]dwarf.Offset, st *dwarf.StructType,
	name string, implCandidates []string) (*dwarf.StructType, h3PeerStep, bool) {
	f := findMember(st, name)
	if f == nil {
		return nil, h3PeerStep{}, false
	}
	off, ok := memberOffset32(f.ByteOffset)
	if !ok {
		return nil, h3PeerStep{}, false
	}
	t := stripType(f.Type)
	if pt, ok := t.(*dwarf.PtrType); ok {
		if target, ok := stripType(pt.Type).(*dwarf.StructType); ok {
			return target, h3PeerStep{Off: off}, true
		}
		return nil, h3PeerStep{}, false
	}
	if isGoInterfaceType(f.Type) {
		for _, cand := range implCandidates {
			if impl := structByName(d, idx, cand); impl != nil {
				return impl, h3PeerStep{Off: off, Iface: 1}, true
			}
		}
	}
	return nil, h3PeerStep{}, false
}

func findMember(st *dwarf.StructType, name string) *dwarf.StructField {
	for _, f := range st.Field {
		if f.Name == name {
			return f
		}
	}
	return nil
}

func hasMember(st *dwarf.StructType, name string, typeCheck func(dwarf.Type) bool) bool {
	f := findMember(st, name)
	return f != nil && (typeCheck == nil || typeCheck(f.Type))
}

// maxTypeWrappers bounds how many typedef and qualifier wrappers stripType
// peels. debug/dwarf caches a typedef before resolving its target, so a
// typedef that names itself, or a cycle of them, never bottoms out.
const maxTypeWrappers = 16

// stripType removes typedef and qualifier wrappers, returning nil when they
// do not end within maxTypeWrappers.
func stripType(t dwarf.Type) dwarf.Type {
	for range maxTypeWrappers {
		switch v := t.(type) {
		case *dwarf.TypedefType:
			t = v.Type
		case *dwarf.QualType:
			t = v.Type
		default:
			return t
		}
	}
	return nil
}

// isGoInterfaceType reports whether a member type is a Go interface (iface or
// eface): a 16-byte two-word struct whose second word is "data".
func isGoInterfaceType(t dwarf.Type) bool {
	st, ok := stripType(t).(*dwarf.StructType)
	if !ok || len(st.Field) != 2 {
		return false
	}
	return st.Field[1].Name == "data" &&
		(st.Field[0].Name == "tab" || st.Field[0].Name == "_type")
}

// atomicPointerInfo returns the offset of the pointer word inside a
// sync/atomic.Pointer[T] member and T's type name.
func atomicPointerInfo(t dwarf.Type) (uint32, string, bool) {
	st, ok := stripType(t).(*dwarf.StructType)
	if !ok || !strings.HasPrefix(st.StructName, "sync/atomic.Pointer[") ||
		!strings.HasSuffix(st.StructName, "]") {
		return 0, "", false
	}
	inner := st.StructName[len("sync/atomic.Pointer[") : len(st.StructName)-1]
	for _, f := range st.Field {
		if f.Name == "v" {
			if off, ok := memberOffset32(f.ByteOffset); ok {
				return off, inner, true
			}
			return 0, "", false
		}
	}
	return 0, "", false
}
