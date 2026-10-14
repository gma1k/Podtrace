package probes

import (
	"testing"
)

func TestOpenDWARFMissingFile(t *testing.T) {
	if _, _, ok := openDWARF("/no/such/binary/here", 0); ok {
		t.Error("expected openDWARF to fail for a missing file")
	}
}

func TestOpenDWARFFixture(t *testing.T) {
	bin := goFixtureBinary(t)
	d, cleanup, ok := openDWARF(bin, 0)
	if !ok {
		t.Fatal("expected openDWARF to succeed on a DWARF-bearing Go binary")
	}
	defer cleanup()
	if d == nil {
		t.Fatal("openDWARF returned nil data with ok=true")
	}
}

func TestIndexDWARFStructs(t *testing.T) {
	d, cleanup, idx := fixtureDWARF(t)
	defer cleanup()
	_ = d

	for _, name := range []string{"runtime.g", "runtime.m", "net/http.Request", "net/url.URL", "net.UDPAddr", "sync.Once"} {
		if _, ok := idx[name]; !ok {
			t.Errorf("expected struct %q in the DWARF index", name)
		}
	}
	if _, ok := idx["this.Type.Does.Not.Exist"]; ok {
		t.Error("index unexpectedly contains a bogus type")
	}
}

func TestStructByNameAndMembers(t *testing.T) {
	d, cleanup, idx := fixtureDWARF(t)
	defer cleanup()

	g := structByName(d, idx, "runtime.g")
	if g == nil {
		t.Fatal("runtime.g not resolved")
	}
	m := findMember(g, "m")
	if m == nil {
		t.Fatal("runtime.g.m member not found")
		return
	}
	if m.ByteOffset != 48 {
		t.Errorf("runtime.g.m offset = %d, want 48", m.ByteOffset)
	}
	if findMember(g, "no_such_member") != nil {
		t.Error("findMember returned a value for an absent member")
	}
	if !hasMember(g, "m", nil) {
		t.Error("hasMember should report m present")
	}
	if hasMember(g, "no_such_member", nil) {
		t.Error("hasMember should report an absent member as missing")
	}

	if structByName(d, idx, "this.Type.Does.Not.Exist") != nil {
		t.Error("structByName should return nil for an unknown type")
	}
}

func TestFollowMemberPointer(t *testing.T) {
	d, cleanup, idx := fixtureDWARF(t)
	defer cleanup()

	g := structByName(d, idx, "runtime.g")
	if g == nil {
		t.Fatal("runtime.g not resolved")
	}
	target, step, ok := followMember(d, idx, g, "m", nil)
	if !ok {
		t.Fatal("followMember failed to follow runtime.g.m pointer")
	}
	if step.Off != 48 || step.Iface != 0 {
		t.Errorf("step = %+v, want Off=48 Iface=0", step)
	}
	if target == nil || target.StructName != "runtime.m" {
		t.Errorf("followMember target = %v, want runtime.m", target)
	}

	if _, _, ok := followMember(d, idx, g, "no_such_member", nil); ok {
		t.Error("followMember must fail for an absent member")
	}

	udp := structByName(d, idx, "net.UDPAddr")
	if udp == nil {
		t.Fatal("net.UDPAddr not resolved")
	}
	if _, _, ok := followMember(d, idx, udp, "Port", nil); ok {
		t.Error("followMember must fail for a non-pointer, non-interface member")
	}
}

func TestFollowMemberInterface(t *testing.T) {
	d, cleanup, idx := fixtureDWARF(t)
	defer cleanup()

	req := structByName(d, idx, "net/http.Request")
	if req == nil {
		t.Fatal("net/http.Request not resolved")
	}
	target, step, ok := followMember(d, idx, req, "Body", []string{"net.UDPAddr"})
	if !ok {
		t.Fatal("followMember failed to follow the Body interface to a candidate impl")
	}
	if step.Iface != 1 {
		t.Errorf("interface step Iface = %d, want 1", step.Iface)
	}
	if step.Off != 64 {
		t.Errorf("Body offset = %d, want 64", step.Off)
	}
	if target == nil || target.StructName != "net.UDPAddr" {
		t.Errorf("target = %v, want net.UDPAddr", target)
	}

	if _, _, ok := followMember(d, idx, req, "Body", []string{"no.such.Impl"}); ok {
		t.Error("followMember must fail when no candidate impl exists in the binary")
	}
}

func TestBuildH3PeerPathNoQuicTypes(t *testing.T) {
	d, cleanup, idx := fixtureDWARF(t)
	defer cleanup()

	if _, ok := buildH3PeerPath(d, idx, "this.Type.Does.Not.Exist", nil); ok {
		t.Error("buildH3PeerPath must fail when the root type is absent")
	}
	if _, ok := buildH3PeerPath(d, idx, "runtime.g", nil); ok {
		t.Error("buildH3PeerPath must fail when the root lacks the quic conn chain")
	}
}

func TestResolveH3PeerPathsNoQuicTypes(t *testing.T) {
	bin := goFixtureBinary(t)
	if _, ok := resolveH3PeerPaths(bin, 0, ""); ok {
		t.Error("resolveH3PeerPaths must fail on a binary without quic-go types")
	}
}

func TestResolveH3PeerPathsMissingFile(t *testing.T) {
	if _, ok := resolveH3PeerPaths("/no/such/binary", 0, "some.Root"); ok {
		t.Error("resolveH3PeerPaths must fail when the binary is missing")
	}
}

func TestMemberOffset32(t *testing.T) {
	if off, ok := memberOffset32(48); !ok || off != 48 {
		t.Errorf("memberOffset32(48) = (%d,%v), want (48,true)", off, ok)
	}
	if _, ok := memberOffset32(-1); ok {
		t.Error("memberOffset32 must reject a negative offset")
	}
	if _, ok := memberOffset32(maxStructFieldOffset + 1); ok {
		t.Error("memberOffset32 must reject an implausibly large offset")
	}
}
