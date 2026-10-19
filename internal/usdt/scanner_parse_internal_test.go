package usdt

import (
	"encoding/binary"
	"testing"
)

func note(order binary.ByteOrder, name string, typ uint32, desc []byte, nameSzOverride, descSzOverride int) []byte {
	nameBytes := append([]byte(name), 0)
	padName := nameBytes
	for len(padName)%4 != 0 {
		padName = append(padName, 0)
	}
	padDesc := desc
	for len(padDesc)%4 != 0 {
		padDesc = append(padDesc, 0)
	}
	nameSz := len(nameBytes)
	if nameSzOverride >= 0 {
		nameSz = nameSzOverride
	}
	descSz := len(desc)
	if descSzOverride >= 0 {
		descSz = descSzOverride
	}
	hdr := make([]byte, 12)
	order.PutUint32(hdr[0:], uint32(nameSz))
	order.PutUint32(hdr[4:], uint32(descSz))
	order.PutUint32(hdr[8:], typ)
	out := append(hdr, padName...)
	return append(out, padDesc...)
}

func stapsdtDesc(order binary.ByteOrder, pc, sem uint64, provider, probe string) []byte {
	d := make([]byte, 24)
	order.PutUint64(d[0:], pc)
	order.PutUint64(d[8:], 0) // base
	order.PutUint64(d[16:], sem)
	d = append(d, []byte(provider)...)
	d = append(d, 0)
	d = append(d, []byte(probe)...)
	d = append(d, 0)
	d = append(d, 0)
	return d
}

func TestParseStapsdtNotes_Valid(t *testing.T) {
	order := binary.ByteOrder(binary.LittleEndian)
	desc := stapsdtDesc(order, 0xDEADBEEF, 0xCAFE, "provider", "probe")
	data := note(order, "stapsdt", 3, desc, -1, -1)

	got := parseStapsdtNotes(data, order, hostArgArch())
	if len(got) != 1 {
		t.Fatalf("expected 1 probe, got %d", len(got))
	}
	p := got[0]
	if p.Provider != "provider" || p.Name != "probe" || p.PC != 0xDEADBEEF || p.SemAddr != 0xCAFE {
		t.Errorf("probe mismatch: %+v", p)
	}
}

func TestParseStapsdtNotes_HugeSizesNoPanic(t *testing.T) {
	order := binary.ByteOrder(binary.LittleEndian)
	desc := stapsdtDesc(order, 1, 2, "p", "n")

	cases := map[string][]byte{
		"huge namesz": note(order, "stapsdt", 3, desc, int(^uint32(0)), -1), // 0xFFFFFFFF
		"huge descsz": note(order, "stapsdt", 3, desc, -1, int(^uint32(0))),
		"both huge":   note(order, "stapsdt", 3, desc, int(^uint32(0)), int(^uint32(0))),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			got := parseStapsdtNotes(data, order, hostArgArch())
			if len(got) != 0 {
				t.Errorf("oversized note should yield no probes, got %d", len(got))
			}
		})
	}
}

func TestParseStapsdtNotes_TruncatedHeader(t *testing.T) {
	order := binary.ByteOrder(binary.LittleEndian)
	if got := parseStapsdtNotes([]byte{1, 2, 3, 4, 5, 6, 7, 8}, order, hostArgArch()); len(got) != 0 {
		t.Errorf("truncated header should yield no probes, got %d", len(got))
	}
	if got := parseStapsdtNotes(nil, order, hostArgArch()); len(got) != 0 {
		t.Errorf("nil data should yield no probes, got %d", len(got))
	}
}
