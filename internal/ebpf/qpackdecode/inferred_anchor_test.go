package qpackdecode

import (
	"fmt"
	"testing"
)

func encodePrefixed(value uint64, prefixBits uint, flags byte) []byte {
	mask := uint64(1)<<prefixBits - 1
	if value < mask {
		return []byte{flags | byte(value)}
	}
	out := []byte{flags | byte(mask)}
	value -= mask
	for value >= 0x80 {
		out = append(out, byte(value&0x7f)|0x80)
		value >>= 7
	}
	return append(out, byte(value))
}

func insertLiterals(t *testing.T, d *Decoder, count int) {
	t.Helper()
	for i := 0; i < count; i++ {
		name := fmt.Sprintf("k%05d", i)
		instruction := append([]byte{0x40 | byte(len(name))}, name...)
		instruction = append(instruction, 0x01, 'v')
		if err := d.ParseEncoderStream(instruction); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
}

func sectionReferencingNewest(requiredInsertCount, decoderMaxEntries uint64) []byte {
	encoded := requiredInsertCount%(2*decoderMaxEntries) + 1
	section := encodePrefixed(encoded, 8, 0)
	return append(section, 0x00, 0x80)
}

func TestCapacityAcceptedBeforeAnySettings(t *testing.T) {
	d := NewDecoder(0)
	if err := d.ParseEncoderStream(encodePrefixed(4096, 5, 0x20)); err != nil {
		t.Fatalf("Set Dynamic Table Capacity 4096 rejected with unknown decoder SETTINGS: %v", err)
	}
	insertLiterals(t, d, 3)
	fields, err := d.DecodeFieldSection(sectionReferencingNewest(3, 4096/entryOverhead))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	expectFields(t, fields, HeaderField{Name: "k00002", Value: "v"})
}

func TestRequiredInsertCountWithDecoderSettingsAboveEncoderCapacity(t *testing.T) {
	const decoderSettings = 65536
	for _, inserts := range []int{300, 5000} {
		d := NewDecoder(0)
		if err := d.ParseEncoderStream(encodePrefixed(4096, 5, 0x20)); err != nil {
			t.Fatalf("set capacity: %v", err)
		}
		insertLiterals(t, d, inserts)
		section := sectionReferencingNewest(uint64(inserts), decoderSettings/entryOverhead)
		fields, err := d.DecodeFieldSection(section)
		if err != nil {
			t.Fatalf("%d inserts: decode: %v", inserts, err)
		}
		expectFields(t, fields, HeaderField{Name: fmt.Sprintf("k%05d", inserts-1), Value: "v"})
	}
}

func TestEncodedInsertCountBeyondKnownSettingsRangeRejected(t *testing.T) {
	d := NewDecoder(220)
	if err := d.ParseEncoderStream(mustHex(t, "3fbd01")); err != nil {
		t.Fatalf("set capacity: %v", err)
	}
	if _, err := d.DecodeFieldSection([]byte{0x0d, 0x00, 0x80}); err == nil {
		t.Fatal("encoded insert count 13 beyond full range 12 of known SETTINGS accepted")
	}
}
