package qpackdecode

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/net/http2/hpack"
)

func TestBlockedErrorMessage(t *testing.T) {
	e := &BlockedError{RequiredInsertCount: 5, InsertCount: 3}
	want := "qpackdecode: blocked field section: requires insert count 5, have 3"
	if got := e.Error(); got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}

func TestSetCapacityErrors(t *testing.T) {
	d := NewDecoder(0)
	if err := d.setCapacity(maxTableCapacity + 1); err == nil {
		t.Fatal("capacity beyond hard cap accepted")
	}
	d2 := NewDecoder(100)
	if err := d2.setCapacity(200); err == nil {
		t.Fatal("capacity exceeding SETTINGS maximum accepted")
	}
	if err := d2.setCapacity(50); err != nil {
		t.Fatalf("valid capacity rejected: %v", err)
	}
}

func TestEncoderStreamTooLarge(t *testing.T) {
	d := NewDecoder(0)
	big := make([]byte, maxEncoderRemainder+1)
	if err := d.ParseEncoderStream(big); err == nil {
		t.Fatal("oversized encoder chunk accepted")
	}
}

func TestEncoderStreamInstructionErrors(t *testing.T) {

	if err := NewDecoder(0).ParseEncoderStream([]byte{0x00}); err == nil {
		t.Fatal("duplicate of nonexistent entry accepted")
	}

	if err := NewDecoder(0).ParseEncoderStream([]byte{0xff, 0x28, 0x00}); err == nil {
		t.Fatal("insert referencing out-of-range static name accepted")
	}

	if err := NewDecoder(0).ParseEncoderStream([]byte{0xc0, 0x00}); err == nil {
		t.Fatal("insert into zero-capacity table accepted")
	}
}

func TestDynamicRepresentationForms(t *testing.T) {
	d := NewDecoder(200)

	if err := d.ParseEncoderStream(mustHex(t, "3fa901 416101 31 416201 32 416301 33")); err != nil {
		t.Fatalf("encoder stream: %v", err)
	}
	if d.InsertCount() != 3 {
		t.Fatalf("insert count = %d, want 3", d.InsertCount())
	}

	fields, err := d.DecodeFieldSection(mustHex(t, "0400 80 4101 39"))
	if err != nil {
		t.Fatalf("section 1: %v", err)
	}
	expectFields(t, fields,
		HeaderField{Name: "c", Value: "3"},
		HeaderField{Name: "b", Value: "9"})

	fields, err = d.DecodeFieldSection(mustHex(t, "0482 10 0101 7a"))
	if err != nil {
		t.Fatalf("section 2: %v", err)
	}
	expectFields(t, fields,
		HeaderField{Name: "a", Value: "1"},
		HeaderField{Name: "b", Value: "z"})
}

func TestDynamicReferenceStrictErrors(t *testing.T) {
	newTable := func(t *testing.T) *Decoder {
		d := NewDecoder(200)
		if err := d.ParseEncoderStream(mustHex(t, "3fa901 416101 31 416201 32 416301 33")); err != nil {
			t.Fatalf("encoder stream: %v", err)
		}
		return d
	}
	cases := map[string]string{
		"post-base indexed out of range":          "0400 15",
		"literal name ref without reachable base": "0400 4300",
		"post-base name ref out of range":         "0400 0500",
		"negative base underflow":                 "0485",
	}
	for name, in := range cases {
		if _, err := newTable(t).DecodeFieldSection(mustHex(t, in)); err == nil {
			t.Errorf("%s: decode succeeded, want error", name)
		}
	}
}

func TestReconstructRequiredInsertCountBranches(t *testing.T) {

	d := NewDecoder(0)
	var blocked *BlockedError
	if _, err := d.DecodeFieldSection([]byte{0x01, 0x00}); !errors.As(err, &blocked) {
		t.Fatalf("maxEntries==0 strict: err = %v, want BlockedError", err)
	}
	fields, unresolved, err := d.DecodeFieldSectionBestEffort([]byte{0x01, 0x00})
	if err != nil || len(fields) != 0 || unresolved != 0 {
		t.Fatalf("maxEntries==0 best-effort: fields=%v unresolved=%d err=%v", fields, unresolved, err)
	}

	full := NewDecoder(200)
	if err := full.ParseEncoderStream(mustHex(t, "3fa901 416101 31 416201 32 416301 33")); err != nil {
		t.Fatalf("encoder stream: %v", err)
	}
	if _, err := full.DecodeFieldSection([]byte{0x0d, 0x00}); err == nil {
		t.Fatal("encoded insert count beyond full range accepted")
	}
	if _, err := full.DecodeFieldSection([]byte{0x0b, 0x00}); err == nil {
		t.Fatal("invalid reconstructed required insert count accepted")
	}
}

func TestRequiredInsertCountWrapSubtracts(t *testing.T) {
	d := NewDecoder(220)
	if err := d.ParseEncoderStream(mustHex(t, "3fbd01")); err != nil {
		t.Fatalf("set capacity: %v", err)
	}
	for i := 0; i < 25; i++ {
		name := []byte{'k', byte('0' + i/10), byte('0' + i%10)}
		instruction := []byte{0x40 | byte(len(name))}
		instruction = append(instruction, name...)
		instruction = append(instruction, 0x01, 'v')
		if err := d.ParseEncoderStream(instruction); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}

	fields, err := d.DecodeFieldSection(mustHex(t, "0900 80"))
	if err != nil {
		t.Fatalf("wrap-subtract section: %v", err)
	}
	expectFields(t, fields, HeaderField{Name: "k19", Value: "v"})
}

func TestSectionErrorNonTruncated(t *testing.T) {
	d := NewDecoder(0)

	if _, err := d.DecodeFieldSection(mustHex(t, "0000 27 a146")); err == nil {
		t.Fatal("over-long literal name accepted")
	}
}

func TestReadPrefixedIntegerOverflow(t *testing.T) {
	buf := []byte{0x1f}
	for i := 0; i < 12; i++ {
		buf = append(buf, 0xff)
	}
	buf = append(buf, 0x00)
	if _, _, err := readPrefixedInteger(buf, 5); err == nil {
		t.Fatal("prefixed integer overflow not detected")
	}
}

func TestReadStringErrors(t *testing.T) {

	if _, _, err := readString([]byte{0x7f, 0xa9, 0x45}, 7, 0x80); err == nil {
		t.Fatal("over-long string length accepted")
	}

	if _, _, err := readString([]byte{0x84, 0xff, 0xff, 0xff, 0xff}, 7, 0x80); err == nil {
		t.Fatal("invalid Huffman payload accepted")
	}

	if _, _, err := readString([]byte{0x05, 'a'}, 7, 0x80); !errors.Is(err, errIncomplete) {
		t.Fatalf("truncated string: err = %v, want errIncomplete", err)
	}

	if _, _, err := readString([]byte{0x7f}, 7, 0x80); !errors.Is(err, errIncomplete) {
		t.Fatalf("truncated length varint: err = %v, want errIncomplete", err)
	}
}

func TestReadStringHuffmanDecodedTooLong(t *testing.T) {
	raw := hpack.AppendHuffmanString(nil, strings.Repeat("0", maxFieldLength+1))
	if len(raw) > maxFieldLength {
		t.Fatalf("compressed length %d already exceeds limit; test cannot isolate the decoded-size guard", len(raw))
	}

	var in []byte
	length := uint64(len(raw))
	if length < 127 {
		in = append(in, 0x80|byte(length))
	} else {
		in = append(in, 0x80|0x7f)
		length -= 127
		for length >= 128 {
			in = append(in, byte(length&0x7f)|0x80)
			length >>= 7
		}
		in = append(in, byte(length))
	}
	in = append(in, raw...)
	if _, _, err := readString(in, 7, 0x80); err == nil {
		t.Fatal("Huffman literal decoding beyond the field limit accepted")
	}
}

func TestEncoderInstructionTruncatedAndBadRefs(t *testing.T) {

	if err := NewDecoder(0).ParseEncoderStream([]byte{0xff}); err != nil {
		t.Fatalf("incomplete name-ref index should buffer, got %v", err)
	}

	if err := NewDecoder(0).ParseEncoderStream([]byte{0x80, 0x00}); err == nil {
		t.Fatal("insert referencing nonexistent dynamic name accepted")
	}

	if err := NewDecoder(0).ParseEncoderStream([]byte{0x1f}); err != nil {
		t.Fatalf("incomplete duplicate index should buffer, got %v", err)
	}

	if err := NewDecoder(0).ParseEncoderStream(mustHex(t, "3fe1ffff0f")); err == nil {
		t.Fatal("set-capacity beyond hard limit accepted")
	}
}

func TestDecodeFieldSectionTruncationAndStaticRange(t *testing.T) {
	cases := map[string]string{
		"truncated delta base":               "00 ff",
		"indexed dynamic without base":       "0400 85",
		"literal static name out of range":   "0000 5f6400",
		"literal-literal value truncated":    "0000 210161",
		"post-base index truncated":          "0000 1f",
		"post-base name-ref index truncated": "0000 07",
		"post-base name-ref value truncated": "0000 0061",
	}
	for name, in := range cases {
		d := NewDecoder(200)
		if name == "indexed dynamic without base" {
			if err := d.ParseEncoderStream(mustHex(t, "3fa901 416101 31 416201 32 416301 33")); err != nil {
				t.Fatalf("%s: encoder stream: %v", name, err)
			}
		}
		if _, err := d.DecodeFieldSection(mustHex(t, in)); err == nil {
			t.Errorf("%s: decode succeeded, want error", name)
		}
	}
}

func TestBestEffortUnresolvedDynamicLiterals(t *testing.T) {
	newTable := func(t *testing.T) *Decoder {
		d := NewDecoder(200)
		if err := d.ParseEncoderStream(mustHex(t, "3fa901 416101 31 416201 32 416301 33")); err != nil {
			t.Fatalf("encoder stream: %v", err)
		}
		return d
	}

	_, unresolved, err := newTable(t).DecodeFieldSectionBestEffort(mustHex(t, "0400 4300"))
	if err != nil || unresolved != 1 {
		t.Fatalf("literal name ref best-effort: unresolved=%d err=%v", unresolved, err)
	}

	_, unresolved, err = newTable(t).DecodeFieldSectionBestEffort(mustHex(t, "0400 0500"))
	if err != nil || unresolved != 1 {
		t.Fatalf("post-base name ref best-effort: unresolved=%d err=%v", unresolved, err)
	}
}

func TestRequiredInsertCountZero(t *testing.T) {
	d := NewDecoder(200)
	if _, err := d.DecodeFieldSection([]byte{0x01, 0x00}); err == nil {
		t.Fatal("reconstructed required insert count 0 accepted")
	}
}
