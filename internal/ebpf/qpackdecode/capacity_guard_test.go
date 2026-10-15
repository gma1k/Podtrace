package qpackdecode

import "testing"

func TestSetCapacity_AcceptedWhenOwnSettingsUnknown(t *testing.T) {
	d := NewDecoder(0)
	if err := d.ParseEncoderStream(mustHex(t, "3fbd01")); err != nil {
		t.Fatalf("capacity 220 with unknown decoder SETTINGS must be accepted: %v", err)
	}
}

func TestSetCapacity_ZeroAllowedWithoutNegotiation(t *testing.T) {
	d := NewDecoder(0)
	if err := d.ParseEncoderStream([]byte{0x20}); err != nil {
		t.Fatalf("capacity 0 must be allowed with no SETTINGS: %v", err)
	}
}

func TestSetCapacity_ExceedingNegotiatedRejected(t *testing.T) {
	d := NewDecoder(100)
	if err := d.ParseEncoderStream(mustHex(t, "3fbd01")); err == nil {
		t.Fatal("capacity 220 exceeding negotiated SETTINGS max 100 must be rejected")
	}
}

func TestSetCapacity_BoundedByMaxTableCapacity(t *testing.T) {
	d := NewDecoder(1 << 30)
	if err := d.setCapacity(maxTableCapacity + 1); err == nil {
		t.Fatal("capacity above maxTableCapacity must be rejected")
	}
	if err := d.setCapacity(maxTableCapacity); err != nil {
		t.Fatalf("capacity at maxTableCapacity must be allowed: %v", err)
	}
}

func TestDuplicate_RejectsEntryExceedingCapacity(t *testing.T) {
	d := NewDecoder(220)
	if err := d.setCapacity(220); err != nil {
		t.Fatalf("set capacity: %v", err)
	}
	if err := d.insert("aa", "bb"); err != nil {
		t.Fatalf("seed insert: %v", err)
	}
	d.capacity = 1
	if err := d.ParseEncoderStream([]byte{0x00}); err == nil {
		t.Fatal("duplicating an entry larger than the current capacity must be rejected")
	}
}
