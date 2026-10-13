package events

import "testing"

func TestLockContentionIsErrorOnlyForRealFutexFailures(t *testing.T) {
	cases := []struct {
		name string
		code int32
		want bool
	}{
		{"acquired", 0, false},
		{"woke waiters", 3, false},
		{"value changed before the wait", -11, false},
		{"timed wait expired", -110, false},
		{"interrupted by a signal", -4, false},
		{"restarted after a signal", -512, false},
		{"restarted without interrupt", -513, false},
		{"restarted without handler", -514, false},
		{"restart block", -516, false},
		{"bad address", -14, true},
		{"invalid argument", -22, true},
		{"deadlock", -35, true},
		{"owner died", -130, true},
	}
	for _, tc := range cases {
		e := &Event{Type: EventLockContention, Error: tc.code}
		if got := e.IsError(); got != tc.want {
			t.Errorf("%s (%d): IsError = %v, want %v", tc.name, tc.code, got, tc.want)
		}
	}
}

func TestKernelRestartCodesAreNeverErrors(t *testing.T) {
	for _, typ := range []EventType{EventTCPRecv, EventTCPSend, EventConnect, EventRead, EventLockContention} {
		for _, code := range []int32{-512, -513, -514, -516} {
			if (&Event{Type: typ, Error: code}).IsError() {
				t.Errorf("type %d with %d counted as an error; the kernel restarts the call", typ, code)
			}
		}
		if !(&Event{Type: typ, Error: -104}).IsError() && typ != EventLockContention {
			t.Errorf("type %d with ECONNRESET must still be an error", typ)
		}
	}
	if !(&Event{Type: EventTCPRecv, Error: -511}).IsError() || !(&Event{Type: EventTCPRecv, Error: -517}).IsError() {
		t.Error("only 512-516 are restart codes")
	}
}
