package h3decode

import (
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func TestH3RoleFollowsIsClient(t *testing.T) {
	for _, tc := range []struct {
		isClient bool
		want     events.HTTPRole
	}{
		{true, events.HTTPRoleClient},
		{false, events.HTTPRoleServer},
	} {
		tx, ok := ParseRecord(buildRecord(1_000_000, 200, tc.isClient, "GET", "/hello"))
		if !ok {
			t.Fatal("ParseRecord rejected the record")
		}
		for _, ev := range tx.Events() {
			if ev.HTTPRole() != tc.want {
				t.Errorf("isClient=%v type=%d: role = %v, want %v", tc.isClient, ev.Type, ev.HTTPRole(), tc.want)
			}
			if ev.HTTPTransport() != events.HTTPTransportH3 || ev.HTTPProtoLabel() != "HTTP/3" {
				t.Errorf("role bits disturbed the transport: %d %q", ev.HTTPTransport(), ev.HTTPProtoLabel())
			}
		}
	}
}
