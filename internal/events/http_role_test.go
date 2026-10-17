package events

import "testing"

func TestHTTPRoleDecodesTheRoleBits(t *testing.T) {
	cases := []struct {
		state uint32
		want  HTTPRole
	}{
		{HTTPTransportTLS, HTTPRoleUnknown},
		{HTTPTransportTLS | HTTPRoleServerBit, HTTPRoleUnknown},
		{HTTPTransportTLS | HTTPRoleBits(false), HTTPRoleClient},
		{HTTPTransportH2TLS | HTTPRoleBits(true), HTTPRoleServer},
		{HTTPTransportH3 | HTTPRoleBits(true), HTTPRoleServer},
	}
	for _, tc := range cases {
		e := &Event{Type: EventHTTPResp, TCPState: tc.state}
		if got := e.HTTPRole(); got != tc.want {
			t.Errorf("TCPState %#x: role = %v, want %v", tc.state, got, tc.want)
		}
	}
}

func TestHTTPRoleNames(t *testing.T) {
	for role, want := range map[HTTPRole]string{
		HTTPRoleUnknown: "unknown",
		HTTPRoleClient:  "client",
		HTTPRoleServer:  "server",
	} {
		if got := role.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", role, got, want)
		}
	}
}

func TestRoleBitsLeaveTransportLabelsUnchanged(t *testing.T) {
	transports := []uint32{HTTPTransportPlaintext, HTTPTransportTLS, HTTPTransportH2C, HTTPTransportH2TLS, HTTPTransportH3}
	for _, transport := range transports {
		bare := &Event{Type: EventHTTPResp, TCPState: transport}
		for _, bits := range []uint32{HTTPRoleBits(false), HTTPRoleBits(true)} {
			withRole := &Event{Type: EventHTTPResp, TCPState: transport | bits}
			if withRole.HTTPTransport() != transport {
				t.Errorf("HTTPTransport(%#x) = %d, want %d", withRole.TCPState, withRole.HTTPTransport(), transport)
			}
			if withRole.HTTPProtoLabel() != bare.HTTPProtoLabel() {
				t.Errorf("HTTPProtoLabel(%#x) = %q, want %q", withRole.TCPState, withRole.HTTPProtoLabel(), bare.HTTPProtoLabel())
			}
			if withRole.HTTPScheme() != bare.HTTPScheme() {
				t.Errorf("HTTPScheme(%#x) = %q, want %q", withRole.TCPState, withRole.HTTPScheme(), bare.HTTPScheme())
			}
		}
	}
}

func TestL7ResponseRolePredicates(t *testing.T) {
	cases := []struct {
		typ            EventType
		state          uint32
		client, server bool
	}{
		{EventHTTPResp, HTTPRoleBits(false), true, false},
		{EventHTTPResp, HTTPRoleBits(true), false, true},
		{EventHTTPResp, 0, false, false},
		{EventGRPCMethod, HTTPRoleBits(false), true, false},
		{EventGRPCMethod, HTTPRoleBits(true), false, true},
		{EventHTTPReq, HTTPRoleBits(false), false, false},
		{EventRedisCmd, HTTPRoleBits(false), false, false},
	}
	for _, tc := range cases {
		e := &Event{Type: tc.typ, TCPState: tc.state}
		if got := e.IsClientL7Response(); got != tc.client {
			t.Errorf("type %d state %#x: IsClientL7Response = %v, want %v", tc.typ, tc.state, got, tc.client)
		}
		if got := e.IsServerL7Response(); got != tc.server {
			t.Errorf("type %d state %#x: IsServerL7Response = %v, want %v", tc.typ, tc.state, got, tc.server)
		}
	}
}
