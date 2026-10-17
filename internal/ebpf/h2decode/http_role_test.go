package h2decode

import (
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func exchange(t *testing.T, requestDir uint8) (req, resp *events.Event) {
	t.Helper()
	d := New()
	reqEnc, respEnc := newBlockEncoder(), newBlockEncoder()
	req = singleEvent(t, d.Ingest(rec(5, requestDir, 0, 1, reqEnc.encode(reqFields("GET", "/orders")...))))
	resp = singleEvent(t, d.Ingest(rec(5, otherDirection(requestDir), 0, 1, respEnc.encode(hf(":status", "200")))))
	return req, resp
}

func TestH2ResponseSentIsTheServerSide(t *testing.T) {
	req, resp := exchange(t, DirIngress)
	if req.HTTPRole() != events.HTTPRoleServer || resp.HTTPRole() != events.HTTPRoleServer {
		t.Errorf("request received, response sent: roles = %v/%v, want server", req.HTTPRole(), resp.HTTPRole())
	}
	if resp.HTTPTransport() != events.HTTPTransportH2C || resp.HTTPProtoLabel() != "HTTP/2" {
		t.Errorf("role bits disturbed the transport: %d %q", resp.HTTPTransport(), resp.HTTPProtoLabel())
	}
}

func TestH2ResponseReceivedIsTheClientSide(t *testing.T) {
	req, resp := exchange(t, DirEgress)
	if req.HTTPRole() != events.HTTPRoleClient || resp.HTTPRole() != events.HTTPRoleClient {
		t.Errorf("request sent, response received: roles = %v/%v, want client", req.HTTPRole(), resp.HTTPRole())
	}
	if !resp.IsClientL7Response() {
		t.Error("a response the process received is not reported as a client response")
	}
}

func TestGRPCCallServedIsTheServerSide(t *testing.T) {
	resp := responses(grpcCall(t, New(), 90, "0"))
	if len(resp) != 1 || resp[0].HTTPRole() != events.HTTPRoleServer {
		t.Fatalf("served gRPC call responses = %+v, want one server-role response", resp)
	}
}

func TestGRPCTrailersReceivedAreTheClientSide(t *testing.T) {
	d := New()
	reqEnc, respEnc := newBlockEncoder(), newBlockEncoder()
	d.Ingest(rec(91, DirEgress, 0, 1, reqEnc.encode(reqFields("POST", "/pkg.Svc/Do", grpcType)...)))
	evs := d.Ingest(rec(91, DirIngress, 0, 1, respEnc.encode(hf(":status", "200"), grpcType, hf("grpc-status", "0"))))
	resp := responses(evs)
	if len(resp) != 1 || resp[0].HTTPRole() != events.HTTPRoleClient {
		t.Fatalf("received gRPC response = %+v, want one client-role response", resp)
	}
}

func TestUnknownDirectionLeavesTheRoleUnknown(t *testing.T) {
	if requestRoleBits(7) != 0 || responseRoleBits(7) != 0 {
		t.Error("a direction the decoder does not know set a role")
	}
}
