//go:build bpf_loadtest && linux

package tracer

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/gma1k/podtrace/internal/events"
)

type rawCodec struct{}

func (rawCodec) Marshal(v any) ([]byte, error) { return *(v.(*[]byte)), nil }
func (rawCodec) Unmarshal(data []byte, v any) error {
	*(v.(*[]byte)) = append([]byte(nil), data...)
	return nil
}
func (rawCodec) Name() string { return "raw" }

func echo(_ any, stream grpc.ServerStream) error {
	var msg []byte
	if err := stream.RecvMsg(&msg); err != nil {
		return err
	}
	out := []byte("ok")
	return stream.SendMsg(&out)
}

func TestKernelALongLivedGRPCConnectionStaysDecodable(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot raise memlock: %v", err)
	}
	tr, err := NewTracer()
	if err != nil {
		t.Skipf("cannot load the podtrace object here: %v", err)
	}
	t.Cleanup(func() { _ = tr.Stop() })
	tr.attachGlobalProtocolProbesOnce()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan *events.Event, 1<<16)
	if err := tr.Start(ctx, ch); err != nil {
		t.Fatalf("Start: %v", err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.ForceServerCodec(rawCodec{}), grpc.UnknownServiceHandler(echo))
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(rawCodec{})))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	const calls = 3000
	for i := 0; i < calls; i++ {
		in, out := []byte("hi"), []byte{}
		if err := conn.Invoke(ctx, "/demo.Demo/Fast", &in, &out); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	time.Sleep(time.Second)

	st := tr.h2Decoder.Stats()
	if st.DecodeErrors != 0 || st.GapsSkipped != 0 {
		t.Errorf("after %d calls on one connection: %+v", calls, st)
	}
	named := 0
	for drained := false; !drained; {
		select {
		case ev := <-ch:
			if ev.Type == events.EventHTTPResp && ev.Target == "POST /demo.Demo/Fast" {
				named++
			}
		default:
			drained = true
		}
	}
	if named < calls {
		t.Errorf("%d of %d calls were decoded with their method, server and client side together", named, calls)
	}
}
