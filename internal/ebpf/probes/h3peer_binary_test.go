package probes

import (
	"os"
	"testing"
)

func TestResolveH3PeerPathsRealBinary(t *testing.T) {
	bin := os.Getenv("PODTRACE_TEST_QUICGO_BIN")
	if bin == "" {
		t.Skip("PODTRACE_TEST_QUICGO_BIN not set")
	}
	paths, ok := resolveH3PeerPaths(bin, 0, "github.com/quic-go/quic-go/http3.ClientConn")
	if !ok {
		t.Fatal("resolveH3PeerPaths failed")
	}
	if paths.Client.NSteps == 0 {
		t.Error("client peer path unresolved")
	}
	if paths.Server.NSteps == 0 {
		t.Error("server peer path unresolved")
	}
	t.Logf("client: nsteps=%d ip_off=%d port_off=%d steps=%+v",
		paths.Client.NSteps, paths.Client.IPOff, paths.Client.PortOff, paths.Client.Steps)
	t.Logf("server: nsteps=%d ip_off=%d port_off=%d steps=%+v",
		paths.Server.NSteps, paths.Server.IPOff, paths.Server.PortOff, paths.Server.Steps)
}

func TestGoFuncReturnOffsetsRealBinaries(t *testing.T) {
	symbols := []string{
		"github.com/quic-go/quic-go/http3.(*ClientConn).RoundTrip",
		"github.com/quic-go/quic-go/http3.requestFromHeaders",
		"github.com/quic-go/quic-go/http3.parseHeaders",
	}
	for _, tc := range []struct{ env, arch string }{
		{"PODTRACE_TEST_QUICGO_BIN", "amd64"},
		{"PODTRACE_TEST_QUICGO_BIN_ARM64", "arm64"},
	} {
		bin := os.Getenv(tc.env)
		if bin == "" {
			t.Logf("%s not set, skipping %s", tc.env, tc.arch)
			continue
		}
		for _, sym := range symbols {
			entry, rets, ok := goFuncReturnOffsets(bin, sym)
			if !ok {
				t.Errorf("%s: %s: no return sites resolved", tc.arch, sym)
				continue
			}
			t.Logf("%s: %s entry=%#x ret_sites=%d", tc.arch, sym, entry, len(rets))
		}
	}
}
