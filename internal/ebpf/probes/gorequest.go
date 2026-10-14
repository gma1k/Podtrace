package probes

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/logger"
)

// goRequestHandler is a Go function whose invocation is one served request,
// with the entry and return-site programs that bracket it for the on-CPU
// sampler's per-request attribution.
type goRequestHandler struct {
	symbol, entryProg, retProg string
}

// goRequestHandlers are the handler entry points of the Go servers podtrace
// attributes CPU to. net/http covers HTTP/1. Each HTTP/2 server runs a
// request's handler in its own goroutine through runHandler, and there are
// three: x/net's, net/http's internal one (Go 1.27+, which x/net's server also
// forwards to) and the older bundled one. For HTTP/2 over TLS runHandler calls
// serverHandler, and the outer probe keeps the request. gRPC runs each RPC in
// handleStream. quic-go's HTTP/3 server is bracketed by the HTTP/3 probes
// (AttachGoHTTP3Probes).
var goRequestHandlers = []goRequestHandler{
	{"net/http.serverHandler.ServeHTTP", "uprobe_go_nethttp_serve", "uprobe_go_nethttp_serve_ret"},
	{"golang.org/x/net/http2.(*serverConn).runHandler", "uprobe_go_h2_handler", "uprobe_go_h2_handler_ret"},
	{"net/http/internal/http2.(*serverConn).runHandler", "uprobe_go_h2_handler", "uprobe_go_h2_handler_ret"},
	{"net/http.(*http2serverConn).runHandler", "uprobe_go_h2_handler", "uprobe_go_h2_handler_ret"},
	{"google.golang.org/grpc.(*Server).handleStream", "uprobe_go_grpc_handle_stream", "uprobe_go_grpc_handle_stream_ret"},
}

// goConnectionServers are functions that, called from inside a request
// handler, turn it into the server of a whole connection.
var goConnectionServers = []struct{ symbol, prog string }{
	{"golang.org/x/net/http2.(*Server).ServeConn", "uprobe_go_h2_serve_conn"},
	{"golang.org/x/net/http2.(*Server).serveConn", "uprobe_go_h2_serve_conn"},
	{"net/http/internal/http2.(*Server).ServeConn", "uprobe_go_h2_serve_conn"},
	{"net/http/internal/http2.(*Server).serveConn", "uprobe_go_h2_serve_conn"},
	{"net/http.(*http2Server).ServeConn", "uprobe_go_h2_serve_conn"},
	{"net/http.(*http2Server).serveConn", "uprobe_go_h2_serve_conn"},
}

// goRequestProbesWanted reports whether anything reads a Go request's id:
// the continuous profiler in the agent, or a diagnose run stamping requests.
func goRequestProbesWanted() bool {
	return config.ContinuousProfilingEnabled || config.RequestStamping
}

// AttachGoRequestProbes brackets every request handler a Go binary contains,
// so the on-CPU sampler can charge a sample, and request stamping an event,
// to the request its goroutine is serving.
func AttachGoRequestProbes(coll *ebpf.Collection, pid uint32) []link.Link {
	if pid == 0 || coll == nil || !goRequestProbesWanted() {
		return nil
	}
	exePath := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "exe")
	exe, err := openExecutable(exePath)
	if err != nil {
		logger.Debug("Go request probes: cannot open executable",
			zap.String("path", exePath), zap.Error(err))
		return nil
	}
	defer func() { _ = exe.Close() }()
	var links []link.Link
	for _, h := range goRequestHandlers {
		links = append(links, attachGoEntryReturnProbes(coll, exe, exePath, pid, h.symbol, h.entryProg, h.retProg)...)
	}
	for _, c := range goConnectionServers {
		prog := coll.Programs[c.prog]
		if prog == nil {
			continue
		}
		if l, ok := attachGoUprobeBySymbol(exe, exePath, c.symbol, prog); ok {
			links = append(links, l)
		}
	}
	return links
}
