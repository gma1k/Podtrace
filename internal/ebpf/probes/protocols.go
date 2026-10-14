package probes

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/hostfs"
	"github.com/gma1k/podtrace/internal/logger"
)

// attachUprobeSymbols attaches uprobe+uretprobe pairs for the given symbols
// on the given executable path. Failures are logged but not fatal.
func attachUprobeSymbols(exe *executable, coll *ebpf.Collection, libPath string,
	pairs []struct{ uprobe, uretprobe, symbol string }) []link.Link {
	var links []link.Link
	for _, p := range pairs {
		if prog := coll.Programs[p.uprobe]; prog != nil {
			l, err := exe.Uprobe(p.symbol, prog, nil)
			if err == nil {
				links = append(links, l)
				logger.Debug("Attached uprobe", zap.String("prog", p.uprobe), zap.String("lib", libPath))
			} else if !strings.Contains(err.Error(), fmt.Sprintf("symbol %s not found", p.symbol)) {
				logger.Info("Uprobe unavailable", zap.String("prog", p.uprobe), zap.Error(err))
			}
		}
		if prog := coll.Programs[p.uretprobe]; prog != nil {
			l, err := exe.Uretprobe(p.symbol, prog, nil)
			if err == nil {
				links = append(links, l)
			} else if !strings.Contains(err.Error(), fmt.Sprintf("symbol %s not found", p.symbol)) {
				logger.Info("Uretprobe unavailable", zap.String("prog", p.uretprobe), zap.Error(err))
			}
		}
	}
	return links
}

// AttachRedisProbes attaches hiredis uprobes for EVENT_REDIS_CMD tracing.
func AttachRedisProbes(coll *ebpf.Collection, containerID string) []link.Link {
	return AttachRedisProbesWithPID(coll, containerID, 0, nil)
}

// AttachRedisProbesWithPID attaches hiredis uprobes with process-assisted library resolution.
func AttachRedisProbesWithPID(coll *ebpf.Collection, containerID string, pid uint32, af *AttachedFiles) []link.Link {
	var links []link.Link
	libNames := []string{"libhiredis.so.1", "libhiredis.so.0.14", "libhiredis.so"}
	paths := findDBLibsWithPID(containerID, pid, libNames)

	for _, path := range paths {
		if !hostfs.IsRegularFile(path) {
			continue
		}
		if !af.Claim("redis", path) {
			continue
		}
		exe, err := openExecutable(path)
		if err != nil {
			continue
		}
		defer func() { _ = exe.Close() }()
		pairs := []struct{ uprobe, uretprobe, symbol string }{
			{"uprobe_redisCommand", "uretprobe_redisCommand", "redisCommand"},
			{"uprobe_redisCommandArgv", "uretprobe_redisCommandArgv", "redisCommandArgv"},
		}
		l := attachUprobeSymbols(exe, coll, path, pairs)
		if len(l) > 0 {
			links = append(links, l...)
			logger.Debug("Redis probes attached", zap.String("lib", path))
		}
	}
	if len(links) == 0 {
		logger.Debug("Redis probes unavailable (libhiredis not found)", zap.String("containerID", containerID))
	}
	return links
}

// AttachMemcachedProbes attaches libmemcached uprobes for EVENT_MEMCACHED_CMD tracing.
func AttachMemcachedProbes(coll *ebpf.Collection, containerID string) []link.Link {
	return AttachMemcachedProbesWithPID(coll, containerID, 0, nil)
}

// AttachMemcachedProbesWithPID attaches libmemcached uprobes with process-assisted library resolution.
func AttachMemcachedProbesWithPID(coll *ebpf.Collection, containerID string, pid uint32, af *AttachedFiles) []link.Link {
	var links []link.Link
	libNames := []string{"libmemcached.so.11", "libmemcached.so.10", "libmemcached.so"}
	paths := findDBLibsWithPID(containerID, pid, libNames)

	for _, path := range paths {
		if !hostfs.IsRegularFile(path) {
			continue
		}
		if !af.Claim("memcached", path) {
			continue
		}
		exe, err := openExecutable(path)
		if err != nil {
			continue
		}
		defer func() { _ = exe.Close() }()
		pairs := []struct{ uprobe, uretprobe, symbol string }{
			{"uprobe_memcached_get", "uretprobe_memcached_get", "memcached_get"},
			{"uprobe_memcached_set", "uretprobe_memcached_set", "memcached_set"},
			{"uprobe_memcached_delete", "uretprobe_memcached_delete", "memcached_delete"},
		}
		l := attachUprobeSymbols(exe, coll, path, pairs)
		if len(l) > 0 {
			links = append(links, l...)
			logger.Debug("Memcached probes attached", zap.String("lib", path))
		}
	}
	if len(links) == 0 {
		logger.Debug("Memcached probes unavailable (libmemcached not found)", zap.String("containerID", containerID))
	}
	return links
}

// AttachKafkaProbes attaches librdkafka uprobes for Kafka produce/consume tracing.
func AttachKafkaProbes(coll *ebpf.Collection, containerID string) []link.Link {
	return AttachKafkaProbesWithPID(coll, containerID, 0, nil)
}

// AttachKafkaProbesWithPID attaches librdkafka uprobes with process-assisted library resolution.
func AttachKafkaProbesWithPID(coll *ebpf.Collection, containerID string, pid uint32, af *AttachedFiles) []link.Link {
	var links []link.Link
	libNames := []string{"librdkafka.so.1", "librdkafka.so"}
	paths := findDBLibsWithPID(containerID, pid, libNames)

	for _, path := range paths {
		if !hostfs.IsRegularFile(path) {
			continue
		}
		if !af.Claim("kafka", path) {
			continue
		}
		exe, err := openExecutable(path)
		if err != nil {
			continue
		}
		defer func() { _ = exe.Close() }()
		pairs := []struct{ uprobe, uretprobe, symbol string }{
			{"uprobe_rd_kafka_topic_new", "uretprobe_rd_kafka_topic_new", "rd_kafka_topic_new"},
			{"uprobe_rd_kafka_produce", "uretprobe_rd_kafka_produce", "rd_kafka_produce"},
			{"uprobe_rd_kafka_consumer_poll", "uretprobe_rd_kafka_consumer_poll", "rd_kafka_consumer_poll"},
		}
		l := attachUprobeSymbols(exe, coll, path, pairs)
		if len(l) > 0 {
			links = append(links, l...)
			logger.Debug("Kafka probes attached", zap.String("lib", path))
		}
	}
	if len(links) == 0 {
		logger.Debug("Kafka probes unavailable (librdkafka not found)", zap.String("containerID", containerID))
	}
	return links
}

// attachKprobes attaches the entry kprobe named entry on sym, and, when ret
// is not empty, the return probe named ret before it. An entry whose return
// probe could not attach is skipped: it would stash state nothing clears.
func attachKprobes(coll *ebpf.Collection, what, sym, entry, ret string) []link.Link {
	var links []link.Link
	if ret != "" {
		prog := coll.Programs[ret]
		if prog == nil {
			logger.Debug(what+" program not present in collection", zap.String("prog", ret))
			return nil
		}
		l, err := attachReturn(coll, ret, func() (link.Link, error) { return kprobeAttach(sym, prog, true) })
		if err != nil {
			logger.Debug(what+" probe unavailable", zap.String("prog", ret), zap.Error(err))
			return nil
		}
		links = append(links, l)
		logger.Debug(what+" probe attached", zap.String("prog", ret))
	}
	prog := coll.Programs[entry]
	if prog == nil {
		logger.Debug(what+" program not present in collection", zap.String("prog", entry))
		return closeAll(links)
	}
	l, err := kprobeAttach(sym, prog, false)
	if err != nil {
		logger.Debug(what+" probe unavailable", zap.String("prog", entry), zap.Error(err))
		return closeAll(links)
	}
	logger.Debug(what+" probe attached", zap.String("prog", entry))
	return append(links, l)
}

// closeAll closes links and returns nothing in their place.
func closeAll(links []link.Link) []link.Link {
	for _, l := range links {
		_ = l.Close()
	}
	return nil
}

// AttachFastCGIProbes attaches kprobes on unix_stream_sendmsg/recvmsg for
// FastCGI / PHP-FPM request lifecycle tracing (BTF-only; no-ops without BTF).
func AttachFastCGIProbes(coll *ebpf.Collection) []link.Link {
	var links []link.Link
	links = append(links, attachKprobes(coll, "FastCGI", "unix_stream_recvmsg", "kprobe_unix_stream_recvmsg", "kretprobe_unix_stream_recvmsg")...)
	links = append(links, attachKprobes(coll, "FastCGI", "unix_stream_sendmsg", "kprobe_unix_stream_sendmsg", "")...)
	return links
}

// AttachGRPCProbes attaches the second kprobe on tcp_sendmsg for gRPC
// HTTP/2 HEADERS frame inspection (BTF-only; no-op without BTF).
func AttachGRPCProbes(coll *ebpf.Collection) []link.Link {
	var links []link.Link
	prog := coll.Programs["kprobe_grpc_tcp_sendmsg"]
	if prog == nil {
		return links
	}
	l, err := link.Kprobe("tcp_sendmsg", prog, nil)
	if err == nil {
		links = append(links, l)
		logger.Debug("gRPC HTTP/2 inspection probe attached")
	} else {
		logger.Debug("gRPC HTTP/2 inspection probe unavailable", zap.Error(err))
	}
	return links
}

// AttachHTTPProbes attaches the socket-level HTTP/1.x inspection kprobes: a
// third kprobe on tcp_sendmsg (request line) plus a kprobe+kretprobe pair on
// tcp_recvmsg (status line).
func AttachHTTPProbes(coll *ebpf.Collection) []link.Link {
	var links []link.Link
	links = append(links, attachKprobes(coll, "HTTP/1.x", "tcp_sendmsg", "kprobe_http_tcp_sendmsg", "")...)
	links = append(links, attachKprobes(coll, "HTTP/1.x", "tcp_recvmsg", "kprobe_http_tcp_recvmsg", "kretprobe_http_tcp_recvmsg")...)
	return links
}

// AttachH2Probes attaches the HTTP/2 (h2c) HPACK endpoint-capture kprobes: a
// kprobe on tcp_sendmsg (request HEADERS) plus a kprobe+kretprobe pair on
// tcp_recvmsg (response HEADERS).
func AttachH2Probes(coll *ebpf.Collection) []link.Link {
	var links []link.Link
	links = append(links, attachKprobes(coll, "HTTP/2", "tcp_sendmsg", "kprobe_h2_tcp_sendmsg", "kretprobe_h2_tcp_sendmsg")...)
	links = append(links, attachKprobes(coll, "HTTP/2", "tcp_recvmsg", "kprobe_h2_tcp_recvmsg", "kretprobe_h2_tcp_recvmsg")...)
	links = append(links, attachKprobes(coll, "HTTP/2", "tcp_close", "kprobe_h2_tcp_close", "")...)
	return links
}
