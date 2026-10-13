package ebpf

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var pairedLifetimeMaps = []string{"start_times", "syscall_paths", "lock_targets"}

var earlyReturnRe = regexp.MustCompile(`if\s*\([^)]*\)\s*\{[^{}]*?return[^;]*;[^{}]*\}`)

var pairedSideMaps = []string{
	"socket_conns", "tcp_target", "connect_addrs", "recvmsg_args",
	"redis_cmds", "memcached_ops", "grpc_methods", "kafka_topic_tmp", "proto_bytes",
}

func TestPairedLifetimeMapsAreLRU(t *testing.T) {
	assertMapsAreLRU(t, pairedLifetimeMaps)
}

func TestPairedSideMapsAreLRU(t *testing.T) {
	assertMapsAreLRU(t, pairedSideMaps)
}

func assertMapsAreLRU(t *testing.T, names []string) {
	t.Helper()
	text := bpfSource(t, "maps.h")
	for _, name := range names {
		block, ok := mapBlock(text, name)
		if !ok {
			t.Errorf("map %q not found in maps.h", name)
			continue
		}
		if !strings.Contains(block, "BPF_MAP_TYPE_LRU_HASH") {
			t.Errorf("map %q must be BPF_MAP_TYPE_LRU_HASH so an entry whose return probe never "+
				"fires (kretprobe miss, thread death) is evicted rather than pinned; a plain HASH "+
				"fills and silently disables every probe sharing it", name)
		}
	}
}

func TestReturnProbesFreeSideMapsWhenStartTimeIsMissing(t *testing.T) {
	cases := []struct {
		file, function string
		maps           []string
	}{
		{"network.c", "tcp_sendmsg_return", []string{"grpc_methods"}},
		{"kafka.c", "uretprobe_rd_kafka_produce", []string{"kafka_topic_tmp", "proto_bytes"}},
		{"redis.c", "redis_emit", []string{"redis_cmds"}},
		{"memcached.c", "mc_emit", []string{"memcached_ops", "proto_bytes"}},
	}
	missingStart := regexp.MustCompile(`if\s*\(!start_ts\)\s*\{[^{}]*\}`)
	for _, tc := range cases {
		body := functionBody(t, bpfSource(t, tc.file), tc.function)
		blk := missingStart.FindString(body)
		if blk == "" {
			t.Errorf("%s:%s has no braced `if (!start_ts)` cleanup block", tc.file, tc.function)
			continue
		}
		for _, mp := range tc.maps {
			if !strings.Contains(blk, "bpf_map_delete_elem(&"+mp+",") {
				t.Errorf("%s:%s leaks %s when its start time is missing", tc.file, tc.function, mp)
			}
		}
	}
}

func TestReturnProbesCleanUpPairedMapsOnEarlyReturn(t *testing.T) {
	bpfDir := locateBPFDir(t)

	entries, err := os.ReadDir(bpfDir)
	if err != nil {
		t.Fatalf("read bpf dir %q: %v", bpfDir, err)
	}

	var violations []string
	fnRe := regexp.MustCompile(`\nint\s+(\w+)\s*\([^)]*\)\s*\{`)

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".c") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(bpfDir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		text := string(src)

		for _, m := range fnRe.FindAllStringSubmatchIndex(text, -1) {
			name := text[m[2]:m[3]]
			body, ok := braceBody(text, m[1]-1)
			if !ok || !strings.Contains(body, "get_event_buf()") {
				continue
			}

			var owned []string
			for _, mp := range pairedLifetimeMaps {
				if strings.Contains(body, "bpf_map_delete_elem(&"+mp+",") {
					owned = append(owned, mp)
				}
			}
			if len(owned) < 2 {
				continue
			}

			for _, blk := range earlyReturnRe.FindAllString(body, -1) {
				cond := strings.TrimSpace(strings.SplitN(blk, "{", 2)[0])
				if strings.Contains(cond, "start_ts") {
					continue
				}
				for _, mp := range owned {
					if !strings.Contains(blk, "bpf_map_delete_elem(&"+mp+",") {
						violations = append(violations,
							e.Name()+":"+name+" early return `"+cond+"` on the consume path leaks "+mp)
					}
				}
			}
		}
	}

	if len(violations) > 0 {
		t.Fatalf("BPF return probes leak paired maps on an early-return path:\n  %s",
			strings.Join(violations, "\n  "))
	}
}

func braceBody(text string, openIdx int) (string, bool) {
	for openIdx < len(text) && text[openIdx] != '{' {
		openIdx++
	}
	if openIdx >= len(text) {
		return "", false
	}
	depth := 0
	for i := openIdx; i < len(text); i++ {
		switch text[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return text[openIdx : i+1], true
			}
		}
	}
	return "", false
}

func bpfSource(t *testing.T, name string) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(locateBPFDir(t), name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(src)
}

func mapBlock(text, name string) (string, bool) {
	end := strings.Index(text, "} "+name+" SEC(")
	if end < 0 {
		return "", false
	}
	start := strings.LastIndex(text[:end], "struct {")
	if start < 0 {
		return "", false
	}
	return text[start:end], true
}

func functionBody(t *testing.T, text, name string) string {
	t.Helper()
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\s*\([^;{]*\)\s*\{`)
	loc := re.FindStringIndex(text)
	if loc == nil {
		t.Fatalf("function %s not found", name)
	}
	body, ok := braceBody(text, loc[1]-1)
	if !ok {
		t.Fatalf("function %s: unbalanced braces", name)
	}
	return body
}

func locateBPFDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			bpfDir := filepath.Join(dir, "bpf")
			if _, err := os.Stat(bpfDir); err != nil {
				t.Fatalf("bpf dir not found at module root %q: %v", dir, err)
			}
			return bpfDir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("module root (go.mod) not found walking up from working directory")
		}
		dir = parent
	}
}
