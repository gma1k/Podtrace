package ebpf

import (
	"regexp"
	"strings"
	"testing"
)

var userspacePointerRe = regexp.MustCompile(`\b(GO_\w*GOROUTINE|GO_ARG_RECV)\(ctx\)`)

func TestUserspacePointerKeysAreProcessScoped(t *testing.T) {
	for _, file := range []string{"gotls.c", "gohandshake.c", "goacquire.c", "http3l7.c"} {
		text := bpfSource(t, file)
		for _, line := range strings.Split(text, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#define") {
				continue
			}
			for _, loc := range userspacePointerRe.FindAllStringIndex(line, -1) {
				if strings.HasSuffix(line[:loc[0]], "process_scoped_id(") {
					continue
				}
				if trimmed == "u64 goroutine = GO_GOROUTINE(ctx);" {
					continue
				}
				t.Errorf("%s: %q uses a raw userspace pointer as a key or conn id; "+
					"another process can hold the same address", file, trimmed)
			}
		}
	}
}

func TestRawGoroutineOnlyFeedsTgidKeyedOncpu(t *testing.T) {
	text := bpfSource(t, "http3l7.c")
	useRe := regexp.MustCompile(`\bgoroutine\b`)
	for _, fn := range []string{"uprobe_h3_req_from_headers_ret", "uprobe_h3_handle_request_ret"} {
		body := functionBody(t, text, fn)
		for _, line := range strings.Split(body, "\n") {
			trimmed := strings.TrimSpace(line)
			if !useRe.MatchString(trimmed) || trimmed == "u64 goroutine = GO_GOROUTINE(ctx);" {
				continue
			}
			if strings.Contains(trimmed, "process_scoped_id(goroutine)") ||
				strings.HasPrefix(trimmed, "oncpu_") {
				continue
			}
			t.Errorf("%s: raw goroutine reaches %q", fn, trimmed)
		}
	}
}

func TestH3StashKeySeparatesClientAndServer(t *testing.T) {
	body := functionBody(t, bpfSource(t, "http3l7.c"), "h3_stash_key")
	if strings.Contains(body, "goroutine |") {
		t.Fatal("h3_stash_key ORs the client bit into a hashed key, so a key with bit 63 already set " +
			"makes a goroutine's client and server stashes collide")
	}
}

func TestRustlsConnKeyCoversTheWholeTupleAndProcess(t *testing.T) {
	body := functionBody(t, bpfSource(t, "rustls.c"), "rustls_conn_key")
	for _, want := range []string{"saddr6", "daddr6", "process_scoped_id("} {
		if !strings.Contains(body, want) {
			t.Errorf("rustls_conn_key must fold %s into the conn id", want)
		}
	}
}
