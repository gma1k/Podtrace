package ebpf

import (
	"strings"
	"testing"
)

func TestSSLReadExUsesByteCountFromOutParameter(t *testing.T) {
	text := bpfSource(t, "http.c")
	entry := functionBody(t, text, "uprobe_SSL_read_ex")
	if !strings.Contains(entry, "PT_REGS_PARM4(ctx)") || !strings.Contains(entry, "ssl_read_stash(ssl, buf, out_len)") {
		t.Error("uprobe_SSL_read_ex must stash the readbytes pointer (4th argument)")
	}
	ret := functionBody(t, text, "uretprobe_SSL_read_ex")
	for _, want := range []string{
		"s64 rc = PT_REGS_RC_INT(ctx);",
		"if (rc != 1)",
		"bpf_probe_read_user(&n, sizeof(n), (void *)out_len)",
		"ssl_read_complete(ctx, base, conn, n)",
	} {
		if !strings.Contains(ret, want) {
			t.Errorf("uretprobe_SSL_read_ex lacks %q", want)
		}
	}
}

func TestSSLReadAndWriteSkipWhenNestedInExVariant(t *testing.T) {
	text := bpfSource(t, "http.c")
	if !strings.Contains(functionBody(t, text, "uprobe_SSL_read"), "outer->out_len") {
		t.Error("uprobe_SSL_read must not overwrite an in-flight SSL_read_ex stash (LibreSSL nests them)")
	}
	if !strings.Contains(functionBody(t, text, "uretprobe_SSL_read"), "st->out_len") {
		t.Error("uretprobe_SSL_read must leave an SSL_read_ex stash to the outer return probe")
	}
	if !strings.Contains(functionBody(t, text, "uprobe_SSL_write"), "outer->out_len") {
		t.Error("uprobe_SSL_write must not overwrite an in-flight SSL_write_ex stash (LibreSSL nests them)")
	}
	if !strings.Contains(functionBody(t, text, "uretprobe_SSL_write"), "st->out_len") {
		t.Error("uretprobe_SSL_write must leave an SSL_write_ex stash to the outer return probe")
	}
}

func TestTLSWritesAreCapturedOnReturn(t *testing.T) {
	text := bpfSource(t, "http.c")
	for _, entry := range []string{"uprobe_SSL_write", "uprobe_SSL_write_ex", "uprobe_gnutls_record_send"} {
		body := functionBody(t, text, entry)
		for _, emit := range []string{"ssl_write_dispatch(", "http_emit_request(", "http_emit_response(", "h2_emit_frames("} {
			if strings.Contains(body, emit) {
				t.Errorf("%s emits on entry, so a write retried after WANT_READ/WANT_WRITE or EAGAIN is recorded once per attempt", entry)
			}
		}
	}
	cases := map[string]string{
		"uretprobe_SSL_write":          "ssl_write_dispatch(ctx, conn, base, (u64)ret)",
		"uretprobe_SSL_write_ex":       "ssl_write_dispatch(ctx, conn, base, n)",
		"uretprobe_gnutls_record_send": "(u64)ret",
	}
	for fn, want := range cases {
		if !strings.Contains(functionBody(t, text, fn), want) {
			t.Errorf("%s must emit with the byte count the call returned", fn)
		}
	}
}
