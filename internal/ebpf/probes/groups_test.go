package probes

import "testing"

func TestGroupForProbe_HTTPSocketProbes(t *testing.T) {
	for _, prog := range []string{
		"kprobe_http_tcp_sendmsg",
		"kprobe_http_tcp_recvmsg",
		"kretprobe_http_tcp_recvmsg",
	} {
		if got := GroupForProbe(prog); got != GroupNetwork {
			t.Errorf("GroupForProbe(%q) = %q, want %q", prog, got, GroupNetwork)
		}
	}
}

func TestGroupForProbe_TLSPlaintextProbes(t *testing.T) {
	for _, prog := range []string{
		"uprobe_SSL_write",
		"uretprobe_SSL_write",
		"uprobe_SSL_read",
		"uretprobe_SSL_read",
		"uprobe_SSL_write_ex",
		"uretprobe_SSL_write_ex",
		"uprobe_SSL_read_ex",
		"uretprobe_SSL_read_ex",
		"uprobe_gnutls_record_send",
		"uretprobe_gnutls_record_send",
		"uprobe_gnutls_record_recv",
		"uretprobe_gnutls_record_recv",
	} {
		if got := GroupForProbe(prog); got != GroupTLS {
			t.Errorf("GroupForProbe(%q) = %q, want %q", prog, got, GroupTLS)
		}
	}
}

func TestGroupForProbe_H2Probes(t *testing.T) {
	for _, prog := range []string{
		"kprobe_h2_tcp_sendmsg",
		"kretprobe_h2_tcp_sendmsg",
		"kprobe_h2_tcp_recvmsg",
		"kretprobe_h2_tcp_recvmsg",
	} {
		if got := GroupForProbe(prog); got != GroupNetwork {
			t.Errorf("GroupForProbe(%q) = %q, want %q", prog, got, GroupNetwork)
		}
	}
}

func TestGroupForProbe_GoTLSProbe(t *testing.T) {
	if got := GroupForProbe("uprobe_go_tls_write"); got != GroupTLS {
		t.Errorf("GroupForProbe(uprobe_go_tls_write) = %q, want %q", got, GroupTLS)
	}
}

func TestGroupForProbe_UnknownDefaultsToNetwork(t *testing.T) {
	if got := GroupForProbe("kprobe_does_not_exist"); got != GroupNetwork {
		t.Errorf("GroupForProbe(unknown) = %q, want %q", got, GroupNetwork)
	}
}
