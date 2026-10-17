package probes

import (
	"reflect"
	"testing"

	"github.com/cilium/ebpf/link"
)

func TestUprobeMultiArgs(t *testing.T) {
	cases := map[string]struct {
		symbol      string
		opts        *link.UprobeOptions
		wantSymbols []string
		want        link.UprobeMultiOptions
	}{
		"symbol only": {
			symbol:      "SSL_write",
			wantSymbols: []string{"SSL_write"},
		},
		"symbol with offset": {
			symbol:      "crypto/tls.(*Conn).Read",
			opts:        &link.UprobeOptions{Offset: 0x40},
			wantSymbols: []string{"crypto/tls.(*Conn).Read"},
			want:        link.UprobeMultiOptions{Offsets: []uint64{0x40}},
		},
		"address plus offset ignores the symbol": {
			symbol: "ignored",
			opts:   &link.UprobeOptions{Address: 0x1000, Offset: 0x8},
			want:   link.UprobeMultiOptions{Addresses: []uint64{0x1008}},
		},
		"usdt site with semaphore and cookie": {
			opts: &link.UprobeOptions{Address: 0x2000, RefCtrOffset: 0x3000, Cookie: 7},
			want: link.UprobeMultiOptions{Addresses: []uint64{0x2000}, RefCtrOffsets: []uint64{0x3000}, Cookies: []uint64{7}},
		},
		"pid filter": {
			symbol:      "PQexec",
			opts:        &link.UprobeOptions{PID: 4242},
			wantSymbols: []string{"PQexec"},
			want:        link.UprobeMultiOptions{PID: 4242},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			symbols, got := uprobeMultiArgs(c.symbol, c.opts)
			if !reflect.DeepEqual(symbols, c.wantSymbols) {
				t.Errorf("symbols = %v, want %v", symbols, c.wantSymbols)
			}
			if !reflect.DeepEqual(*got, c.want) {
				t.Errorf("options = %+v, want %+v", *got, c.want)
			}
		})
	}
}

func TestSetUprobeMulti(t *testing.T) {
	defer SetUprobeMulti(UprobeMultiEnabled())
	SetUprobeMulti(true)
	if !UprobeMultiEnabled() {
		t.Error("uprobe_multi was enabled but reports off")
	}
	SetUprobeMulti(false)
	if UprobeMultiEnabled() {
		t.Error("uprobe_multi was disabled but reports on")
	}
}
