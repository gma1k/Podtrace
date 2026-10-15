package quicinitial

import (
	"encoding/binary"
	"testing"
)

func clientHelloFor(host string) []byte {
	sni := []byte{0, 0, 0x00}
	sni = append(sni, byte(len(host)>>8), byte(len(host)))
	sni = append(sni, host...)
	binary.BigEndian.PutUint16(sni, uint16(len(sni)-2))
	ext := []byte{0x00, 0x00, byte(len(sni) >> 8), byte(len(sni))}
	ext = append(ext, sni...)
	body := make([]byte, 2+32)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(hs, body...)
}

func TestExtractPacketsKeepsConcurrentConnectionsApart(t *testing.T) {
	first := buildClientInitial(t, []byte{1, 1, 1, 1, 1, 1, 1, 1}, clientHelloFor("a.example"))
	second := buildClientInitial(t, []byte{2, 2, 2, 2, 2, 2, 2, 2}, clientHelloFor("much-longer-name.example"))

	for _, c := range []struct {
		pkts [][]byte
		want string
	}{
		{[][]byte{first, second}, "a.example"},
		{[][]byte{second, first}, "much-longer-name.example"},
	} {
		info, err := ExtractPackets(c.pkts)
		if err != nil {
			t.Fatalf("ExtractPackets: %v", err)
		}
		if info.SNI != c.want {
			t.Fatalf("SNI = %q, want %q from the first connection only", info.SNI, c.want)
		}
	}
}

func TestInitialDCID(t *testing.T) {
	dcid := []byte{9, 8, 7}
	pkt := buildClientInitial(t, dcid, clientHelloFor("x.example"))
	got, ok := initialDCID(pkt)
	if !ok || string(got) != string(dcid) {
		t.Fatalf("initialDCID = %v, %v", got, ok)
	}
	if _, ok := initialDCID([]byte{0xc0, 0, 0, 0, 1, 20, 1}); ok {
		t.Fatal("truncated DCID accepted")
	}
}
