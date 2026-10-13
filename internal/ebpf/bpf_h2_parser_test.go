package ebpf

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const h2FrameHarness = `#include <stdio.h>
#include "h2_frame.h"

static int nibble(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	return c - 'a' + 10;
}

int main(int argc, char **argv)
{
	for (int i = 1; i < argc; i++) {
		unsigned char fh[HTTP2_FRAME_HDR];
		for (int j = 0; j < HTTP2_FRAME_HDR; j++)
			fh[j] = (unsigned char)(nibble(argv[i][2 * j]) << 4 | nibble(argv[i][2 * j + 1]));
		putchar(h2_frame_header_valid(fh) ? '1' : '0');
	}
	putchar('\n');
	return 0;
}
`

func TestH2FrameHeaderValidRejectsDatabaseProtocols(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		if cc, err = exec.LookPath("gcc"); err != nil {
			t.Skip("no C compiler available")
		}
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "harness.c")
	if err := os.WriteFile(src, []byte(h2FrameHarness), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "harness")
	if out, err := exec.Command(cc, "-std=c11", "-Wall", "-Werror", "-I", locateBPFDir(t), "-o", bin, src).CombinedOutput(); err != nil {
		t.Fatalf("compile h2_frame.h natively: %v\n%s", err, out)
	}

	cases := []struct {
		name  string
		frame string
		want  bool
	}{
		{"settings", "000012040000000000", true},
		{"settings empty", "000000040000000000", true},
		{"settings ack", "000000040100000000", true},
		{"settings ack with payload", "000006040100000000", false},
		{"settings bad length", "000005040000000000", false},
		{"settings on a stream", "000006040000000001", false},
		{"headers", "000020010400000001", true},
		{"headers padded priority end stream", "000020012d00000003", true},
		{"headers on stream zero", "000020010400000000", false},
		{"data", "000400000100000001", true},
		{"data on stream zero", "000400000000000000", false},
		{"data reserved bit", "000004000080000001", false},
		{"data oversized", "004001000000000001", false},
		{"window update connection", "000004080000000000", true},
		{"window update bad length", "000000080000000000", false},
		{"ping", "000008060000000000", true},
		{"goaway", "000008070000000000", true},
		{"rst stream", "000004030000000005", true},
		{"priority", "000005020000000005", true},
		{"continuation", "000010090400000001", true},
		{"unknown type", "0000000a0000000000", false},
		{"mysql server greeting", "4a0000000a382e302e", false},
		{"mysql handshake response", "55000001850aff0100", false},
		{"mysql small packet", "050000000300000001", false},
		{"postgres ssl request", "0000000804d2162f00", false},
		{"postgres gssenc request", "0000000804d2163000", false},
		{"postgres startup", "000000520003000075", false},
	}

	args := make([]string, len(cases))
	for i, tc := range cases {
		args[i] = tc.frame
	}
	out, err := exec.Command(bin, args...).Output()
	if err != nil {
		t.Fatalf("run harness: %v", err)
	}
	got := strings.TrimSpace(string(out))
	if len(got) != len(cases) {
		t.Fatalf("harness returned %d results for %d cases: %q", len(got), len(cases), got)
	}
	for i, tc := range cases {
		if (got[i] == '1') != tc.want {
			t.Errorf("%s (%s): h2_frame_header_valid = %c, want %v", tc.name, tc.frame, got[i], tc.want)
		}
	}
}

func TestH2SniffUsesFrameHeaderValidation(t *testing.T) {
	body := functionBody(t, bpfSource(t, "h2.c"), "h2_start_looks_h2")
	if !strings.Contains(body, "h2_frame_header_valid(") {
		t.Fatal("h2_start_looks_h2 must validate the whole frame header, not just the type byte")
	}
	if strings.Contains(body, "<= HTTP2_CONTINUATION") {
		t.Fatal("h2_start_looks_h2 still classifies on the type byte alone")
	}
}

func TestH2HeadersPrefixSurvivesSegmentBoundary(t *testing.T) {
	body := functionBody(t, bpfSource(t, "h2.c"), "h2_frames_cb")
	if strings.Contains(body, "off += 5;") {
		t.Fatal("h2_frames_cb skips HEADERS priority bytes from the current buffer even when they are in the next segment")
	}
	for _, want := range []string{"fs->pad_len_pending", "fs->pre_skip"} {
		if !strings.Contains(body, want) {
			t.Errorf("h2_frames_cb must carry %s across segments", want)
		}
	}
	if !strings.Contains(bpfSource(t, "maps.h"), "u8  pad_len_pending;") {
		t.Error("struct h2_frame_state lacks pad_len_pending")
	}
}

func TestH2LostHeaderFragmentConsumesSequence(t *testing.T) {
	body := functionBody(t, bpfSource(t, "h2.c"), "h2_frames_cb")
	idx := strings.Index(body, "bpf_probe_read_user(s->frag, frag, (u8 *)c->base + off) != 0")
	if idx < 0 {
		t.Fatal("h2_frames_cb has no explicit branch for a failed header fragment read")
	}
	branch, ok := braceBody(body, idx)
	if !ok || !strings.Contains(branch, "h2_next_seq(") {
		t.Fatal("a failed header fragment read must consume a seq so userspace sees the gap")
	}
}
