//go:build bpf_loadtest && linux

package probes

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/cilium/ebpf"
)

func hashMap(t *testing.T, value any) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  uint32(binary.Size(value)),
		MaxEntries: 8,
	})
	if err != nil {
		t.Skipf("cannot create a map (needs privileges): %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func TestKernelAnHTTP3TargetGetsItsFieldOffsetsPublished(t *testing.T) {
	uprobeProgram(t)
	offsets := hashMap(t, h3FieldOffsets{})
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{},
		Maps: map[string]*ebpf.Map{
			"h3_offsets":        offsets,
			"h3_peer_paths_map": hashMap(t, h3PeerPaths{}),
		},
	}
	pid := uint32(os.Getpid())

	for _, l := range AttachGoHTTP3Probes(coll, pid) {
		_ = l.Close()
	}

	var got h3FieldOffsets
	if err := offsets.Lookup(&pid, &got); err != nil {
		t.Fatalf("no HTTP/3 field offsets published for the target: %v", err)
	}
	if got.Method == 0 && got.URL == 0 && got.Status == 0 {
		t.Errorf("published offsets %+v are all zero", got)
	}
}
