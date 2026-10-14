//go:build bpf_loadtest && linux

package loader

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/gma1k/podtrace/internal/config"
)

func TestLoadPodtrace_KernelVerifierAccepts(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("kernel BPF load requires root (run: sudo -E go test -tags bpf_loadtest ./internal/ebpf/loader/...)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock: %v", err)
	}

	originalPath := config.BPFObjectPath
	t.Cleanup(func() { config.BPFObjectPath = originalPath })
	config.BPFObjectPath = findBPFObjectPath()

	spec, err := LoadPodtrace()
	if err != nil {
		t.Skipf("BPF object not built (run: make internal/ebpf/embedded/podtrace.$GOARCH.bpf.o): %v", err)
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("kernel verifier rejected the freshly built object:\n%+v", ve)
		}
		t.Fatalf("NewCollectionWithOptions: %v", err)
	}
	defer coll.Close()

	if len(coll.Programs) == 0 {
		t.Fatal("collection loaded zero programs into the kernel")
	}
}
