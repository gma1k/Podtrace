//go:build bpf_loadtest && linux

package probes

import (
	"os"
	"testing"
)

func TestKernelTwoContainersOfOneFileShareItsUprobes(t *testing.T) {
	prog := uprobeProgram(t)
	a, err := openExecutable(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	b, err := openExecutable("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	for _, ret := range []bool{false, true} {
		attach := a.Uprobe
		again := b.Uprobe
		if ret {
			attach, again = a.Uretprobe, b.Uretprobe
		}
		first, err := attach("runtime.main", prog, nil)
		if err != nil {
			t.Fatalf("attach (ret=%v): %v", ret, err)
		}
		second, err := again("runtime.main", prog, nil)
		if err != nil {
			t.Fatalf("second attach (ret=%v): %v", ret, err)
		}
		if first.(*uprobeHandle).Link != second.(*uprobeHandle).Link {
			t.Errorf("ret=%v: one file reached by two paths got two uprobes; each call would fire twice", ret)
		}
		if err := first.Close(); err != nil {
			t.Fatal(err)
		}
		if err := second.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if len(sharedUprobes.sites) != 0 {
		t.Errorf("%d uprobes left attached after every holder closed", len(sharedUprobes.sites))
	}
}
