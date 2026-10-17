package tracer

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/gma1k/podtrace/internal/config"
)

func uprobeModeSpec() *ebpf.CollectionSpec {
	return &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
		"uprobe_SSL_write":     {Type: ebpf.Kprobe, SectionName: "uprobe/SSL_write"},
		"uretprobe_SSL_read":   {Type: ebpf.Kprobe, SectionName: "uretprobe/SSL_read"},
		"kprobe_tcp_connect":   {Type: ebpf.Kprobe, SectionName: "kprobe/tcp_connect"},
		"fexit_vfs_read":       {Type: ebpf.Tracing, SectionName: "fexit/vfs_read", AttachType: ebpf.AttachTraceFExit},
		"tracepoint_sched_one": {Type: ebpf.TracePoint, SectionName: "tp/sched/sched_switch"},
	}}
}

func withUprobeMultiSupport(t *testing.T, kernel, enabled bool) {
	t.Helper()
	prevHave, prevEnabled := haveUprobeMulti, config.UprobeMultiEnabled
	haveUprobeMulti = func() bool { return kernel }
	config.UprobeMultiEnabled = enabled
	t.Cleanup(func() { haveUprobeMulti, config.UprobeMultiEnabled = prevHave, prevEnabled })
}

func TestSetUprobeAttachType_OnlyTouchesUprobePrograms(t *testing.T) {
	spec := uprobeModeSpec()
	if n := setUprobeAttachType(spec, true); n != 2 {
		t.Fatalf("switched %d programs, want the 2 uprobe programs", n)
	}
	for name, p := range spec.Programs {
		multi := p.AttachType == ebpf.AttachTraceUprobeMulti
		if multi != isUprobeProgram(p) {
			t.Errorf("%s: attach type %v", name, p.AttachType)
		}
	}
	if spec.Programs["fexit_vfs_read"].AttachType != ebpf.AttachTraceFExit {
		t.Error("a non-uprobe program's attach type must be left alone")
	}
	setUprobeAttachType(spec, false)
	if spec.Programs["uprobe_SSL_write"].AttachType != ebpf.AttachNone {
		t.Error("switching back must restore the classic attach type")
	}
}

func TestNewCollectionForUprobeMode_LoadsMultiWhenSupported(t *testing.T) {
	withUprobeMultiSupport(t, true, true)
	spec := uprobeModeSpec()
	var seen ebpf.AttachType
	_, multi, err := newCollectionForUprobeMode(spec, ebpf.CollectionOptions{}, func(s *ebpf.CollectionSpec, _ ebpf.CollectionOptions) (*ebpf.Collection, error) {
		seen = s.Programs["uprobe_SSL_write"].AttachType
		return &ebpf.Collection{}, nil
	})
	if err != nil || !multi || seen != ebpf.AttachTraceUprobeMulti {
		t.Fatalf("multi=%v err=%v attach=%v; a supporting kernel must load uprobes for uprobe_multi", multi, err, seen)
	}
}

func TestNewCollectionForUprobeMode_FallsBackWhenTheMultiLoadFails(t *testing.T) {
	withUprobeMultiSupport(t, true, true)
	spec := uprobeModeSpec()
	var attempts []ebpf.AttachType
	_, multi, err := newCollectionForUprobeMode(spec, ebpf.CollectionOptions{}, func(s *ebpf.CollectionSpec, _ ebpf.CollectionOptions) (*ebpf.Collection, error) {
		attempts = append(attempts, s.Programs["uprobe_SSL_write"].AttachType)
		if s.Programs["uprobe_SSL_write"].AttachType == ebpf.AttachTraceUprobeMulti {
			return nil, errors.New("verifier refused the program")
		}
		return &ebpf.Collection{}, nil
	})
	if err != nil || multi {
		t.Fatalf("multi=%v err=%v; a refused multi load must still start the agent on classic uprobes", multi, err)
	}
	if len(attempts) != 2 || attempts[1] != ebpf.AttachNone {
		t.Errorf("load attempts = %v, want a multi attempt then a classic one", attempts)
	}
}

func TestNewCollectionForUprobeMode_ClassicWhenUnsupportedOrDisabled(t *testing.T) {
	for name, c := range map[string]struct{ kernel, enabled bool }{
		"kernel without uprobe_multi": {kernel: false, enabled: true},
		"disabled by configuration":   {kernel: true, enabled: false},
	} {
		t.Run(name, func(t *testing.T) {
			withUprobeMultiSupport(t, c.kernel, c.enabled)
			loads := 0
			_, multi, err := newCollectionForUprobeMode(uprobeModeSpec(), ebpf.CollectionOptions{}, func(s *ebpf.CollectionSpec, _ ebpf.CollectionOptions) (*ebpf.Collection, error) {
				loads++
				if s.Programs["uprobe_SSL_write"].AttachType != ebpf.AttachNone {
					t.Error("uprobes must load as classic programs")
				}
				return &ebpf.Collection{}, nil
			})
			if err != nil || multi || loads != 1 {
				t.Errorf("multi=%v err=%v loads=%d", multi, err, loads)
			}
		})
	}
}

func TestNewCollectionForUprobeMode_ClassicLoadErrorIsReturned(t *testing.T) {
	withUprobeMultiSupport(t, false, true)
	want := errors.New("no BTF")
	_, _, err := newCollectionForUprobeMode(uprobeModeSpec(), ebpf.CollectionOptions{}, func(*ebpf.CollectionSpec, ebpf.CollectionOptions) (*ebpf.Collection, error) {
		return nil, want
	})
	if !errors.Is(err, want) {
		t.Errorf("err = %v, want the load error", err)
	}
}

func TestHaveUprobeMulti_AnswersWithoutPanicking(t *testing.T) {
	first := haveUprobeMulti()
	if haveUprobeMulti() != first {
		t.Error("the kernel feature probe must give a stable answer")
	}
}
