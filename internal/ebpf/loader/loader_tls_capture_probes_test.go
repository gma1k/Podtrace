package loader

import "testing"

func TestLoadedSpec_HasTLSCaptureProbes(t *testing.T) {
	programs, _ := loadSpecOrSkip(t)
	for _, name := range []string{
		"uprobe_SSL_read_ex",
		"uretprobe_SSL_read_ex",
		"uprobe_SSL_write_ex",
		"uretprobe_SSL_write_ex",
		"uretprobe_SSL_write",
		"uretprobe_gnutls_record_send",
	} {
		if _, ok := programs[name]; !ok {
			t.Errorf("compiled BPF object is missing %q, so TLS writes or the OpenSSL _ex API go uncaptured", name)
		}
	}
}

func TestLoadedSpec_HasProcessCPUMaps(t *testing.T) {
	_, maps := loadSpecOrSkip(t)
	for _, name := range []string{"proc_cpu_ns", "proc_cpu_enabled"} {
		if _, ok := maps[name]; !ok {
			t.Errorf("compiled BPF object is missing map %q, so the report cannot show CPU time for exited processes", name)
		}
	}
}

func TestLoadedSpec_HasCgroupInheritanceHook(t *testing.T) {
	programs, maps := loadSpecOrSkip(t)
	if _, ok := programs["raw_tracepoint_cgroup_mkdir"]; !ok {
		t.Error("compiled BPF object is missing raw_tracepoint_cgroup_mkdir, so a restarted container is missed until the pod watch reports it")
	}
	for _, name := range []string{"target_parent_cgroup_ids", "inherited_cgroup_ids"} {
		if _, ok := maps[name]; !ok {
			t.Errorf("compiled BPF object is missing map %q", name)
		}
	}
}
