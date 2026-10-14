package filter

import "testing"

func TestACgroupV1PathContainingAColonIsKeptWhole(t *testing.T) {
	content := "4:cpu,cpuacct:/kubepods/pod1/abc:def\n1:name=systemd:/x:y:z\n"
	if got, want := ExtractCgroupPathFromProc(content), "/kubepods/pod1/abc:def"; got != want {
		t.Errorf("ExtractCgroupPathFromProc = %q, want %q", got, want)
	}
	if got, want := ExtractCgroupPathFromProc("1:name=systemd:/x:y:z\n"), "/x:y:z"; got != want {
		t.Errorf("ExtractCgroupPathFromProc = %q, want %q", got, want)
	}
}
