package diagnose

import "testing"

func TestAddProcessCPUMergesAndIgnoresEmpty(t *testing.T) {
	d := NewDiagnostician()
	if got := d.ProcessCPU(); got != nil {
		t.Fatalf("a fresh diagnostician has CPU times %v", got)
	}
	d.AddProcessCPU(nil)
	d.AddProcessCPU(map[uint32]uint64{})
	if got := d.ProcessCPU(); got != nil {
		t.Fatalf("empty input was kept: %v", got)
	}
	d.AddProcessCPU(map[uint32]uint64{10: 1_000, 11: 5})
	d.AddProcessCPU(map[uint32]uint64{10: 500})
	got := d.ProcessCPU()
	if got[10] != 1_500 || got[11] != 5 || len(got) != 2 {
		t.Fatalf("ProcessCPU = %v, want map[10:1500 11:5]", got)
	}
	got[10] = 0
	if d.ProcessCPU()[10] != 1_500 {
		t.Fatal("ProcessCPU must return a copy")
	}
}
