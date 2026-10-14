package probes

import (
	"debug/dwarf"
	"testing"
	"time"
)

func TestASelfReferentialTypedefDoesNotSpinForever(t *testing.T) {
	self := &dwarf.TypedefType{}
	self.Type = self
	a, b := &dwarf.TypedefType{}, &dwarf.QualType{}
	a.Type, b.Type = b, a

	done := make(chan struct{})
	go func() {
		defer close(done)
		if got := stripType(self); got != nil {
			t.Errorf("stripType(self-typedef) = %v, want nil", got)
		}
		if got := stripType(a); got != nil {
			t.Errorf("stripType(typedef cycle) = %v, want nil", got)
		}
		if isGoInterfaceType(self) {
			t.Error("a self-referential typedef was taken for an interface")
		}
		if _, _, ok := atomicPointerInfo(self); ok {
			t.Error("a self-referential typedef was taken for an atomic pointer")
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stripType never returned on a typedef that names itself")
	}
}

func TestStripTypeStillPeelsAnOrdinaryChain(t *testing.T) {
	base := &dwarf.StructType{StructName: "net.UDPAddr"}
	chain := &dwarf.TypedefType{Type: &dwarf.QualType{Type: base}}
	if got := stripType(chain); got != base {
		t.Errorf("stripType = %v, want the struct under the wrappers", got)
	}
}
