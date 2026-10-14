package safeelf

import (
	"debug/elf"
	"os"
	"testing"
)

func TestOpen_RealExecutable(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot find test executable: %v", err)
	}
	f, err := Open(exe)
	if err != nil {
		t.Fatalf("Open(%q) = %v, want a parsed ELF", exe, err)
	}
	if f == nil {
		t.Fatal("Open returned a nil file with no error")
		return
	}
	_ = f.Close()
}

func TestOpen_MissingFile(t *testing.T) {
	if _, err := Open("/no/such/podtrace/binary"); err == nil {
		t.Fatal("Open must return an error for a missing path")
	}
}

func TestSectionData_RejectsOversizedSection(t *testing.T) {
	sec := &elf.Section{SectionHeader: elf.SectionHeader{Name: ".huge", Size: MaxSectionSize + 1}}
	data, err := SectionData(sec)
	if err == nil {
		t.Fatal("SectionData must reject a section larger than MaxSectionSize")
	}
	if data != nil {
		t.Errorf("SectionData returned data %v alongside the cap error", data)
	}
}

func TestSectionData_ReadsRealSection(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot find test executable: %v", err)
	}
	f, err := Open(exe)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = f.Close() }()

	sec := smallReadableSection(f)
	if sec == nil {
		t.Skip("no small in-file section available")
		return
	}
	data, err := SectionData(sec)
	if err != nil {
		t.Fatalf("SectionData(%q) = %v", sec.Name, err)
	}
	if uint64(len(data)) != sec.Size {
		t.Errorf("SectionData(%q) returned %d bytes, want %d", sec.Name, len(data), sec.Size)
	}
}

func TestSymbolSectionWithinCap_RealELF(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot find test executable: %v", err)
	}
	f, err := Open(exe)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = f.Close() }()

	if SymbolSectionWithinCap(f, ".this-section-does-not-exist") {
		t.Error("SymbolSectionWithinCap must be false for an absent section")
	}

	present := firstPresentSymbolSection(f)
	if present == "" {
		t.Skip("test binary has no symbol section to assert on")
	}
	if !SymbolSectionWithinCap(f, present) {
		t.Errorf("SymbolSectionWithinCap(%q) = false, want true for a small real symbol table", present)
	}
}

func TestDWARFWithinCap_OverCapIsRejected(t *testing.T) {
	f := &elf.File{Sections: []*elf.Section{
		{SectionHeader: elf.SectionHeader{Name: ".debug_info", Size: MaxDWARFTotalSize + 1}},
	}}
	if DWARFWithinCap(f) {
		t.Fatal("DWARFWithinCap must be false when combined DWARF exceeds MaxDWARFTotalSize")
	}
}

func TestDWARFWithinCap_CompressedPrefixCounts(t *testing.T) {
	f := &elf.File{Sections: []*elf.Section{
		{SectionHeader: elf.SectionHeader{Name: ".zdebug_info", Size: MaxDWARFTotalSize/2 + 1}},
		{SectionHeader: elf.SectionHeader{Name: ".zdebug_line", Size: MaxDWARFTotalSize/2 + 1}},
	}}
	if DWARFWithinCap(f) {
		t.Fatal("DWARFWithinCap must sum .zdebug_* sections toward the cap")
	}
}

func TestDWARFWithinCap_SmallSectionsWithinCap(t *testing.T) {
	f := &elf.File{Sections: []*elf.Section{
		{SectionHeader: elf.SectionHeader{Name: ".text", Size: 4096}},
		{SectionHeader: elf.SectionHeader{Name: ".debug_info", Size: 128}},
		{SectionHeader: elf.SectionHeader{Name: ".debug_line", Size: 64}},
	}}
	if !DWARFWithinCap(f) {
		t.Fatal("DWARFWithinCap must be true for small debug sections")
	}
}

func TestDWARFWithinCap_NoDebugSections(t *testing.T) {
	f := &elf.File{Sections: []*elf.Section{
		{SectionHeader: elf.SectionHeader{Name: ".text", Size: 4096}},
	}}
	if !DWARFWithinCap(f) {
		t.Fatal("DWARFWithinCap must be true when there are no debug sections")
	}
}

func TestRecoverParse_SwallowsPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("RecoverParse failed to contain the panic: %v", r)
		}
	}()
	parseThatPanics()
}

func parseThatPanics() {
	defer RecoverParse("test-parse")
	panic("malformed untrusted binary")
}

func smallReadableSection(f *elf.File) *elf.Section {
	for _, s := range f.Sections {
		if s.Type == elf.SHT_NOBITS {
			continue
		}
		if s.Size > 0 && s.Size < 1<<20 {
			return s
		}
	}
	return nil
}

func firstPresentSymbolSection(f *elf.File) string {
	for _, name := range []string{".symtab", ".dynsym"} {
		if f.Section(name) != nil {
			return name
		}
	}
	return ""
}

func TestASymbolTableOverTheCapIsRejected(t *testing.T) {
	huge := &elf.File{Sections: []*elf.Section{
		{SectionHeader: elf.SectionHeader{Name: ".dynsym", Size: 1024}},
		{SectionHeader: elf.SectionHeader{Name: ".symtab", Size: MaxSymbolTableSize + 1}},
	}}
	if SymbolTablesWithinCap(huge) {
		t.Error("a .symtab over MaxSymbolTableSize passed; cilium would expand it to several times its size")
	}
	if SymbolSectionWithinCap(huge, ".symtab") {
		t.Error("SymbolSectionWithinCap passed a .symtab over MaxSymbolTableSize")
	}
	small := &elf.File{Sections: []*elf.Section{{SectionHeader: elf.SectionHeader{Name: ".symtab", Size: 1024}}}}
	if !SymbolTablesWithinCap(small) || !SymbolTablesWithinCap(&elf.File{}) {
		t.Error("a small or absent symbol table was rejected")
	}
}
