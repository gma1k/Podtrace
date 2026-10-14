package kernelagg

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type scriptedRowMap struct {
	rows           map[Key]Value
	lookupAndDel   error
	lookupErr      error
	deleteErr      error
	atomicCalls    int
	separateLookup int
	separateDelete int
}

func (m *scriptedRowMap) LookupAndDelete(key, valueOut any) error {
	m.atomicCalls++
	if m.lookupAndDel != nil {
		return m.lookupAndDel
	}
	k := *(key.(*Key))
	v, ok := m.rows[k]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	*(valueOut.(*[]Value)) = []Value{v, v}
	delete(m.rows, k)
	return nil
}

func (m *scriptedRowMap) Lookup(key, valueOut any) error {
	m.separateLookup++
	if m.lookupErr != nil {
		return m.lookupErr
	}
	v, ok := m.rows[*(key.(*Key))]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	*(valueOut.(*[]Value)) = []Value{v}
	return nil
}

func (m *scriptedRowMap) Delete(key any) error {
	m.separateDelete++
	delete(m.rows, *(key.(*Key)))
	return m.deleteErr
}

func TestARowIsTakenAtomicallyAndSummedAcrossCPUs(t *testing.T) {
	k := Key{CgroupID: 1}
	m := &scriptedRowMap{rows: map[Key]Value{k: {Count: 2}}}
	taker := &mapTaker{m: m}

	v, err := taker.take(&k)
	if err != nil || v.Count != 4 {
		t.Fatalf("take = %+v, %v; want both CPUs' counts summed", v, err)
	}
	if m.separateLookup != 0 || len(m.rows) != 0 {
		t.Error("an atomic take fell back to the two-step path or left the row")
	}
	if v, err := taker.take(&k); err != nil || v != (Value{}) {
		t.Errorf("taking a row already gone = %+v, %v; want zero and no error", v, err)
	}
}

func TestAKernelWithoutAtomicTakeFallsBackForTheRestOfTheDrain(t *testing.T) {
	for _, unsupported := range []error{ebpf.ErrNotSupported, unix.EINVAL} {
		a, b := Key{CgroupID: 1}, Key{CgroupID: 2}
		m := &scriptedRowMap{rows: map[Key]Value{a: {Count: 3}, b: {Count: 5}}, lookupAndDel: unsupported}
		taker := &mapTaker{m: m}

		va, err := taker.take(&a)
		if err != nil || va.Count != 3 {
			t.Fatalf("%v: take = %+v, %v", unsupported, va, err)
		}
		vb, _ := taker.take(&b)
		if vb.Count != 5 || m.atomicCalls != 1 {
			t.Errorf("%v: atomic take retried %d times; a kernel that refused it once refuses it for every row", unsupported, m.atomicCalls)
		}
		if len(m.rows) != 0 {
			t.Errorf("%v: the fallback left %d rows", unsupported, len(m.rows))
		}
	}
}

func TestATakeFailureIsSurfaced(t *testing.T) {
	k := Key{CgroupID: 9}
	boom := errors.New("boom")
	for name, m := range map[string]*scriptedRowMap{
		"atomic": {rows: map[Key]Value{k: {Count: 1}}, lookupAndDel: boom},
		"lookup": {rows: map[Key]Value{k: {Count: 1}}, lookupAndDel: ebpf.ErrNotSupported, lookupErr: boom},
		"delete": {rows: map[Key]Value{k: {Count: 1}}, lookupAndDel: ebpf.ErrNotSupported, deleteErr: boom},
	} {
		if _, err := (&mapTaker{m: m}).take(&k); !errors.Is(err, boom) {
			t.Errorf("%s failure: take = %v, want it surfaced", name, err)
		}
	}
	gone := &scriptedRowMap{rows: map[Key]Value{}, lookupAndDel: ebpf.ErrNotSupported}
	if v, err := (&mapTaker{m: gone}).take(&k); err != nil || v != (Value{}) {
		t.Errorf("two-step take of a missing row = %+v, %v; want zero and no error", v, err)
	}
	vanished := &scriptedRowMap{rows: map[Key]Value{k: {Count: 1}}, lookupAndDel: ebpf.ErrNotSupported, deleteErr: ebpf.ErrKeyNotExist}
	if v, err := (&mapTaker{m: vanished}).take(&k); err != nil || v.Count != 1 {
		t.Errorf("a row deleted between lookup and delete = %+v, %v; want its value and no error", v, err)
	}
}
