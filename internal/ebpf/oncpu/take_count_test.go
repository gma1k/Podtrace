package oncpu

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
)

type fakeCountTaker struct {
	lookupErr error
	value     uint64
	deleted   int
}

func (f *fakeCountTaker) LookupAndDelete(_, valueOut any) error {
	if f.lookupErr != nil {
		return f.lookupErr
	}
	*valueOut.(*uint64) = f.value
	return nil
}

func (f *fakeCountTaker) Delete(any) error {
	f.deleted++
	return nil
}

func TestTakeCountReturnsTheValueAtRemoval(t *testing.T) {
	m := &fakeCountTaker{value: 9}
	count := uint64(4)
	if err := takeCountFrom(m)(&Key{}, &count); err != nil || count != 9 || m.deleted != 0 {
		t.Fatalf("err=%v count=%d deleted=%d", err, count, m.deleted)
	}
}

func TestTakeCountFallsBackToDeleteWithoutLookupAndDelete(t *testing.T) {
	m := &fakeCountTaker{lookupErr: ebpf.ErrNotSupported}
	count := uint64(4)
	if err := takeCountFrom(m)(&Key{}, &count); err != nil || count != 4 || m.deleted != 1 {
		t.Fatalf("err=%v count=%d deleted=%d", err, count, m.deleted)
	}
}

func TestTakeCountReportsOtherErrors(t *testing.T) {
	boom := errors.New("boom")
	m := &fakeCountTaker{lookupErr: boom}
	count := uint64(0)
	if err := takeCountFrom(m)(&Key{}, &count); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
}
