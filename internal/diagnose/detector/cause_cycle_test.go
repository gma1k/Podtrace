package detector

import (
	"reflect"
	"testing"
)

func TestDirectCausesThatOnlyBlameEachOtherAreStillReported(t *testing.T) {
	front := ref(IDL7LatencyDegraded, "front")
	b, c, d := ref(IDL7LatencyDegraded, "b"), ref(IDL7LatencyDegraded, "c"), ref(IDL7LatencyDegraded, "d")
	got := RootCauses([]IssueRef{front, b, c, d}, calls(map[string][]string{
		"front": {"b", "c", "d"},
		"b":     {"c"},
		"c":     {"b"},
	}))

	want := []Cause{{IssueRef: b}, {IssueRef: c}, {IssueRef: d}}
	if !reflect.DeepEqual(got[front], want) {
		t.Errorf("front causes %v, want %v: b and c only blame each other, so together "+
			"they are a root, and d is not front's only cause", got[front], want)
	}
}

func TestALoopThatLeadsToARootIsNotItselfARoot(t *testing.T) {
	front := ref(IDL7LatencyDegraded, "front")
	b, c := ref(IDL7LatencyDegraded, "b"), ref(IDL7LatencyDegraded, "c")
	pool := ref(IDDBPoolSaturated, "c")
	got := RootCauses([]IssueRef{front, b, c, pool}, calls(map[string][]string{
		"front": {"b"},
		"b":     {"c"},
		"c":     {"b"},
	}))

	want := []Cause{{IssueRef: pool, Via: []IssueRef{b, c}}}
	if !reflect.DeepEqual(got[front], want) {
		t.Errorf("front causes %v, want %v", got[front], want)
	}
}
