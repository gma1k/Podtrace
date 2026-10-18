package nodespawn

import (
	"context"
	"strconv"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func useLocalOwnerIdentity(t *testing.T, bootID, pidNS string) {
	t.Helper()
	savedBoot, savedNS := MachineBootID, MachinePIDNamespace
	MachineBootID = func() string { return bootID }
	MachinePIDNamespace = func() string { return pidNS }
	t.Cleanup(func() { MachineBootID, MachinePIDNamespace = savedBoot, savedNS })
}

func TestAPodOwnedFromAnotherPIDNamespaceIsNotReapedOnLiveness(t *testing.T) {
	useLocalOwnerIdentity(t, "boot", "4026531836")
	other := reapPodFull("other-runner", 4242, "boot", 10*time.Minute, nil)
	other.Labels[LabelOwnerPIDNS] = "4026532999"
	mine := reapPodFull("mine", 4242, "boot", 10*time.Minute, nil)
	mine.Labels[LabelOwnerPIDNS] = "4026531836"
	cs := fake.NewClientset(other, mine)

	if _, err := reapStaleWithLiveness(context.Background(), cs, "ns1", "", func(int) bool { return false }); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.CoreV1().Pods("ns1").Get(context.Background(), "other-runner", metav1.GetOptions{}); err != nil {
		t.Error("a pod whose owner PID is invisible from this PID namespace was reaped")
	}
	if _, err := cs.CoreV1().Pods("ns1").Get(context.Background(), "mine", metav1.GetOptions{}); err == nil {
		t.Error("an orphan from this PID namespace was not reaped")
	}
}

func TestAnExpiredPodFromAnotherPIDNamespaceIsStillReaped(t *testing.T) {
	useLocalOwnerIdentity(t, "boot", "4026531836")
	old := reapPodFull("old", 4242, "boot", ReaperMaxAge+time.Hour, nil)
	old.Labels[LabelOwnerPIDNS] = "4026532999"
	cs := fake.NewClientset(old)

	reaped, err := reapStaleWithLiveness(context.Background(), cs, "ns1", "", func(int) bool { return true })
	if err != nil || reaped != 1 {
		t.Fatalf("reaped %d (err %v), want the expired pod", reaped, err)
	}
}

func TestSpawnPodsRecordTheirOwnersPIDNamespace(t *testing.T) {
	useLocalOwnerIdentity(t, "boot", "4026531836")
	pod, err := BuildPodSpec(PodSpecOptions{NodeName: "n1", Namespace: "ns1", Image: "img", OwnerPID: 7})
	if err != nil {
		t.Fatal(err)
	}
	if got := pod.Labels[LabelOwnerPIDNS]; got != "4026531836" {
		t.Fatalf("owner PID namespace label = %q", got)
	}
}

func TestThisProcessHasAPIDNamespace(t *testing.T) {
	ns := MachinePIDNamespace()
	if ns == "" {
		t.Skip("no /proc/self/ns/pid on this platform")
	}
	if _, err := strconv.ParseUint(ns, 10, 64); err != nil {
		t.Fatalf("PID namespace %q is not an inode number", ns)
	}
}
