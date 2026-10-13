package kubernetes

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/gma1k/podtrace/internal/config"
)

func twoContainerSandbox(t *testing.T, ids ...string) {
	t.Helper()
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "cgroup.controllers"), []byte("cpu memory\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		dir := filepath.Join(base, "kubepods.slice", "container-"+id)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(""), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	orig := config.CgroupBasePath
	config.CgroupBasePath = base
	t.Setenv("PODTRACE_CRI_RESOLVE", "false")
	t.Cleanup(func() { config.CgroupBasePath = orig })
}

func TestRebuildFromStoreNeverPublishesAPartialTargetSet(t *testing.T) {
	a, b := hex64(), hex64()
	twoContainerSandbox(t, a, b)

	tr := NewTargetRegistry(fake.NewSimpleClientset(), TargetSelection{Namespaces: []string{"prod"}})
	podInf := informers.NewSharedInformerFactory(tr.clientset, 0).Core().V1().Pods().Informer()
	tr.podInfs = append(tr.podInfs, podInf)
	for _, p := range []struct{ uid, name, id string }{{"uid-a", "client", a}, {"uid-b", "rustls", b}} {
		if err := podInf.GetStore().Add(runningPod(p.uid, "prod", p.name, "c", p.id)); err != nil {
			t.Fatal(err)
		}
	}

	tr.rebuildFromStore(context.Background())
	select {
	case snap := <-tr.Updates():
		t.Fatalf("rebuild published a snapshot of %d pods before the set was complete", len(snap))
	default:
	}

	tr.emitSnapshot()
	select {
	case snap := <-tr.Updates():
		if len(snap) != 2 {
			t.Fatalf("first published snapshot has %d pods, want 2", len(snap))
		}
	default:
		t.Fatal("no snapshot published after the rebuild")
	}
}

func TestHandlePodUpsertStillPublishesEachChange(t *testing.T) {
	a := hex64()
	twoContainerSandbox(t, a)
	tr := NewTargetRegistry(fake.NewSimpleClientset(), TargetSelection{Namespaces: []string{"prod"}})

	tr.handlePodUpsert(context.Background(), runningPod("uid-a", "prod", "client", "c", a))
	select {
	case snap := <-tr.Updates():
		if len(snap) != 1 {
			t.Fatalf("snapshot has %d pods, want 1", len(snap))
		}
	default:
		t.Fatal("a live pod change must still be published")
	}
}
