package resource

import (
	"sync"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/alerting"
)

func waitForAlertFrom(t *testing.T, ch chan *alerting.Alert, source string) *alerting.Alert {
	t.Helper()
	deadline := time.After(time.Second)
	for {
		select {
		case a := <-ch:
			if a.Source == source {
				return a
			}
		case <-deadline:
			t.Fatalf("no %s alert delivered", source)
			return nil
		}
	}
}

func assertAlertTargetsPod(t *testing.T, a *alerting.Alert, rm *ResourceMonitor, source string) {
	t.Helper()
	if a.PodName != "web-0" || a.Namespace != "shop" {
		t.Fatalf("alert subject = %s/%s, want shop/web-0", a.Namespace, a.PodName)
	}
	if got := a.Context["cgroup_path"]; got != rm.cgroupPath {
		t.Errorf("alert cgroup_path context = %v, want %q", got, rm.cgroupPath)
	}
	ev := alerting.BuildAlertEvent(a, time.Now())
	if ev == nil {
		t.Fatal("BuildAlertEvent returned nil for a resource alert on a known pod")
	}
	if ev.InvolvedObject.Kind != "Pod" || ev.InvolvedObject.Name != "web-0" || ev.InvolvedObject.Namespace != "shop" {
		t.Errorf("involved object = %+v, want Pod shop/web-0", ev.InvolvedObject)
	}
	if ev.Namespace != "shop" {
		t.Errorf("event namespace = %q, want shop", ev.Namespace)
	}
	if got := ev.Annotations[alerting.AnnotationAlertSource]; got != source {
		t.Errorf("event alert-source annotation = %q, want %q", got, source)
	}
}

func TestCheckAlertsNamesOwningPodAndBuildsTriggerEvent(t *testing.T) {
	ch := useEnabledAlertManager(t)
	alertsMap := newFakeBPFMap()
	rm := newMonitorWithFakeMaps(t, nil, alertsMap, nil)
	rm.SetPodIdentity("web-0", "shop")

	rm.mu.Lock()
	rm.limits = map[uint32]*ResourceLimit{
		ResourceMemory: {LimitBytes: 100, UsageBytes: 96, ResourceType: ResourceMemory},
	}
	rm.mu.Unlock()

	rm.checkAlerts()

	a := waitForAlertFrom(t, ch, alerting.AlertSourceResourceMonitor)
	assertAlertTargetsPod(t, a, rm, alerting.AlertSourceResourceMonitor)
}

func TestCheckBPFCPUAlertsNamesOwningPodAndBuildsTriggerEvent(t *testing.T) {
	ch := useEnabledAlertManager(t)
	quotaMap := newFakeInodeMap()
	alertsMap := newFakeBPFMap()
	rm := newMonitorWithFakeMaps(t, nil, nil, nil)
	rm.SetPodIdentity("web-0", "shop")
	rm.cpuQuotaMicros = 50000
	rm.cpuPeriodMicros = 100000
	rm.EnableBPFCPUSampler(quotaMap, alertsMap)
	if err := alertsMap.Put(resourceMapKey{CgroupID: rm.cgroupInode, ResourceType: ResourceCPU}, uint32(AlertCritical)); err != nil {
		t.Fatalf("seed alert level: %v", err)
	}

	rm.checkBPFCPUAlerts()

	a := waitForAlertFrom(t, ch, alerting.AlertSourceResourceMonitorBPF)
	assertAlertTargetsPod(t, a, rm, alerting.AlertSourceResourceMonitorBPF)
}

func TestAlertSubjectNeverMakesACgroupPathTheEventTarget(t *testing.T) {
	rm := newMonitorWithFakeMaps(t, nil, nil, nil)

	cases := []struct {
		name          string
		podName       string
		namespace     string
		wantPod       string
		wantNamespace string
		wantEvent     bool
	}{
		{name: "resolved pod", podName: "web-0", namespace: "shop", wantPod: "web-0", wantNamespace: "shop", wantEvent: true},
		{name: "namespace only", namespace: "shop", wantNamespace: "shop"},
		{name: "unresolved", wantPod: rm.cgroupPath},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rm.SetPodIdentity(tc.podName, tc.namespace)
			pod, ns := rm.alertSubject()
			if pod != tc.wantPod || ns != tc.wantNamespace {
				t.Fatalf("alertSubject() = (%q, %q), want (%q, %q)", pod, ns, tc.wantPod, tc.wantNamespace)
			}
			ev := alerting.BuildAlertEvent(&alerting.Alert{
				Source:    alerting.AlertSourceResourceMonitor,
				PodName:   pod,
				Namespace: ns,
			}, time.Now())
			if (ev != nil) != tc.wantEvent {
				t.Errorf("BuildAlertEvent produced event = %v, want %v", ev != nil, tc.wantEvent)
			}
		})
	}
}

func TestSetPodIdentityIsSafeWhileAlerting(t *testing.T) {
	rm := newMonitorWithFakeMaps(t, nil, nil, nil)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			rm.SetPodIdentity("web-0", "shop")
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_, _ = rm.alertSubject()
			_ = rm.metricsNamespace()
		}
	}()
	wg.Wait()
}
