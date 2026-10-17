package metricsexporter

import (
	"testing"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gma1k/podtrace/internal/events"
)

func TestTrafficDerivedLabelsWithInvalidUTF8DoNotPanic(t *testing.T) {
	cases := []*events.Event{
		{Type: events.EventRedisCmd, LatencyNS: 1000, Details: "GET\xff", ProcessName: "redis-cli"},
		{Type: events.EventMemcachedCmd, LatencyNS: 1000, Details: "get\xfe", ProcessName: "mc"},
		{Type: events.EventGRPCMethod, LatencyNS: 1000, Target: "/pkg.Svc/Get\xff", ProcessName: "svc"},
		{Type: events.EventFastCGIResp, LatencyNS: 1000, Details: "GET\xc3", ProcessName: "php-fpm"},
		{Type: events.EventKafkaProduce, LatencyNS: 1000, Target: "orders\xff", ProcessName: "producer"},
		{Type: events.EventTCPSend, LatencyNS: 1000, Bytes: 10, ProcessName: "w\xc3"},
		{Type: events.EventDNS, LatencyNS: 1000, ProcessName: "\xff"},
	}
	for _, e := range cases {
		t.Run(e.TypeString(), func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("HandleEventWithContext panicked: %v", r)
				}
			}()
			HandleEventWithContext(e, map[string]interface{}{"namespace": "shop"})
		})
	}

	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, f := range families {
		for _, m := range f.GetMetric() {
			for _, lp := range m.GetLabel() {
				if !utf8.ValidString(lp.GetValue()) {
					t.Errorf("%s{%s=%q} is not valid UTF-8", f.GetName(), lp.GetName(), lp.GetValue())
				}
			}
		}
	}
}

func TestHandleEventWithContextRecoveredIsolatesAPanic(t *testing.T) {
	saved := commandCardinality
	commandCardinality = nil
	t.Cleanup(func() { commandCardinality = saved })

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic escaped the per-event recover: %v", r)
		}
	}()
	HandleEventWithContextRecovered(&events.Event{Type: events.EventRedisCmd, Details: "GET"}, nil)
	HandleEventWithContextRecovered(nil, nil)
}
