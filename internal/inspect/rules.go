package inspect

import (
	"fmt"
	"time"

	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/diagnose/detector"
	"github.com/gma1k/podtrace/internal/events"
)

const (
	familyL7Requests      = "podtrace_workload_l7_requests_total"
	familyL7Duration      = "podtrace_workload_l7_request_duration_seconds"
	familyUtilization     = "podtrace_workload_resource_utilization_percent"
	familyAcquire         = "podtrace_workload_db_connection_acquire_seconds"
	familyConnections     = "podtrace_workload_network_connections_total"
	familyNetworkLatency  = "podtrace_workload_network_latency_seconds"
	familyPoolUtilization = "podtrace_workload_db_pool_utilization_percent"
	familyCPURunqueue     = "podtrace_workload_cpu_runqueue_latency_seconds"
	familyLockContention  = "podtrace_workload_lock_contention_seconds"
	familyNetworkRTT      = "podtrace_workload_network_rtt_seconds"
	familyDNSLatency      = "podtrace_workload_dns_latency_seconds"
	familyFSLatency       = "podtrace_workload_filesystem_latency_seconds"
	familyDNSLookups      = "podtrace_workload_dns_lookups_total"
	familyTLSHandshake    = "podtrace_workload_tls_handshake_duration_seconds"
	familyErrors          = "podtrace_workload_errors_total"
)

// RuleFamilies is every family the built-in rules read, and nothing else.
func RuleFamilies() []string {
	return []string{
		familyL7Requests,
		familyL7Duration,
		familyUtilization,
		familyAcquire,
		familyConnections,
		familyNetworkLatency,
		familyPoolUtilization,
		familyCPURunqueue,
		familyLockContention,
		familyNetworkRTT,
		familyDNSLatency,
		familyFSLatency,
		familyDNSLookups,
		familyTLSHandshake,
		familyErrors,
	}
}

// Thresholds is the tunable part of the rule set.
type Thresholds struct {
	ErrorRatePercent float64

	MinRequestsPerSecond float64

	MeanLatency time.Duration

	UtilizationWarn      int
	UtilizationCritical  int
	UtilizationEmergency int

	AcquireMean time.Duration

	RTTSpikeBound time.Duration

	SpikeRatePercent float64

	PoolUtilizationWarn     int
	PoolUtilizationCritical int

	CPUBlockedMean time.Duration

	MinPreemptions uint64

	DNSSlowBound time.Duration

	DNSSlowRatePercent float64

	FSSlowBound time.Duration

	FSSlowRatePercent float64

	DNSFailureRatePercent float64

	TLSHandshakeFailurePercent float64

	HoldTime time.Duration

	HoldTimes map[detector.ID]time.Duration
}

// unset reports whether no threshold was configured at all, so New can fill
// in the shipped defaults.
func (t Thresholds) unset() bool {
	return t.ErrorRatePercent == 0 &&
		t.MinRequestsPerSecond == 0 &&
		t.MeanLatency == 0 &&
		t.UtilizationWarn == 0 &&
		t.UtilizationCritical == 0 &&
		t.UtilizationEmergency == 0 &&
		t.AcquireMean == 0 &&
		t.RTTSpikeBound == 0 &&
		t.SpikeRatePercent == 0 &&
		t.PoolUtilizationWarn == 0 &&
		t.PoolUtilizationCritical == 0 &&
		t.CPUBlockedMean == 0 &&
		t.MinPreemptions == 0 &&
		t.DNSSlowBound == 0 &&
		t.DNSSlowRatePercent == 0 &&
		t.FSSlowBound == 0 &&
		t.FSSlowRatePercent == 0 &&
		t.DNSFailureRatePercent == 0 &&
		t.TLSHandshakeFailurePercent == 0 &&
		t.HoldTime == 0 &&
		len(t.HoldTimes) == 0
}

// holdTimeFor returns how long a rule's condition must hold before its issue
// activates: the rule's own default unless overridden.
func (t Thresholds) holdTimeFor(rule Rule) time.Duration {
	if override, ok := t.HoldTimes[rule.ID]; ok && override > 0 {
		return override
	}
	if t.HoldTime > 0 {
		return t.HoldTime
	}
	return rule.For
}

// Rule is one continuous inspection.
type Rule struct {
	ID detector.ID

	For time.Duration

	Query string

	Eval func(w Window, t Thresholds) []detector.Issue
}

// DefaultThresholds are the shipped defaults.
func DefaultThresholds() Thresholds {
	return Thresholds{
		ErrorRatePercent:     5,
		MinRequestsPerSecond: 0.1,
		MeanLatency:          time.Second,
		UtilizationWarn:      80,
		UtilizationCritical:  90,
		UtilizationEmergency: 95,
		AcquireMean:          100 * time.Millisecond,

		RTTSpikeBound:    time.Duration(config.RTTSpikeThresholdMS) * time.Millisecond,
		SpikeRatePercent: config.SpikeRateThreshold,

		PoolUtilizationWarn:     80,
		PoolUtilizationCritical: 90,

		CPUBlockedMean: 50 * time.Millisecond,

		MinPreemptions: 100,

		DNSSlowBound:       100 * time.Millisecond,
		DNSSlowRatePercent: 5,

		FSSlowBound:       50 * time.Millisecond,
		FSSlowRatePercent: 5,

		DNSFailureRatePercent: 5,

		TLSHandshakeFailurePercent: 5,
	}
}

// Rules returns the built-in rule set.
func Rules() []Rule {
	return []Rule{
		errorRateRule(),
		latencyRule(),
		saturationRule(),
		acquireLatencyRule(),
		connectionFailureRateRule(),
		rttSpikeRule(),
		poolSaturationRule(),
		cpuContentionRule(),
		dnsSlowLookupRule(),
		fsSlowOperationsRule(),
		dnsFailureRateRule(),
		tlsHandshakeFailureRule(),
	}
}

func subjectOf(s Sample) detector.Subject {
	return detector.Subject{
		Namespace: s.Namespace,
		Workload:  s.Workload,
		Container: s.Container,
	}
}

// errorRateRule fires on the error ratio of application-layer requests.
func errorRateRule() Rule {
	return Rule{
		ID:  detector.IDL7ErrorRate,
		For: 2 * time.Minute,
		Query: `100 * sum by (namespace, workload) (rate(podtrace_workload_l7_requests_total{outcome="error"}[5m]))
  / sum by (namespace, workload) (rate(podtrace_workload_l7_requests_total[5m]))`,
		Eval: func(w Window, t Thresholds) []detector.Issue {
			if !w.Ready() {
				return nil
			}
			interval := w.Interval()

			type totals struct {
				sample   Sample
				requests float64
				errors   float64
			}
			byWorkload := map[string]*totals{}
			for _, d := range w.Deltas(familyL7Requests) {
				if d.Reset {
					continue
				}
				key := d.Sample.Namespace + "/" + d.Sample.Workload
				agg, ok := byWorkload[key]
				if !ok {
					agg = &totals{sample: d.Sample}
					byWorkload[key] = agg
				}
				agg.requests += d.Value
				if d.Sample.Label("outcome") == "error" {
					agg.errors += d.Value
				}
			}

			var issues []detector.Issue
			for _, agg := range byWorkload {
				if agg.requests == 0 {
					continue
				}
				perSecond := agg.requests / interval.Seconds()
				if perSecond < t.MinRequestsPerSecond {
					continue
				}
				ratio := agg.errors / agg.requests * 100
				if ratio <= t.ErrorRatePercent {
					continue
				}
				issues = append(issues, detector.Issue{
					ID:       detector.IDL7ErrorRate,
					Severity: alerting.SeverityWarning,
					Subject: detector.Subject{
						Namespace: agg.sample.Namespace,
						Workload:  agg.sample.Workload,
					},
					Evidence: []detector.Evidence{
						detector.NewEvidence("error_rate", ratio, t.ErrorRatePercent, "%"),
						detector.NewEvidence("errors", agg.errors, 0, "count"),
						detector.NewEvidence("requests", agg.requests, 0, "count"),
						detector.NewEvidence("request_rate", perSecond, t.MinRequestsPerSecond, "/s"),
					},
					Remediation: "Check the workload's own logs first, then the service map " +
						"for a failing dependency; a session on this workload captures the " +
						"failing requests with their status codes.",
					Message: fmt.Sprintf("High application error rate for %s/%s: %.1f%% of %.0f requests (threshold: %.1f%%)",
						agg.sample.Namespace, agg.sample.Workload, ratio, agg.requests, t.ErrorRatePercent),
				})
			}
			return issues
		},
	}
}

// latencyRule fires on the mean request duration over the interval.
func latencyRule() Rule {
	return Rule{
		ID:  detector.IDL7LatencyDegraded,
		For: 3 * time.Minute,
		Query: `sum by (namespace, workload) (rate(podtrace_workload_l7_request_duration_seconds_sum[5m]))
  / sum by (namespace, workload) (rate(podtrace_workload_l7_request_duration_seconds_count[5m]))`,
		Eval: func(w Window, t Thresholds) []detector.Issue {
			if !w.Ready() {
				return nil
			}

			type totals struct {
				sample Sample
				count  uint64
				sum    float64
			}
			byWorkload := map[string]*totals{}
			for _, d := range w.Deltas(familyL7Duration) {
				if d.Reset || d.Count == 0 {
					continue
				}
				key := d.Sample.Namespace + "/" + d.Sample.Workload
				agg, ok := byWorkload[key]
				if !ok {
					agg = &totals{sample: d.Sample}
					byWorkload[key] = agg
				}
				agg.count += d.Count
				agg.sum += d.Sum
			}

			threshold := t.MeanLatency.Seconds()
			var issues []detector.Issue
			for _, agg := range byWorkload {
				mean := agg.sum / float64(agg.count)
				if mean <= threshold {
					continue
				}
				issues = append(issues, detector.Issue{
					ID:       detector.IDL7LatencyDegraded,
					Severity: alerting.SeverityWarning,
					Subject: detector.Subject{
						Namespace: agg.sample.Namespace,
						Workload:  agg.sample.Workload,
					},
					Evidence: []detector.Evidence{
						detector.NewEvidence("mean_duration", mean, threshold, "s"),
						detector.NewEvidence("requests", float64(agg.count), 0, "count"),
					},
					Remediation: "Compare the workload's own duration against its egress edges " +
						"on the service map: if a dependency moved with it, the cause is " +
						"downstream; if it did not, profile the workload itself.",
					Message: fmt.Sprintf("Degraded request latency for %s/%s: %.0fms mean over %d requests (threshold: %.0fms)",
						agg.sample.Namespace, agg.sample.Workload,
						mean*1000, agg.count, threshold*1000),
				})
			}
			return issues
		},
	}
}

// saturationRule fires on a container approaching a resource limit.
func saturationRule() Rule {
	return Rule{
		ID:    detector.IDResourceSaturation,
		For:   time.Minute,
		Query: `max by (namespace, workload, resource) (podtrace_workload_resource_utilization_percent)`,
		Eval: func(w Window, t Thresholds) []detector.Issue {
			var issues []detector.Issue
			for _, s := range w.Gauges(familyUtilization) {
				pct := int(s.Value)
				severity, firing := detector.SeverityForUtilization(pct,
					t.UtilizationWarn, t.UtilizationCritical, t.UtilizationEmergency)
				if !firing {
					continue
				}
				resource := s.Label("resource")
				subject := subjectOf(s)
				subject.Pod = s.Pod
				subject.Resource = resource
				issues = append(issues, detector.Issue{
					ID:       detector.IDResourceSaturation,
					Severity: severity,
					Subject:  subject,
					Evidence: []detector.Evidence{
						detector.NewEvidence("utilization", s.Value,
							float64(t.UtilizationWarn), "%"),
					},
					Remediation: "Raise the container's limit for this resource, or reduce what " +
						"the workload asks of it; saturation here shows up as latency everywhere else.",
					Message: fmt.Sprintf("Resource limit %s: %s/%s %s at %d%% utilization (threshold: %d%% warning, %d%% critical, %d%% emergency)",
						detector.SeverityLabel(severity), s.Namespace, s.Workload, resource, pct,
						t.UtilizationWarn, t.UtilizationCritical, t.UtilizationEmergency),
				})
			}
			return issues
		},
	}
}

// acquireLatencyRule fires when callers are spending real time getting a
// database connection before their query can start.
func acquireLatencyRule() Rule {
	return Rule{
		ID:  detector.IDDBAcquireSlow,
		For: 2 * time.Minute,
		Query: `sum by (namespace, workload) (rate(podtrace_workload_db_connection_acquire_seconds_sum[5m]))
  / sum by (namespace, workload) (rate(podtrace_workload_db_connection_acquire_seconds_count[5m]))`,
		Eval: func(w Window, t Thresholds) []detector.Issue {
			if !w.Ready() {
				return nil
			}

			type totals struct {
				sample Sample
				count  uint64
				sum    float64
			}
			byWorkload := map[string]*totals{}
			for _, d := range w.Deltas(familyAcquire) {
				if d.Reset || d.Count == 0 {
					continue
				}
				key := d.Sample.Namespace + "/" + d.Sample.Workload
				agg, ok := byWorkload[key]
				if !ok {
					agg = &totals{sample: d.Sample}
					byWorkload[key] = agg
				}
				agg.count += d.Count
				agg.sum += d.Sum
			}

			var issues []detector.Issue
			for _, agg := range byWorkload {
				mean := time.Duration(agg.sum / float64(agg.count) * float64(time.Second))
				if mean < t.AcquireMean {
					continue
				}
				s := agg.sample
				issues = append(issues, detector.Issue{
					ID:       detector.IDDBAcquireSlow,
					Severity: alerting.SeverityWarning,
					Subject:  detector.Subject{Namespace: s.Namespace, Workload: s.Workload},
					Evidence: []detector.Evidence{
						detector.NewEvidence("mean_acquire_time", mean.Seconds(),
							t.AcquireMean.Seconds(), "s"),
						detector.NewEvidence("waiting_acquisitions", float64(agg.count), 0, ""),
					},
					Remediation: "Check SetMaxOpenConns and SetMaxIdleConns together: a low " +
						"maximum queues callers, while a low idle count makes them re-establish " +
						"connections they could have reused. Both show up here. Compare with the " +
						"application's own sql.DBStats to tell which.",
					Message: fmt.Sprintf("Slow database connection acquisition: %s/%s spent a mean of %s across %d acquisitions, queueing or reconnecting (threshold: %s)",
						s.Namespace, s.Workload, mean.Round(time.Millisecond), agg.count,
						t.AcquireMean.Round(time.Millisecond)),
				})
			}
			return issues
		},
	}
}

// workloadTotals accumulates one family's window deltas per workload, which
// every ratio rule below needs and none of them should each re-derive.
type workloadTotals struct {
	sample Sample
	count  uint64
	sum    float64
	value  float64
	errors float64
	above  float64
}

func totalsByWorkload(deltas []Delta) map[string]*workloadTotals {
	out := map[string]*workloadTotals{}
	for _, d := range deltas {
		if d.Reset {
			continue
		}
		key := d.Sample.Namespace + "/" + d.Sample.Workload
		agg, ok := out[key]
		if !ok {
			agg = &workloadTotals{sample: d.Sample}
			out[key] = agg
		}
		agg.count += d.Count
		agg.sum += d.Sum
		agg.value += d.Value
	}
	return out
}

// connectionFailureRateRule fires on the share of outbound connection attempts
// that failed.
func connectionFailureRateRule() Rule {
	return Rule{
		ID:  detector.IDConnectionFailureRate,
		For: 2 * time.Minute,
		Query: `100 * sum by (namespace, workload) (rate(podtrace_workload_network_connections_total{outcome="error"}[5m]))
  / sum by (namespace, workload) (rate(podtrace_workload_network_connections_total{outcome!="unreachable"}[5m]))`,
		Eval: func(w Window, t Thresholds) []detector.Issue {
			if !w.Ready() {
				return nil
			}
			interval := w.Interval()

			byWorkload := map[string]*workloadTotals{}
			for _, d := range w.Deltas(familyConnections) {
				if d.Reset {
					continue
				}
				if d.Sample.Label("outcome") == "unreachable" {
					continue
				}
				key := d.Sample.Namespace + "/" + d.Sample.Workload
				agg, ok := byWorkload[key]
				if !ok {
					agg = &workloadTotals{sample: d.Sample}
					byWorkload[key] = agg
				}
				agg.value += d.Value
				if d.Sample.Label("outcome") == "error" {
					agg.errors += d.Value
				}
			}

			var issues []detector.Issue
			for _, agg := range byWorkload {
				if agg.value == 0 {
					continue
				}
				perSecond := agg.value / interval.Seconds()
				if perSecond < t.MinRequestsPerSecond {
					continue
				}
				rate := agg.errors / agg.value * 100
				if rate <= t.ErrorRatePercent {
					continue
				}
				s := agg.sample
				issues = append(issues, detector.Issue{
					ID:       detector.IDConnectionFailureRate,
					Severity: alerting.SeverityWarning,
					Subject: detector.Subject{
						Namespace: s.Namespace,
						Workload:  s.Workload,
					},
					Evidence: []detector.Evidence{
						detector.NewEvidence("error_rate", rate, t.ErrorRatePercent, "%"),
						detector.NewEvidence("failed_connections", agg.errors, 0, "count"),
						detector.NewEvidence("total_connections", agg.value, 0, "count"),
						detector.NewEvidence("connection_rate", perSecond, t.MinRequestsPerSecond, "/s"),
					},
					Remediation: "Check the destination's readiness and any NetworkPolicy or " +
						"firewall between the two; the service map shows which peer is failing.",
					Message: fmt.Sprintf("High connection failure rate for %s/%s: %.1f%% (%.0f/%.0f) (threshold: %.1f%%)",
						s.Namespace, s.Workload, rate, agg.errors, agg.value, t.ErrorRatePercent),
				})
			}
			return issues
		},
	}
}

// rttSpikeRule fires when too large a share of socket operations run slower
// than the spike bound.
func rttSpikeRule() Rule {
	return Rule{
		ID:  detector.IDRTTSpikeRate,
		For: 3 * time.Minute,
		Query: `100 * (1 - (
  sum by (namespace, workload) (rate(podtrace_workload_network_latency_seconds_bucket{le="0.1"}[5m]))
  / sum by (namespace, workload) (rate(podtrace_workload_network_latency_seconds_count[5m]))))`,
		Eval: func(w Window, t Thresholds) []detector.Issue {
			if !w.Ready() || t.RTTSpikeBound <= 0 {
				return nil
			}
			bound := t.RTTSpikeBound.Seconds()

			family, source := familyNetworkRTT, "kernel smoothed RTT"
			if len(w.Cur.Family(familyNetworkRTT)) == 0 {
				family, source = familyNetworkLatency, "socket operation latency"
			}

			byWorkload := map[string]*workloadTotals{}
			for _, d := range w.Deltas(family) {
				if d.Reset || d.Count == 0 {
					continue
				}
				share, ok := d.FractionAbove(bound)
				if !ok {
					continue
				}
				key := d.Sample.Namespace + "/" + d.Sample.Workload
				agg, found := byWorkload[key]
				if !found {
					agg = &workloadTotals{sample: d.Sample}
					byWorkload[key] = agg
				}
				agg.count += d.Count
				agg.above += share / 100 * float64(d.Count)
			}

			var issues []detector.Issue
			for _, agg := range byWorkload {
				rate := agg.above / float64(agg.count) * 100
				if rate <= t.SpikeRatePercent {
					continue
				}
				s := agg.sample
				issues = append(issues, detector.Issue{
					ID:       detector.IDRTTSpikeRate,
					Severity: alerting.SeverityWarning,
					Subject: detector.Subject{
						Namespace: s.Namespace,
						Workload:  s.Workload,
					},
					Evidence: []detector.Evidence{
						detector.NewEvidence("spike_rate", rate, t.SpikeRatePercent, "%"),
						detector.NewEvidence("rtt_threshold", t.RTTSpikeBound.Seconds()*1000,
							t.RTTSpikeBound.Seconds()*1000, "ms"),
						detector.NewEvidence("spikes", agg.above, 0, "count"),
						detector.NewEvidence("total_operations", float64(agg.count), 0, "count"),
					},
					Remediation: remediationForRTTSource(source),
					Message: fmt.Sprintf("High TCP RTT spike rate for %s/%s: %.1f%% of %d samples slower than %s, measured from %s (threshold: %.1f%%)",
						s.Namespace, s.Workload, rate, agg.count,
						t.RTTSpikeBound.Round(time.Millisecond), source, t.SpikeRatePercent),
				})
			}
			return issues
		},
	}
}

// poolSaturationRule fires on a Go database/sql pool approaching its ceiling,
// which is the point of having the gauge: db.connection_acquire_slow only
// notices once callers are already queueing.
func poolSaturationRule() Rule {
	return Rule{
		ID:    detector.IDDBPoolSaturated,
		For:   2 * time.Minute,
		Query: `max by (namespace, workload) (podtrace_workload_db_pool_utilization_percent)`,
		Eval: func(w Window, t Thresholds) []detector.Issue {
			if t.PoolUtilizationWarn <= 0 {
				return nil
			}
			var issues []detector.Issue
			for _, s := range w.Gauges(familyPoolUtilization) {
				pct := int(s.Value)
				var severity alerting.AlertSeverity
				switch {
				case pct >= t.PoolUtilizationCritical:
					severity = alerting.SeverityCritical
				case pct >= t.PoolUtilizationWarn:
					severity = alerting.SeverityWarning
				default:
					continue
				}
				subject := subjectOf(s)
				subject.Pod = s.Pod
				issues = append(issues, detector.Issue{
					ID:       detector.IDDBPoolSaturated,
					Severity: severity,
					Subject:  subject,
					Evidence: []detector.Evidence{
						detector.NewEvidence("pool_utilization", s.Value,
							float64(t.PoolUtilizationWarn), "%"),
					},
					Remediation: "Raise SetMaxOpenConns, or find what is holding connections: " +
						"the pool is near its ceiling but callers are not queueing yet, so " +
						"there is still time to act before latency moves.",
					Message: fmt.Sprintf("Database pool near capacity: %s/%s has %d%% of SetMaxOpenConns in use (threshold: %d%% warning, %d%% critical)",
						s.Namespace, s.Workload, pct,
						t.PoolUtilizationWarn, t.PoolUtilizationCritical),
				})
			}
			return issues
		},
	}
}

// cpuContentionRule fires when a workload spends real time runnable but not
// running.
func cpuContentionRule() Rule {
	return Rule{
		ID:  detector.IDCPUContention,
		For: 3 * time.Minute,
		Query: `sum by (namespace, workload) (rate(podtrace_workload_cpu_runqueue_latency_seconds_sum[5m]))
  / sum by (namespace, workload) (rate(podtrace_workload_cpu_runqueue_latency_seconds_count[5m]))`,
		Eval: func(w Window, t Thresholds) []detector.Issue {
			if !w.Ready() {
				return nil
			}

			runqueue := totalsByWorkload(w.Deltas(familyCPURunqueue))
			locks := totalsByWorkload(w.Deltas(familyLockContention))

			threshold := t.CPUBlockedMean.Seconds()
			var issues []detector.Issue
			for key, agg := range runqueue {
				if agg.count == 0 || agg.count < t.MinPreemptions {
					continue
				}
				mean := agg.sum / float64(agg.count)
				if mean <= threshold {
					continue
				}
				s := agg.sample
				ev := []detector.Evidence{
					detector.NewEvidence("mean_runqueue_latency", mean, threshold, "s"),
					detector.NewEvidence("preemptions", float64(agg.count), float64(t.MinPreemptions), "count"),
				}
				remediation := "The workload was runnable and had no CPU to run on: check " +
					"the node's CPU pressure and this container's CPU limit before looking " +
					"inside the application."
				if lock, ok := locks[key]; ok && lock.count > 0 {
					lockMean := lock.sum / float64(lock.count)
					ev = append(ev,
						detector.NewEvidence("mean_lock_wait", lockMean, 0, "s"),
						detector.NewEvidence("lock_waits", float64(lock.count), 0, "count"))
					if lockMean >= mean {
						remediation = "Lock waits here are longer than the scheduler waits, so " +
							"this is contention inside the application rather than for CPU. " +
							"A session with profiling on this workload shows which call sites " +
							"are holding the lock."
					}
				}
				issues = append(issues, detector.Issue{
					ID:       detector.IDCPUContention,
					Severity: alerting.SeverityWarning,
					Subject: detector.Subject{
						Namespace: s.Namespace,
						Workload:  s.Workload,
					},
					Evidence:    ev,
					Remediation: remediation,
					Message: fmt.Sprintf("CPU contention for %s/%s: %.0fms mean time runnable but not running across %d preemptions (threshold: %.0fms)",
						s.Namespace, s.Workload, mean*1000, agg.count, threshold*1000),
				})
			}
			return issues
		},
	}
}

// remediationForRTTSource keeps the advice honest about what was measured.
func remediationForRTTSource(source string) string {
	if source == "kernel smoothed RTT" {
		return "This is the kernel's own smoothed RTT, so the delay is on the wire " +
			"rather than in the application or its peer. Check node saturation and " +
			"the network path to the peer."
	}
	return "This times the send and receive calls themselves, so a slow peer and a " +
		"slow network path both land here. Compare the workload's egress edges on " +
		"the service map before suspecting the wire: if one dependency moved with " +
		"it, the peer is slow, not the network. Enabling the sock_ops RTT hook " +
		"replaces this reading with the kernel's own."
}

// dnsSlowLookupRule fires when too large a share of a workload's DNS
// resolutions answer slower than the slow bound.
func dnsSlowLookupRule() Rule {
	return Rule{
		ID:  detector.IDDNSSlowLookupRate,
		For: 3 * time.Minute,
		Query: `100 * (1 - (
  sum by (namespace, workload) (rate(podtrace_workload_dns_latency_seconds_bucket{le="0.1"}[5m]))
  / sum by (namespace, workload) (rate(podtrace_workload_dns_latency_seconds_count[5m]))))`,
		Eval: func(w Window, t Thresholds) []detector.Issue {
			if !w.Ready() || t.DNSSlowBound <= 0 {
				return nil
			}
			bound := t.DNSSlowBound.Seconds()
			interval := w.Interval()

			byWorkload := map[string]*workloadTotals{}
			for _, d := range w.Deltas(familyDNSLatency) {
				if d.Reset || d.Count == 0 {
					continue
				}
				share, ok := d.FractionAbove(bound)
				if !ok {
					continue
				}
				key := d.Sample.Namespace + "/" + d.Sample.Workload
				agg, found := byWorkload[key]
				if !found {
					agg = &workloadTotals{sample: d.Sample}
					byWorkload[key] = agg
				}
				agg.count += d.Count
				agg.above += share / 100 * float64(d.Count)
			}

			var issues []detector.Issue
			for _, agg := range byWorkload {
				perSecond := float64(agg.count) / interval.Seconds()
				if perSecond < t.MinRequestsPerSecond {
					continue
				}
				rate := agg.above / float64(agg.count) * 100
				if rate <= t.DNSSlowRatePercent {
					continue
				}
				s := agg.sample
				issues = append(issues, detector.Issue{
					ID:       detector.IDDNSSlowLookupRate,
					Severity: alerting.SeverityWarning,
					Subject: detector.Subject{
						Namespace: s.Namespace,
						Workload:  s.Workload,
					},
					Evidence: []detector.Evidence{
						detector.NewEvidence("slow_lookup_rate", rate, t.DNSSlowRatePercent, "%"),
						detector.NewEvidence("slow_bound", bound*1000, bound*1000, "ms"),
						detector.NewEvidence("slow_lookups", agg.above, 0, "count"),
						detector.NewEvidence("total_lookups", float64(agg.count), 0, "count"),
						detector.NewEvidence("lookup_rate", perSecond, t.MinRequestsPerSecond, "/s"),
					},
					Remediation: "Check whether CoreDNS's own upstream lookups slowed down with it: " +
						"if they did, the upstream resolver is the cause; if not, look at the " +
						"path between the workload and CoreDNS. A short ndots or a node-local " +
						"DNS cache cuts the number of lookups that leave the node.",
					Message: fmt.Sprintf("Slow DNS resolution for %s/%s: %.1f%% of %d lookups slower than %s (threshold: %.1f%%)",
						s.Namespace, s.Workload, rate, agg.count,
						t.DNSSlowBound.Round(time.Millisecond), t.DNSSlowRatePercent),
				})
			}
			return issues
		},
	}
}

// fsSlowOperationOps are the operations fs.slow_operations judges. Opens,
// closes, unlinks and renames are metadata operations with a latency of
// their own, and a close has none at all.
var fsSlowOperationOps = map[string]bool{"read": true, "write": true, "fsync": true}

// fsSlowOperationsRule fires when too large a share of a workload's
// regular-file reads, writes and fsyncs take longer than the slow bound.
func fsSlowOperationsRule() Rule {
	return Rule{
		ID:  detector.IDFSSlowOperations,
		For: 3 * time.Minute,
		Query: `100 * (1 - (
  sum by (namespace, workload) (rate(podtrace_workload_filesystem_latency_seconds_bucket{operation=~"read|write|fsync",le="0.05"}[5m]))
  / sum by (namespace, workload) (rate(podtrace_workload_filesystem_latency_seconds_count{operation=~"read|write|fsync"}[5m]))))`,
		Eval: func(w Window, t Thresholds) []detector.Issue {
			if !w.Ready() || t.FSSlowBound <= 0 {
				return nil
			}
			bound := t.FSSlowBound.Seconds()
			interval := w.Interval()

			byWorkload := map[string]*workloadTotals{}
			for _, d := range w.Deltas(familyFSLatency) {
				if d.Reset || d.Count == 0 || !fsSlowOperationOps[d.Sample.Label("operation")] {
					continue
				}
				share, ok := d.FractionAbove(bound)
				if !ok {
					continue
				}
				key := d.Sample.Namespace + "/" + d.Sample.Workload
				agg, found := byWorkload[key]
				if !found {
					agg = &workloadTotals{sample: d.Sample}
					byWorkload[key] = agg
				}
				agg.count += d.Count
				agg.above += share / 100 * float64(d.Count)
			}

			var issues []detector.Issue
			for _, agg := range byWorkload {
				perSecond := float64(agg.count) / interval.Seconds()
				if perSecond < t.MinRequestsPerSecond {
					continue
				}
				rate := agg.above / float64(agg.count) * 100
				if rate <= t.FSSlowRatePercent {
					continue
				}
				s := agg.sample
				issues = append(issues, detector.Issue{
					ID:       detector.IDFSSlowOperations,
					Severity: alerting.SeverityWarning,
					Subject: detector.Subject{
						Namespace: s.Namespace,
						Workload:  s.Workload,
					},
					Evidence: []detector.Evidence{
						detector.NewEvidence("slow_operation_rate", rate, t.FSSlowRatePercent, "%"),
						detector.NewEvidence("slow_bound", bound*1000, bound*1000, "ms"),
						detector.NewEvidence("slow_operations", agg.above, 0, "count"),
						detector.NewEvidence("total_operations", float64(agg.count), 0, "count"),
						detector.NewEvidence("operation_rate", perSecond, t.MinRequestsPerSecond, "/s"),
					},
					Remediation: "Look at the volume behind the workload: its storage class and IOPS " +
						"limit, a cgroup io.max on the pod, and other pods on the same node or " +
						"volume. A diagnose session names the files whose operations took 1ms or longer.",
					Message: fmt.Sprintf("Slow filesystem operations for %s/%s: %.1f%% of %d reads, writes and fsyncs took longer than %s (threshold: %.1f%%)",
						s.Namespace, s.Workload, rate, agg.count,
						t.FSSlowBound.Round(time.Millisecond), t.FSSlowRatePercent),
				})
			}
			return issues
		},
	}
}

// dnsFailureRateRule fires when too large a share of a workload's DNS
// lookups fail: a server failure, a refusal, another error rcode, or no
// answer at all.
func dnsFailureRateRule() Rule {
	return Rule{
		ID:  detector.IDDNSFailureRate,
		For: 3 * time.Minute,
		Query: `100 * sum by (namespace, workload) (rate(podtrace_workload_dns_lookups_total{rcode!~"NOERROR|NXDOMAIN"}[5m]))
  / sum by (namespace, workload) (rate(podtrace_workload_dns_lookups_total[5m]))`,
		Eval: func(w Window, t Thresholds) []detector.Issue {
			if !w.Ready() || t.DNSFailureRatePercent <= 0 {
				return nil
			}
			interval := w.Interval()

			byWorkload := map[string]*workloadTotals{}
			failedBy := map[string]map[string]float64{}
			for _, d := range w.Deltas(familyDNSLookups) {
				if d.Reset {
					continue
				}
				key := d.Sample.Namespace + "/" + d.Sample.Workload
				agg, ok := byWorkload[key]
				if !ok {
					agg = &workloadTotals{sample: d.Sample}
					byWorkload[key] = agg
					failedBy[key] = map[string]float64{}
				}
				agg.value += d.Value
				if answer := d.Sample.Label("rcode"); events.DNSAnswerFailed(answer) {
					agg.errors += d.Value
					failedBy[key][answer] += d.Value
				}
			}

			var issues []detector.Issue
			for key, agg := range byWorkload {
				if agg.value == 0 {
					continue
				}
				perSecond := agg.value / interval.Seconds()
				if perSecond < t.MinRequestsPerSecond {
					continue
				}
				rate := agg.errors / agg.value * 100
				if rate <= t.DNSFailureRatePercent {
					continue
				}
				s := agg.sample
				top := topDNSFailure(failedBy[key])
				issues = append(issues, detector.Issue{
					ID:       detector.IDDNSFailureRate,
					Severity: alerting.SeverityWarning,
					Subject: detector.Subject{
						Namespace: s.Namespace,
						Workload:  s.Workload,
					},
					Evidence: []detector.Evidence{
						detector.NewEvidence("failure_rate", rate, t.DNSFailureRatePercent, "%"),
						detector.NewEvidence("failed_lookups", agg.errors, 0, "count"),
						detector.NewEvidence("total_lookups", agg.value, 0, "count"),
						detector.NewEvidence("lookup_rate", perSecond, t.MinRequestsPerSecond, "/s"),
					},
					Remediation: remediationForDNSFailure(top),
					Message: fmt.Sprintf("DNS lookups failing for %s/%s: %.1f%% of %.0f lookups, mostly %s (threshold: %.1f%%)",
						s.Namespace, s.Workload, rate, agg.value, top, t.DNSFailureRatePercent),
				})
			}
			return issues
		},
	}
}

// topDNSFailure names the failure with the most lookups, the first by name
// on a tie, so the message is stable.
func topDNSFailure(failed map[string]float64) string {
	top, most := "", -1.0
	for answer, n := range failed {
		if n > most || (n == most && answer < top) {
			top, most = answer, n
		}
	}
	return top
}

// remediationForDNSFailure points at where each kind of failure is fixed.
func remediationForDNSFailure(answer string) string {
	switch answer {
	case events.DNSAnswerTimeout:
		return "Queries get no answer: check that CoreDNS (or the node-local cache) is running and " +
			"reachable, that no NetworkPolicy blocks port 53, and for conntrack races on UDP " +
			"(the five-second stall); the query's server is in the DNS event."
	case events.DNSAnswerServFail:
		return "The resolver could not answer: check CoreDNS's logs and its upstream resolvers, " +
			"since a SERVFAIL is usually the upstream timing out or failing DNSSEC."
	case events.DNSAnswerRefused:
		return "The server refused the query: check that the workload asks the cluster resolver " +
			"and that the server allows recursion for it."
	default:
		return "Check CoreDNS's logs for the rcode, and the workload's resolver configuration."
	}
}

// tlsHandshakeFailureRule fires when too large a share of a workload's TLS
// handshakes fail: failures from errors_total{kind="tls"}, divided by every
// handshake, failed ones included, from the handshake histogram's count.
func tlsHandshakeFailureRule() Rule {
	return Rule{
		ID:  detector.IDTLSHandshakeFailureRate,
		For: 3 * time.Minute,
		Query: `100 * sum by (namespace, workload) (rate(podtrace_workload_errors_total{kind="tls"}[5m]))
  / sum by (namespace, workload) (rate(podtrace_workload_tls_handshake_duration_seconds_count[5m]))`,
		Eval: func(w Window, t Thresholds) []detector.Issue {
			if !w.Ready() || t.TLSHandshakeFailurePercent <= 0 {
				return nil
			}
			interval := w.Interval()

			byWorkload := map[string]*workloadTotals{}
			for _, d := range w.Deltas(familyTLSHandshake) {
				if d.Reset || d.Count == 0 {
					continue
				}
				key := d.Sample.Namespace + "/" + d.Sample.Workload
				agg, ok := byWorkload[key]
				if !ok {
					agg = &workloadTotals{sample: d.Sample}
					byWorkload[key] = agg
				}
				agg.value += float64(d.Count)
			}
			for _, d := range w.Deltas(familyErrors) {
				if d.Reset || d.Sample.Label("kind") != "tls" {
					continue
				}
				if agg, ok := byWorkload[d.Sample.Namespace+"/"+d.Sample.Workload]; ok {
					agg.errors += d.Value
				}
			}

			var issues []detector.Issue
			for _, agg := range byWorkload {
				perSecond := agg.value / interval.Seconds()
				if perSecond < t.MinRequestsPerSecond {
					continue
				}
				rate := min(agg.errors/agg.value*100, 100)
				if rate <= t.TLSHandshakeFailurePercent {
					continue
				}
				s := agg.sample
				issues = append(issues, detector.Issue{
					ID:       detector.IDTLSHandshakeFailureRate,
					Severity: alerting.SeverityWarning,
					Subject: detector.Subject{
						Namespace: s.Namespace,
						Workload:  s.Workload,
					},
					Evidence: []detector.Evidence{
						detector.NewEvidence("failure_rate", rate, t.TLSHandshakeFailurePercent, "%"),
						detector.NewEvidence("failed_handshakes", agg.errors, 0, "count"),
						detector.NewEvidence("total_handshakes", agg.value, 0, "count"),
						detector.NewEvidence("handshake_rate", perSecond, t.MinRequestsPerSecond, "/s"),
					},
					Remediation: "Check the certificates on both sides (expiry, the chain the client trusts, " +
						"the name it asks for), that client and server share a TLS version and cipher, and " +
						"that the client is not speaking TLS to a plaintext port; the session report lists " +
						"which processes fail.",
					Message: fmt.Sprintf("TLS handshakes failing for %s/%s: %.1f%% of %.0f handshakes (threshold: %.1f%%)",
						s.Namespace, s.Workload, rate, agg.value, t.TLSHandshakeFailurePercent),
				})
			}
			return issues
		},
	}
}
