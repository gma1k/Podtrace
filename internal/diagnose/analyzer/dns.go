package analyzer

import (
	"net"
	"sort"
	"strings"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
)

// DNSLookups keeps the DNS events that are lookups, by the rule the metrics
// plane counts them with: not a connection to an encrypted resolver, and not
// a getaddrinfo call when the packets already show its queries.
func DNSLookups(responses []*events.Event, packetCapture bool) []*events.Event {
	out := make([]*events.Event, 0, len(responses))
	for _, e := range responses {
		if e != nil && e.CountsAsDNSLookup(packetCapture) {
			out = append(out, e)
		}
	}
	return out
}

// AnalyzeDNS aggregates DNS activity. Names and per-name lookup counts come
// from queries (every lookup, reliable even without a response).
func AnalyzeDNS(queries, responses []*events.Event) (avgLatency, maxLatency float64, errors int, p50, p95, p99 float64, topTargets []TargetCount) {
	var totalLatency float64
	var latencies []float64
	maxLatency = 0
	errors = 0

	for _, e := range responses {
		if e.IsError() {
			errors++
		}
		if e.DNSAnswer() == events.DNSAnswerTimeout {
			continue
		}
		latencyMs := float64(e.LatencyNS) / float64(config.NSPerMS)
		latencies = append(latencies, latencyMs)
		totalLatency += latencyMs
		if latencyMs > maxLatency {
			maxLatency = latencyMs
		}
	}

	if len(latencies) > 0 {
		avgLatency = totalLatency / float64(len(latencies))
		sort.Float64s(latencies)
		p50 = Percentile(latencies, 50)
		p95 = Percentile(latencies, 95)
		p99 = Percentile(latencies, 99)
	}

	nameSource := queries
	if len(nameSource) == 0 {
		nameSource = responses
	}
	targetMap := make(map[string]int)
	for _, e := range nameSource {
		if e.Target != "" && e.Target != "?" {
			targetMap[e.Target]++
		}
	}
	for target, count := range targetMap {
		topTargets = append(topTargets, TargetCount{target, count})
	}
	sortTargetCounts(topTargets)

	return
}

// DNSEncryptedResolvers counts the connections to encrypted resolvers (DoT,
// or DoH to a well-known resolver) by resolver, most first.
func DNSEncryptedResolvers(evs []*events.Event) []TargetCount {
	counts := make(map[string]int)
	for _, e := range evs {
		if e != nil && e.Type == events.EventDNS && e.DNSTransport == events.DNSSourceEncrypted {
			counts[e.Target]++
		}
	}
	return sortedNameCounts(counts)
}

// DNSAnswered counts the lookups that got an answer, whatever it was: the
// ones latency figures describe.
func DNSAnswered(responses []*events.Event) int {
	n := 0
	for _, e := range responses {
		if e != nil && e.DNSAnswer() != events.DNSAnswerTimeout {
			n++
		}
	}
	return n
}

// DNSRCodeBreakdown counts DNS responses by answer (NXDOMAIN, SERVFAIL,
// timeout, …), excluding NOERROR, sorted most-frequent first. It shows why
// lookups did not resolve rather than a bare error total.
func DNSRCodeBreakdown(responses []*events.Event) []TargetCount {
	counts := make(map[string]int)
	for _, e := range responses {
		if e == nil {
			continue
		}
		if answer := e.DNSAnswer(); answer != events.DNSAnswerNoError {
			counts[answer]++
		}
	}
	return sortedNameCounts(counts)
}

// DNSQueryTypeBreakdown counts DNS responses by query-type mnemonic (A, AAAA,
// …), sorted most-frequent first.
func DNSQueryTypeBreakdown(responses []*events.Event) []TargetCount {
	counts := make(map[string]int)
	for _, e := range responses {
		if e == nil {
			continue
		}
		counts[e.DNSQueryType()]++
	}
	return sortedNameCounts(counts)
}

// sortedNameCounts turns a name→count map into a slice ordered by count
// descending, then name ascending for a deterministic, stable rendering.
func sortedNameCounts(counts map[string]int) []TargetCount {
	out := make([]TargetCount, 0, len(counts))
	for name, count := range counts {
		out = append(out, TargetCount{Target: name, Count: count})
	}
	sortTargetCounts(out)
	return out
}

// sortTargetCounts orders targets by count, most first, and by name among
// equal counts so the top-N cut is the same on every run.
func sortTargetCounts(out []TargetCount) {
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Target < out[j].Target
	})
}

// TargetAddrs pairs a DNS name with the distinct addresses it resolved to.
type TargetAddrs struct {
	Target string
	Addrs  []string
}

// ResolvedAddresses aggregates the resolved A/AAAA addresses seen per DNS name
// across response events.
func ResolvedAddresses(responses []*events.Event) []TargetAddrs {
	var order []string
	byName := make(map[string]*TargetAddrs)
	seen := make(map[string]map[string]struct{})
	for _, e := range responses {
		if e.Target == "" || e.Details == "" {
			continue
		}
		for _, addr := range strings.Split(e.Details, ",") {
			addr = strings.TrimSpace(addr)
			if addr == "" || net.ParseIP(addr) == nil {
				continue
			}
			ta, ok := byName[e.Target]
			if !ok {
				ta = &TargetAddrs{Target: e.Target}
				byName[e.Target] = ta
				seen[e.Target] = make(map[string]struct{})
				order = append(order, e.Target)
			}
			if _, dup := seen[e.Target][addr]; dup {
				continue
			}
			seen[e.Target][addr] = struct{}{}
			ta.Addrs = append(ta.Addrs, addr)
		}
	}
	out := make([]TargetAddrs, 0, len(order))
	for _, name := range order {
		out = append(out, *byName[name])
	}
	sort.SliceStable(out, func(i, j int) bool {
		return len(out[i].Addrs) > len(out[j].Addrs)
	})
	return out
}
