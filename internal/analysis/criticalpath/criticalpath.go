// Package criticalpath breaks a request's duration down by where it went:
// waiting on the network, the database, the filesystem, a lock, and so on.
//
// The kernel stamps every event with the correlation id of the request its
// thread, goroutine or connection is serving, and reports when a served
// request finishes (events.EventRequestDone). The collector groups the events
// of each request by that id, so concurrent requests in one process are kept
// apart, and turns their intervals into exclusive time: a database call's
// socket wait is counted once, as database, and two calls made in parallel
// are counted once, so the shares of a request never add up to more than its
// duration.
package criticalpath

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/safeconv"
)

// Category is where a stretch of a request's time went.
type Category string

const (
	Database   Category = "database"
	Cache      Category = "cache"
	Messaging  Category = "messaging"
	DNS        Category = "dns"
	TLS        Category = "tls handshake"
	Connect    Category = "connect"
	Network    Category = "network"
	Filesystem Category = "filesystem"
	Lock       Category = "lock"

	Untraced Category = "not in traced I/O"
)

// precedence orders the categories from most to least specific. Where two
// intervals overlap, the time goes to the earlier one: a database query is
// also a socket read, and the query says more.
var precedence = []Category{Database, Cache, Messaging, DNS, TLS, Connect, Network, Filesystem, Lock}

const (
	maxOpenRequests      = 8192
	maxIntervals         = 512
	maxEndpoints         = 8192
	recentlyFinishedSize = 4096
	slowestKept          = 5
	maxEndpointSummaries = 64

	OtherEndpoints  = "(other endpoints)"
	UnknownEndpoint = "(endpoint not seen)"
)

// CategoryOf returns the category of an event's latency, and false for an
// event that is not a wait a request makes.
func CategoryOf(e *events.Event) (Category, bool) {
	switch e.Type {
	case events.EventDBQuery, events.EventDBAcquire:
		return Database, true
	case events.EventRedisCmd, events.EventMemcachedCmd:
		return Cache, true
	case events.EventKafkaProduce, events.EventKafkaFetch:
		return Messaging, true
	case events.EventDNS:
		return DNS, true
	case events.EventTLSHandshake:
		return TLS, true
	case events.EventConnect, events.EventConnectResult:
		return Connect, true
	case events.EventUDPSend, events.EventUDPRecv:
		if e.PeerDstPort == 53 || e.PeerSrcPort == 53 {
			return DNS, true
		}
		return Network, true
	case events.EventTCPSend, events.EventTCPRecv:
		return Network, true
	case events.EventRead, events.EventWrite, events.EventFsync, events.EventOpen,
		events.EventClose, events.EventUnlink, events.EventRename:
		return Filesystem, true
	case events.EventLockContention:
		return Lock, true
	}
	return "", false
}

// Share is one category's part of a duration.
type Share struct {
	Category Category
	Duration time.Duration
}

// Request is one finished request and where its time went.
type Request struct {
	Kind      string
	Endpoint  string
	Namespace string
	Pod       string
	Process   string
	Latency   time.Duration
	Shares    []Share
	Truncated bool
}

// EndpointSummary is where the requests of one endpoint spent their time.
type EndpointSummary struct {
	Endpoint   string
	Requests   int
	Total      time.Duration
	ByCategory map[Category]time.Duration
}

// Summary is everything the collector learned.
type Summary struct {
	Requests int
	ByKind   map[string]int

	Total      time.Duration
	ByCategory map[Category]time.Duration

	ByEndpoint []EndpointSummary

	Slowest []Request

	Late      int
	Evicted   int
	Truncated int
}

type interval struct {
	start, end uint64
	category   Category
}

type pending struct {
	intervals []interval
	truncated bool
}

// Collector accumulates requests from a stream of events. It is safe for
// concurrent use and bounded however long it runs.
type Collector struct {
	mu sync.Mutex

	open      map[uint64]*pending
	openOrder []uint64

	endpoints     map[uint64]string
	endpointOrder []uint64

	finished     map[uint64]struct{}
	finishedRing []uint64
	finishedNext int

	byEndpoint map[string]*EndpointSummary

	summary Summary
}

// New returns an empty collector.
func New() *Collector {
	return &Collector{
		open:       map[uint64]*pending{},
		endpoints:  map[uint64]string{},
		finished:   map[uint64]struct{}{},
		byEndpoint: map[string]*EndpointSummary{},
		summary: Summary{
			ByKind:     map[string]int{},
			ByCategory: map[Category]time.Duration{},
		},
	}
}

// Feed takes one event. Every event should be fed, before any sampling, or a
// request is compared with part of its own waits.
func (c *Collector) Feed(e *events.Event) {
	if c == nil || e == nil || e.CorrelationID == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	switch e.Type {
	case events.EventRequestDone:
		c.finish(e)
		return
	case events.EventHTTPReq, events.EventHTTPResp:
		if _, done := c.finished[e.CorrelationID]; done {
			return
		}
		if e.Target != "" {
			c.rememberEndpoint(e.CorrelationID, endpointOf(e))
		}
		return
	}

	category, ok := CategoryOf(e)
	if !ok || e.LatencyNS == 0 || e.LatencyNS > e.Timestamp {
		return
	}
	if _, done := c.finished[e.CorrelationID]; done {
		c.summary.Late++
		return
	}
	p := c.open[e.CorrelationID]
	if p == nil {
		if len(c.open) >= maxOpenRequests {
			c.evictOldest()
		}
		p = &pending{}
		c.open[e.CorrelationID] = p
		c.openOrder = append(c.openOrder, e.CorrelationID)
	}
	if len(p.intervals) >= maxIntervals {
		p.truncated = true
		return
	}
	p.intervals = append(p.intervals, interval{
		start:    e.Timestamp - e.LatencyNS,
		end:      e.Timestamp,
		category: category,
	})
}

// Summary returns a copy of what has been collected.
func (c *Collector) Summary() Summary {
	if c == nil {
		return Summary{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.summary
	out.ByKind = make(map[string]int, len(c.summary.ByKind))
	for k, v := range c.summary.ByKind {
		out.ByKind[k] = v
	}
	out.ByCategory = make(map[Category]time.Duration, len(c.summary.ByCategory))
	for k, v := range c.summary.ByCategory {
		out.ByCategory[k] = v
	}
	out.Slowest = append([]Request(nil), c.summary.Slowest...)
	out.ByEndpoint = make([]EndpointSummary, 0, len(c.byEndpoint))
	for _, e := range c.byEndpoint {
		cp := *e
		cp.ByCategory = make(map[Category]time.Duration, len(e.ByCategory))
		for k, v := range e.ByCategory {
			cp.ByCategory[k] = v
		}
		out.ByEndpoint = append(out.ByEndpoint, cp)
	}
	sort.Slice(out.ByEndpoint, func(i, j int) bool {
		if out.ByEndpoint[i].Total != out.ByEndpoint[j].Total {
			return out.ByEndpoint[i].Total > out.ByEndpoint[j].Total
		}
		return out.ByEndpoint[i].Endpoint < out.ByEndpoint[j].Endpoint
	})
	return out
}

func (c *Collector) addToEndpoint(endpoint string, latency time.Duration, shares []Share) {
	if endpoint == "" {
		endpoint = UnknownEndpoint
	}
	e := c.byEndpoint[endpoint]
	if e == nil {
		if len(c.byEndpoint) >= maxEndpointSummaries-1 {
			endpoint = OtherEndpoints
			e = c.byEndpoint[endpoint]
		}
		if e == nil {
			e = &EndpointSummary{Endpoint: endpoint, ByCategory: map[Category]time.Duration{}}
			c.byEndpoint[endpoint] = e
		}
	}
	e.Requests++
	e.Total += latency
	for _, s := range shares {
		e.ByCategory[s.Category] += s.Duration
	}
}

func (c *Collector) finish(e *events.Event) {
	id := e.CorrelationID
	p := c.open[id]
	delete(c.open, id)
	endpoint := c.endpoints[id]
	delete(c.endpoints, id)
	c.markFinished(id)

	end := e.Timestamp
	start := end
	if e.LatencyNS <= end {
		start = end - e.LatencyNS
	}
	var intervals []interval
	truncated := false
	if p != nil {
		intervals = p.intervals
		truncated = p.truncated
	}
	shares := breakdown(start, end, intervals)

	kind := KindName(e.TCPState)
	latency := nanoseconds(end - start)
	c.summary.Requests++
	c.summary.ByKind[kind]++
	c.summary.Total += latency
	for _, s := range shares {
		c.summary.ByCategory[s.Category] += s.Duration
	}
	if truncated {
		c.summary.Truncated++
	}

	r := Request{
		Kind:      kind,
		Endpoint:  endpoint,
		Process:   e.ProcessName,
		Latency:   latency,
		Shares:    shares,
		Truncated: truncated,
	}
	if e.K8s != nil {
		r.Namespace, r.Pod = e.K8s.Namespace, e.K8s.PodName
	}
	c.addToEndpoint(endpoint, r.Latency, shares)
	c.keepIfSlow(r)
}

func (c *Collector) keepIfSlow(r Request) {
	s := c.summary.Slowest
	if len(s) == slowestKept && r.Latency <= s[len(s)-1].Latency {
		return
	}
	i := sort.Search(len(s), func(i int) bool { return s[i].Latency < r.Latency })
	s = append(s, Request{})
	copy(s[i+1:], s[i:])
	s[i] = r
	if len(s) > slowestKept {
		s = s[:slowestKept]
	}
	c.summary.Slowest = s
}

func (c *Collector) rememberEndpoint(id uint64, endpoint string) {
	if _, ok := c.endpoints[id]; ok {
		return
	}
	for len(c.endpoints) >= maxEndpoints && len(c.endpointOrder) > 0 {
		oldest := c.endpointOrder[0]
		c.endpointOrder = c.endpointOrder[1:]
		delete(c.endpoints, oldest)
	}
	c.endpoints[id] = endpoint
	c.endpointOrder = append(c.endpointOrder, id)
}

func (c *Collector) evictOldest() {
	for len(c.openOrder) > 0 {
		oldest := c.openOrder[0]
		c.openOrder = c.openOrder[1:]
		if _, ok := c.open[oldest]; ok {
			delete(c.open, oldest)
			c.summary.Evicted++
			return
		}
	}
}

func (c *Collector) markFinished(id uint64) {
	if len(c.finishedRing) < recentlyFinishedSize {
		c.finishedRing = append(c.finishedRing, id)
	} else {
		delete(c.finished, c.finishedRing[c.finishedNext])
		c.finishedRing[c.finishedNext] = id
		c.finishedNext = (c.finishedNext + 1) % recentlyFinishedSize
	}
	c.finished[id] = struct{}{}
	c.openOrder = compactOrder(c.openOrder, maxOpenRequests, func(k uint64) bool { _, ok := c.open[k]; return ok })
	c.endpointOrder = compactOrder(c.endpointOrder, maxEndpoints, func(k uint64) bool { _, ok := c.endpoints[k]; return ok })
}

// compactOrder drops the ids that are no longer live from an insertion-order
// slice once it holds twice the live bound: finished requests leave their ids
// behind, and a long collection would otherwise keep every one.
func compactOrder(order []uint64, bound int, live func(uint64) bool) []uint64 {
	if len(order) <= 2*bound {
		return order
	}
	kept := order[:0]
	for _, k := range order {
		if live(k) {
			kept = append(kept, k)
		}
	}
	return kept
}

// breakdown divides [start, end] between the categories of the intervals
// that cover it, giving overlapping time to the most specific one, and the
// rest to Untraced. The shares sum to end-start.
func breakdown(start, end uint64, intervals []interval) []Share {
	if end <= start {
		return nil
	}
	type edge struct {
		at    uint64
		rank  int
		delta int
	}
	rankOf := make(map[Category]int, len(precedence))
	for i, c := range precedence {
		rankOf[c] = i
	}
	edges := make([]edge, 0, 2*len(intervals))
	for _, iv := range intervals {
		s, e := max(iv.start, start), min(iv.end, end)
		if e <= s {
			continue
		}
		r, ok := rankOf[iv.category]
		if !ok {
			continue
		}
		edges = append(edges, edge{s, r, +1}, edge{e, r, -1})
	}
	sort.Slice(edges, func(i, j int) bool { return edges[i].at < edges[j].at })

	active := make([]int, len(precedence))
	spent := make([]uint64, len(precedence))
	var untraced uint64
	cursor := start
	account := func(to uint64) {
		if to <= cursor {
			return
		}
		top := -1
		for r, n := range active {
			if n > 0 {
				top = r
				break
			}
		}
		if top < 0 {
			untraced += to - cursor
		} else {
			spent[top] += to - cursor
		}
		cursor = to
	}
	for _, e := range edges {
		account(e.at)
		active[e.rank] += e.delta
	}
	account(end)

	var shares []Share
	for r, ns := range spent {
		if ns > 0 {
			shares = append(shares, Share{Category: precedence[r], Duration: nanoseconds(ns)})
		}
	}
	if untraced > 0 {
		shares = append(shares, Share{Category: Untraced, Duration: nanoseconds(untraced)})
	}
	sort.SliceStable(shares, func(i, j int) bool { return shares[i].Duration > shares[j].Duration })
	return shares
}

// nanoseconds converts a kernel nanosecond count to a Duration, clamping a
// count beyond what a Duration holds rather than wrapping it negative.
func nanoseconds(ns uint64) time.Duration {
	return time.Duration(safeconv.Uint64ToInt64(ns))
}

const goBit = 0x100

// KindName names the protocol a request-done event's kind field describes.
func KindName(kind uint32) string {
	if kind&goBit != 0 {
		switch kind &^ goBit {
		case 1:
			return "Go net/http"
		case 2:
			return "Go HTTP/2"
		case 3:
			return "Go gRPC"
		case 4:
			return "Go HTTP/3"
		}
		return "Go"
	}
	switch kind {
	case 0:
		return "HTTP/1"
	case 1:
		return "HTTP/2"
	case 2:
		return "HTTP/3"
	}
	return "other"
}

// endpointOf names a request's endpoint. An HTTP/1 target already starts
// with its method; other protocols carry the method apart.
func endpointOf(e *events.Event) string {
	if e.HTTPMethod != "" && !strings.HasPrefix(e.Target, e.HTTPMethod+" ") {
		return e.HTTPMethod + " " + e.Target
	}
	return e.Target
}
