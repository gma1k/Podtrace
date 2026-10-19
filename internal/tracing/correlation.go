package tracing

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"sync"
	"time"

	"github.com/gma1k/podtrace/internal/events"
)

// correlationKey identifies one L7 request across its request and response
// events.
func correlationKey(e *events.Event) string {
	return strconv.FormatUint(e.CorrelationID, 10)
}

// deriveSpanID produces a stable 8-byte span id from a correlation key.
func deriveSpanID(key string) string {
	sum := sha256.Sum256([]byte("span\x00" + key))
	return hex.EncodeToString(sum[:8])
}

// deriveTraceID produces a stable 16-byte trace id from a correlation key,
// used only when synthesizing a trace for context-less traffic.
func deriveTraceID(key string) string {
	sum := sha256.Sum256([]byte("trace\x00" + key))
	return hex.EncodeToString(sum[:16])
}

// correlationEntry is the inbound trace context of a request, held until its
// response event arrives so the response (which carries no headers) can join
// the same span.
type correlationEntry struct {
	traceID      string
	parentSpanID string
	spanID       string
	flags        uint8
	state        string
	storedNS     int64
}

// correlationCache carries a request's inbound trace context to its response
// event.
type correlationCache struct {
	mu         sync.Mutex
	m          map[string]*list.Element
	order      *list.List
	maxEntries int
	evicted    uint64
}

type correlationItem struct {
	key   string
	entry correlationEntry
}

func newCorrelationCache(maxEntries int) *correlationCache {
	return &correlationCache{m: make(map[string]*list.Element), order: list.New(), maxEntries: maxEntries}
}

func (c *correlationCache) store(key string, e correlationEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e.storedNS = time.Now().UnixNano()
	if el, ok := c.m[key]; ok {
		el.Value.(*correlationItem).entry = e
		c.order.MoveToFront(el)
		return
	}
	for len(c.m) > 0 && len(c.m) >= c.maxEntries {
		c.removeLocked(c.order.Back())
		c.evicted++
	}
	c.m[key] = c.order.PushFront(&correlationItem{key: key, entry: e})
}

func (c *correlationCache) loadDelete(key string) (correlationEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.m[key]
	if !ok {
		return correlationEntry{}, false
	}
	c.removeLocked(el)
	return el.Value.(*correlationItem).entry, true
}

// sweep drops entries older than maxAge (requests that never got a response).
// The list is in store order, so it stops at the first fresh entry.
func (c *correlationCache) sweep(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge).UnixNano()
	c.mu.Lock()
	defer c.mu.Unlock()
	for el := c.order.Back(); el != nil; el = c.order.Back() {
		if el.Value.(*correlationItem).entry.storedNS >= cutoff {
			return
		}
		c.removeLocked(el)
	}
}

func (c *correlationCache) removeLocked(el *list.Element) {
	delete(c.m, el.Value.(*correlationItem).key)
	c.order.Remove(el)
}

// isCorrelatableL7 reports whether an event is one half of an L7 request/
// response pair that carries a correlation id. HTTP/1.x, HTTP/2, HTTP/3 and
// gRPC all surface as EventHTTPReq/EventHTTPResp.
func isCorrelatableL7(e *events.Event) bool {
	return e.CorrelationID != 0 &&
		(e.Type == events.EventHTTPReq || e.Type == events.EventHTTPResp)
}
