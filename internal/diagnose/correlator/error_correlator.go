package correlator

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/sanitize"
)

type ErrorChain struct {
	RootCause   *ErrorEvent
	Chain       []*ErrorEvent
	Suggestions []string
	Severity    string
}

type ErrorEvent struct {
	Event     *events.Event
	Timestamp time.Time
	ErrorCode int32
	Operation string
	Target    string
	Context   map[string]string
}

// maxRetainedErrors bounds the correlator's error buffer.
const maxRetainedErrors = 10000

type ErrorCorrelator struct {
	mu         sync.Mutex
	seen       int
	errors     []*ErrorEvent
	chains     []*ErrorChain
	timeWindow time.Duration
	dirty      bool
}

func NewErrorCorrelator(timeWindow time.Duration) *ErrorCorrelator {
	if timeWindow == 0 {
		timeWindow = 30 * time.Second
	}
	return &ErrorCorrelator{
		errors:     make([]*ErrorEvent, 0),
		chains:     make([]*ErrorChain, 0),
		timeWindow: timeWindow,
	}
}

func (ec *ErrorCorrelator) AddEvent(event *events.Event, k8sContext interface{}) {
	if event == nil || !event.IsError() {
		return
	}

	ec.mu.Lock()
	defer ec.mu.Unlock()

	errorEvent := &ErrorEvent{
		Event:     event,
		Timestamp: event.TimestampTime(),
		ErrorCode: event.Error,
		Operation: event.TypeString(),
		Target:    event.Target,
		Context:   make(map[string]string),
	}

	if ctx, ok := k8sContext.(map[string]interface{}); ok {
		if targetPod, ok := ctx["target_pod"].(string); ok && targetPod != "" {
			errorEvent.Context["target_pod"] = targetPod
		}
		if targetService, ok := ctx["target_service"].(string); ok && targetService != "" {
			errorEvent.Context["target_service"] = targetService
		}
		if namespace, ok := ctx["target_namespace"].(string); ok && namespace != "" {
			errorEvent.Context["namespace"] = namespace
		}
	}

	ec.seen++
	ec.errors = append(ec.errors, errorEvent)
	if len(ec.errors) > maxRetainedErrors {
		drop := len(ec.errors) - maxRetainedErrors
		ec.errors = ec.errors[:copy(ec.errors, ec.errors[drop:])]
	}
	ec.dirty = true
}

// ensureChains rebuilds the chain set if errors changed since the last
// build.
func (ec *ErrorCorrelator) ensureChains() {
	if ec.dirty {
		ec.buildChains()
		ec.dirty = false
	}
}

func (ec *ErrorCorrelator) buildChains() {
	ec.chains = make([]*ErrorChain, 0)

	if len(ec.errors) == 0 {
		return
	}

	sort.Slice(ec.errors, func(i, j int) bool {
		return ec.errors[i].Timestamp.Before(ec.errors[j].Timestamp)
	})

	type openChain struct {
		root  time.Time
		chain []*ErrorEvent
	}
	open := map[string]*openChain{}
	flush := func(oc *openChain) {
		if oc == nil || len(oc.chain) <= 1 {
			return
		}
		ec.chains = append(ec.chains, &ErrorChain{
			RootCause:   oc.chain[0],
			Chain:       oc.chain,
			Suggestions: ec.generateSuggestions(oc.chain),
			Severity:    ec.calculateSeverity(oc.chain),
		})
	}
	for _, e := range ec.errors {
		key := errorChainKey(e)
		if key == "" {
			continue
		}
		oc := open[key]
		if oc == nil || e.Timestamp.Sub(oc.root) > ec.timeWindow {
			flush(oc)
			open[key] = &openChain{root: e.Timestamp, chain: []*ErrorEvent{e}}
			continue
		}
		oc.chain = append(oc.chain, e)
	}
	for _, oc := range open {
		flush(oc)
	}
	sort.Slice(ec.chains, func(i, j int) bool {
		return ec.chains[i].RootCause.Timestamp.Before(ec.chains[j].RootCause.Timestamp)
	})
}

// errorChainKey is the identifier errors are grouped by, most specific first.
// Errors with no identifier are not chained.
func errorChainKey(e *ErrorEvent) string {
	if e.Target != "" {
		return "t:" + e.Target
	}
	if p := e.Context["target_pod"]; p != "" {
		return "p:" + p
	}
	if s := e.Context["target_service"]; s != "" {
		return "s:" + s
	}
	return ""
}

func (ec *ErrorCorrelator) isRelated(err1, err2 *ErrorEvent) bool {
	if err1.Target != "" && err2.Target != "" && err1.Target == err2.Target {
		return true
	}

	if err1.Context["target_pod"] != "" && err2.Context["target_pod"] != "" {
		if err1.Context["target_pod"] == err2.Context["target_pod"] {
			return true
		}
	}

	if err1.Context["target_service"] != "" && err2.Context["target_service"] != "" {
		if err1.Context["target_service"] == err2.Context["target_service"] {
			return true
		}
	}

	return false
}

// dnsSuggestions is where each kind of failed lookup is fixed. A DNS event's
// error is an rcode or a timeout, not an errno, so the errno suggestions do
// not apply to it.
var dnsSuggestions = map[string]string{
	events.DNSAnswerTimeout:  "No answer from the resolver - check that it is running and reachable on port 53, and for conntrack races on UDP",
	events.DNSAnswerServFail: "The resolver could not answer - check its logs and its upstream resolvers",
	events.DNSAnswerRefused:  "The server refused the query - check which server the workload asks and whether it allows recursion",
	events.DNSAnswerOther:    "The server answered with an error rcode - check its logs",
}

const maxBreakdownRows = 10

const maxExampleTargetLen = 80

// errorBreakdown says which events the error total counts: grouped by
// operation and error, most frequent first, each with an example target.
func errorBreakdown(errs []*ErrorEvent) string {
	type group struct {
		operation, code, example string
		count                    int
	}
	byKey := make(map[string]*group)
	for _, e := range errs {
		code := errorCodeText(e)
		key := e.Operation + "\x00" + code
		g, ok := byKey[key]
		if !ok {
			g = &group{operation: e.Operation, code: code}
			byKey[key] = g
		}
		g.count++
		if g.example == "" && e.Target != "" {
			g.example = e.Target
		}
	}
	groups := make([]*group, 0, len(byKey))
	for _, g := range byKey {
		groups = append(groups, g)
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].count != groups[j].count {
			return groups[i].count > groups[j].count
		}
		if groups[i].operation != groups[j].operation {
			return groups[i].operation < groups[j].operation
		}
		return groups[i].code < groups[j].code
	})

	out := "  Errors by operation:\n"
	for i, g := range groups {
		if i == maxBreakdownRows {
			out += fmt.Sprintf("    - ... %d more kinds\n", len(groups)-maxBreakdownRows)
			break
		}
		line := fmt.Sprintf("    - %s (%s): %d", g.operation, g.code, g.count)
		if g.example != "" {
			line += ", e.g. " + events.TruncateString(sanitize.Terminal(g.example), maxExampleTargetLen)
		}
		out += line + "\n"
	}
	return out
}

func errorCodeText(e *ErrorEvent) string {
	if e.Event != nil && e.Event.Type == events.EventDNS {
		return "answer: " + e.Event.DNSAnswer()
	}
	return fmt.Sprintf("code: %d", e.ErrorCode)
}

func (ec *ErrorCorrelator) generateSuggestions(chain []*ErrorEvent) []string {
	suggestions := make([]string, 0)

	errorCodes := make(map[int32]int)
	dnsAnswers := make(map[string]bool)
	for _, err := range chain {
		if err.Event != nil && err.Event.Type == events.EventDNS {
			dnsAnswers[err.Event.DNSAnswer()] = true
			continue
		}
		errorCodes[err.ErrorCode]++
	}
	for _, answer := range []string{events.DNSAnswerTimeout, events.DNSAnswerServFail, events.DNSAnswerRefused, events.DNSAnswerOther} {
		if dnsAnswers[answer] {
			suggestions = append(suggestions, dnsSuggestions[answer])
		}
	}

	codes := make([]int32, 0, len(errorCodes))
	for code := range errorCodes {
		codes = append(codes, code)
	}
	sort.Slice(codes, func(i, j int) bool { return codes[i] > codes[j] })
	for _, code := range codes {
		count := errorCodes[code]
		switch code {
		case -11:
			if count > 5 {
				suggestions = append(suggestions, "High EAGAIN errors detected - consider increasing buffer sizes or reducing load")
			}
		case -111:
			suggestions = append(suggestions, "Connection refused errors - check if target service is running and accessible")
		case -110:
			suggestions = append(suggestions, "Connection timed out - check network connectivity and firewall rules")
		case -2:
			suggestions = append(suggestions, "No such file or directory - verify file paths and permissions")
		case -13:
			suggestions = append(suggestions, "Permission denied - check file/directory permissions")
		}
	}

	if len(chain) > 10 {
		suggestions = append(suggestions, "High error rate detected - investigate root cause and consider circuit breaker pattern")
	}

	targetPod := chain[0].Context["target_pod"]
	if targetPod != "" {
		suggestions = append(suggestions, fmt.Sprintf("Errors related to pod %s - check pod health and resource limits", sanitize.Terminal(targetPod)))
	}

	targetService := chain[0].Context["target_service"]
	if targetService != "" {
		suggestions = append(suggestions, fmt.Sprintf("Errors related to service %s - check service endpoints and health", sanitize.Terminal(targetService)))
	}

	return suggestions
}

func (ec *ErrorCorrelator) calculateSeverity(chain []*ErrorEvent) string {
	if len(chain) > 20 {
		return "critical"
	}
	if len(chain) > 10 {
		return "high"
	}
	if len(chain) > 5 {
		return "medium"
	}
	return "low"
}

func (ec *ErrorCorrelator) GetChains() []*ErrorChain {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.ensureChains()
	out := make([]*ErrorChain, len(ec.chains))
	copy(out, ec.chains)
	return out
}

func (ec *ErrorCorrelator) GetErrorSummary() string {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	if len(ec.errors) == 0 {
		return ""
	}
	ec.ensureChains()

	report := "Error Correlation & Root Cause Analysis:\n"
	report += fmt.Sprintf("  Total errors: %d\n", ec.seen)
	if ec.seen > len(ec.errors) {
		report += fmt.Sprintf("  Correlated below: the most recent %d (older errors are not retained)\n", len(ec.errors))
	}
	report += errorBreakdown(ec.errors)
	report += fmt.Sprintf("  Error chains: %d\n", len(ec.chains))

	if len(ec.chains) > 0 {
		report += "  Top error chains:\n"
		maxChains := 5
		if len(ec.chains) < maxChains {
			maxChains = len(ec.chains)
		}

		for i := 0; i < maxChains; i++ {
			chain := ec.chains[i]
			report += fmt.Sprintf("    Chain %d (Severity: %s):\n", i+1, chain.Severity)
			report += fmt.Sprintf("      Root cause: %s error on %s (%s)\n",
				chain.RootCause.Operation, sanitize.Terminal(chain.RootCause.Target), errorCodeText(chain.RootCause))
			report += fmt.Sprintf("      Chain length: %d errors\n", len(chain.Chain))
			report += fmt.Sprintf("      Time window: %s\n", chain.Chain[len(chain.Chain)-1].Timestamp.Sub(chain.RootCause.Timestamp))

			if len(chain.Suggestions) > 0 {
				report += "      Suggestions:\n"
				for _, suggestion := range chain.Suggestions {
					report += fmt.Sprintf("        - %s\n", suggestion)
				}
			}
		}
	}

	report += "\n"
	return report
}
