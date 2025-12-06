package correlator

import (
	"fmt"
	"sort"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

type ErrorChain struct {
	RootCause    *ErrorEvent
	Chain        []*ErrorEvent
	Suggestions  []string
	Severity     string
}

type ErrorEvent struct {
	Event       *events.Event
	Timestamp   time.Time
	ErrorCode   int32
	Operation   string
	Target      string
	Context     map[string]string
}

type ErrorCorrelator struct {
	errors      []*ErrorEvent
	chains      []*ErrorChain
	timeWindow  time.Duration
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
	if event == nil || event.Error == 0 {
		return
	}

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

	ec.errors = append(ec.errors, errorEvent)
	ec.buildChains()
}

func (ec *ErrorCorrelator) buildChains() {
	ec.chains = make([]*ErrorChain, 0)

	if len(ec.errors) == 0 {
		return
	}

	sort.Slice(ec.errors, func(i, j int) bool {
		return ec.errors[i].Timestamp.Before(ec.errors[j].Timestamp)
	})

	for i, rootError := range ec.errors {
		chain := []*ErrorEvent{rootError}
		rootTime := rootError.Timestamp

		for j := i + 1; j < len(ec.errors); j++ {
			nextError := ec.errors[j]
			if nextError.Timestamp.Sub(rootTime) <= ec.timeWindow {
				if ec.isRelated(rootError, nextError) {
					chain = append(chain, nextError)
				}
			} else {
				break
			}
		}

		if len(chain) > 1 {
			suggestions := ec.generateSuggestions(chain)
			severity := ec.calculateSeverity(chain)

			ec.chains = append(ec.chains, &ErrorChain{
				RootCause:   chain[0],
				Chain:       chain,
				Suggestions: suggestions,
				Severity:    severity,
			})
		}
	}
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

func (ec *ErrorCorrelator) generateSuggestions(chain []*ErrorEvent) []string {
	suggestions := make([]string, 0)

	errorCodes := make(map[int32]int)
	for _, err := range chain {
		errorCodes[err.ErrorCode]++
	}

	for code, count := range errorCodes {
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
		suggestions = append(suggestions, fmt.Sprintf("Errors related to pod %s - check pod health and resource limits", targetPod))
	}

	targetService := chain[0].Context["target_service"]
	if targetService != "" {
		suggestions = append(suggestions, fmt.Sprintf("Errors related to service %s - check service endpoints and health", targetService))
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
	return ec.chains
}

func (ec *ErrorCorrelator) GetErrorSummary() string {
	if len(ec.errors) == 0 {
		return ""
	}

	report := "Error Correlation & Root Cause Analysis:\n"
	report += fmt.Sprintf("  Total errors: %d\n", len(ec.errors))
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
			report += fmt.Sprintf("      Root cause: %s error on %s (code: %d)\n",
				chain.RootCause.Operation, chain.RootCause.Target, chain.RootCause.ErrorCode)
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

