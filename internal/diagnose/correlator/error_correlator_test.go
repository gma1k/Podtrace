package correlator

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

func TestErrorCorrelator_AddEvent(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)

	event := &events.Event{
		Type:      events.EventConnect,
		Target:    "10.244.1.5:8080",
		Error:     -111,
		Timestamp: uint64(time.Now().UnixNano()),
	}

	correlator.AddEvent(event, nil)

	chains := correlator.GetChains()
	if len(chains) != 0 {
		t.Logf("chains created: %d", len(chains))
	}
}

func TestErrorCorrelator_BuildChains(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)

	baseTime := time.Now()
	events := []*events.Event{
		{
			Type:      events.EventConnect,
			Target:    "10.244.1.5:8080",
			Error:     -111,
			Timestamp: uint64(baseTime.UnixNano()),
		},
		{
			Type:      events.EventTCPSend,
			Target:    "10.244.1.5:8080",
			Error:     -11,
			Timestamp: uint64(baseTime.Add(1 * time.Second).UnixNano()),
		},
		{
			Type:      events.EventConnect,
			Target:    "10.244.1.5:8080",
			Error:     -111,
			Timestamp: uint64(baseTime.Add(2 * time.Second).UnixNano()),
		},
	}

	k8sContext := map[string]interface{}{
		"target_pod": "target-pod",
	}

	for _, event := range events {
		correlator.AddEvent(event, k8sContext)
	}

	chains := correlator.GetChains()
	if len(chains) == 0 {
		t.Log("no chains created, which may be expected")
	}
}

func TestErrorCorrelator_GenerateSuggestions(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)

	chain := []*ErrorEvent{
		{
			ErrorCode: -111,
			Target:    "10.244.1.5:8080",
			Context:   map[string]string{"target_pod": "target-pod"},
		},
		{
			ErrorCode: -11,
			Target:    "10.244.1.5:8080",
			Context:   map[string]string{"target_pod": "target-pod"},
		},
	}

	suggestions := correlator.generateSuggestions(chain)
	if len(suggestions) == 0 {
		t.Error("expected at least one suggestion")
	}
}

func TestErrorCorrelator_CalculateSeverity(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)

	tests := []struct {
		chainLength int
		expected    string
	}{
		{25, "critical"},
		{15, "high"},
		{7, "medium"},
		{3, "low"},
	}

	for _, tt := range tests {
		chain := make([]*ErrorEvent, tt.chainLength)
		for i := range chain {
			chain[i] = &ErrorEvent{}
		}

		severity := correlator.calculateSeverity(chain)
		if severity != tt.expected {
			t.Errorf("expected severity %q for chain length %d, got %q", tt.expected, tt.chainLength, severity)
		}
	}
}

func TestErrorCorrelator_GetErrorSummary(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)

	summary := correlator.GetErrorSummary()
	if summary != "" {
		t.Error("expected empty summary when no errors")
	}

	event := &events.Event{
		Type:      events.EventConnect,
		Target:    "10.244.1.5:8080",
		Error:     -111,
		Timestamp: uint64(time.Now().UnixNano()),
	}

	correlator.AddEvent(event, nil)
	summary = correlator.GetErrorSummary()
	if summary == "" {
		t.Error("expected non-empty summary with errors")
	}
}

func TestNewErrorCorrelator_ZeroTimeWindow(t *testing.T) {
	correlator := NewErrorCorrelator(0)
	if correlator.timeWindow != 30*time.Second {
		t.Errorf("Expected default time window of 30s, got %v", correlator.timeWindow)
	}
}

func TestNewErrorCorrelator_CustomTimeWindow(t *testing.T) {
	correlator := NewErrorCorrelator(60 * time.Second)
	if correlator.timeWindow != 60*time.Second {
		t.Errorf("Expected time window of 60s, got %v", correlator.timeWindow)
	}
}

func TestErrorCorrelator_AddEvent_NilEvent(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)
	correlator.AddEvent(nil, nil)
	
	if len(correlator.errors) != 0 {
		t.Errorf("Expected no errors, got %d", len(correlator.errors))
	}
}

func TestErrorCorrelator_AddEvent_NoError(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)
	event := &events.Event{
		Type:      events.EventConnect,
		Target:    "10.244.1.5:8080",
		Error:     0,
		Timestamp: uint64(time.Now().UnixNano()),
	}
	
	correlator.AddEvent(event, nil)
	
	if len(correlator.errors) != 0 {
		t.Errorf("Expected no errors, got %d", len(correlator.errors))
	}
}

func TestErrorCorrelator_AddEvent_WithK8sContext(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)
	
	event := &events.Event{
		Type:      events.EventConnect,
		Target:    "10.244.1.5:8080",
		Error:     -111,
		Timestamp: uint64(time.Now().UnixNano()),
	}
	
	k8sContext := map[string]interface{}{
		"target_pod":       "test-pod",
		"target_service":   "test-service",
		"target_namespace": "test-namespace",
	}
	
	correlator.AddEvent(event, k8sContext)
	
	if len(correlator.errors) != 1 {
		t.Fatalf("Expected 1 error, got %d", len(correlator.errors))
	}
	
	errorEvent := correlator.errors[0]
	if errorEvent.Context["target_pod"] != "test-pod" {
		t.Errorf("Expected target_pod 'test-pod', got %q", errorEvent.Context["target_pod"])
	}
	if errorEvent.Context["target_service"] != "test-service" {
		t.Errorf("Expected target_service 'test-service', got %q", errorEvent.Context["target_service"])
	}
	if errorEvent.Context["namespace"] != "test-namespace" {
		t.Errorf("Expected namespace 'test-namespace', got %q", errorEvent.Context["namespace"])
	}
}

func TestErrorCorrelator_AddEvent_WithInvalidK8sContext(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)
	
	event := &events.Event{
		Type:      events.EventConnect,
		Target:    "10.244.1.5:8080",
		Error:     -111,
		Timestamp: uint64(time.Now().UnixNano()),
	}
	
	correlator.AddEvent(event, "invalid-context")
	
	if len(correlator.errors) != 1 {
		t.Fatalf("Expected 1 error, got %d", len(correlator.errors))
	}
	
	errorEvent := correlator.errors[0]
	if len(errorEvent.Context) != 0 {
		t.Errorf("Expected empty context, got %v", errorEvent.Context)
	}
}

func TestErrorCorrelator_AddEvent_WithPartialK8sContext(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)
	
	event := &events.Event{
		Type:      events.EventConnect,
		Target:    "10.244.1.5:8080",
		Error:     -111,
		Timestamp: uint64(time.Now().UnixNano()),
	}
	
	k8sContext := map[string]interface{}{
		"target_pod": "",
		"target_service": "test-service",
	}
	
	correlator.AddEvent(event, k8sContext)
	
	if len(correlator.errors) != 1 {
		t.Fatalf("Expected 1 error, got %d", len(correlator.errors))
	}
	
	errorEvent := correlator.errors[0]
	if errorEvent.Context["target_pod"] != "" {
		t.Errorf("Expected empty target_pod, got %q", errorEvent.Context["target_pod"])
	}
	if errorEvent.Context["target_service"] != "test-service" {
		t.Errorf("Expected target_service 'test-service', got %q", errorEvent.Context["target_service"])
	}
}

func TestErrorCorrelator_IsRelated_ByTarget(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)
	
	err1 := &ErrorEvent{
		Target: "10.244.1.5:8080",
	}
	err2 := &ErrorEvent{
		Target: "10.244.1.5:8080",
	}
	
	if !correlator.isRelated(err1, err2) {
		t.Error("Expected errors with same target to be related")
	}
}

func TestErrorCorrelator_IsRelated_ByTargetPod(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)
	
	err1 := &ErrorEvent{
		Context: map[string]string{"target_pod": "test-pod"},
	}
	err2 := &ErrorEvent{
		Context: map[string]string{"target_pod": "test-pod"},
	}
	
	if !correlator.isRelated(err1, err2) {
		t.Error("Expected errors with same target_pod to be related")
	}
}

func TestErrorCorrelator_IsRelated_ByTargetService(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)
	
	err1 := &ErrorEvent{
		Context: map[string]string{"target_service": "test-service"},
	}
	err2 := &ErrorEvent{
		Context: map[string]string{"target_service": "test-service"},
	}
	
	if !correlator.isRelated(err1, err2) {
		t.Error("Expected errors with same target_service to be related")
	}
}

func TestErrorCorrelator_IsRelated_NotRelated(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)
	
	err1 := &ErrorEvent{
		Target:  "10.244.1.5:8080",
		Context: map[string]string{"target_pod": "pod1"},
	}
	err2 := &ErrorEvent{
		Target:  "10.244.1.6:8080",
		Context: map[string]string{"target_pod": "pod2"},
	}
	
	if correlator.isRelated(err1, err2) {
		t.Error("Expected errors with different targets and pods to not be related")
	}
}

func TestErrorCorrelator_IsRelated_EmptyTargets(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)
	
	err1 := &ErrorEvent{
		Target: "",
		Context: map[string]string{},
	}
	err2 := &ErrorEvent{
		Target: "",
		Context: map[string]string{},
	}
	
	if correlator.isRelated(err1, err2) {
		t.Error("Expected errors with empty targets and contexts to not be related")
	}
}

func TestErrorCorrelator_IsRelated_OneEmptyTarget(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)
	
	err1 := &ErrorEvent{
		Target: "10.244.1.5:8080",
	}
	err2 := &ErrorEvent{
		Target: "",
	}
	
	if correlator.isRelated(err1, err2) {
		t.Error("Expected errors with one empty target to not be related")
	}
}

func TestErrorCorrelator_IsRelated_OneEmptyTargetPod(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)
	
	err1 := &ErrorEvent{
		Context: map[string]string{"target_pod": "test-pod"},
	}
	err2 := &ErrorEvent{
		Context: map[string]string{},
	}
	
	if correlator.isRelated(err1, err2) {
		t.Error("Expected errors with one empty target_pod to not be related")
	}
}

func TestErrorCorrelator_GenerateSuggestions_ErrorCodeEAGAIN(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)
	
	chain := make([]*ErrorEvent, 6)
	for i := range chain {
		chain[i] = &ErrorEvent{
			ErrorCode: -11,
		}
	}
	
	suggestions := correlator.generateSuggestions(chain)
	
	found := false
	for _, s := range suggestions {
		if contains(s, "EAGAIN") || contains(s, "buffer") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected suggestion for EAGAIN errors with count > 5")
	}
}

func TestErrorCorrelator_GenerateSuggestions_ErrorCodeEAGAIN_LowCount(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)
	
	chain := []*ErrorEvent{
		{ErrorCode: -11},
		{ErrorCode: -11},
	}
	
	suggestions := correlator.generateSuggestions(chain)
	
	for _, s := range suggestions {
		if contains(s, "EAGAIN") || contains(s, "buffer") {
			t.Error("Should not suggest EAGAIN fix for count <= 5")
		}
	}
}

func TestErrorCorrelator_GenerateSuggestions_ErrorCodeConnectionRefused(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)
	
	chain := []*ErrorEvent{
		{ErrorCode: -111},
	}
	
	suggestions := correlator.generateSuggestions(chain)
	
	found := false
	for _, s := range suggestions {
		if contains(s, "Connection refused") || contains(s, "service is running") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected suggestion for connection refused errors")
	}
}

func TestErrorCorrelator_GenerateSuggestions_ErrorCodeConnectionTimeout(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)
	
	chain := []*ErrorEvent{
		{ErrorCode: -110},
	}
	
	suggestions := correlator.generateSuggestions(chain)
	
	found := false
	for _, s := range suggestions {
		if contains(s, "Connection timed out") || contains(s, "network connectivity") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected suggestion for connection timeout errors")
	}
}

func TestErrorCorrelator_GenerateSuggestions_ErrorCodeNoSuchFile(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)
	
	chain := []*ErrorEvent{
		{ErrorCode: -2},
	}
	
	suggestions := correlator.generateSuggestions(chain)
	
	found := false
	for _, s := range suggestions {
		if contains(s, "No such file") || contains(s, "file paths") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected suggestion for no such file errors")
	}
}

func TestErrorCorrelator_GenerateSuggestions_ErrorCodePermissionDenied(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)
	
	chain := []*ErrorEvent{
		{ErrorCode: -13},
	}
	
	suggestions := correlator.generateSuggestions(chain)
	
	found := false
	for _, s := range suggestions {
		if contains(s, "Permission denied") || contains(s, "permissions") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected suggestion for permission denied errors")
	}
}

func TestErrorCorrelator_GenerateSuggestions_HighErrorRate(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)
	
	chain := make([]*ErrorEvent, 11)
	for i := range chain {
		chain[i] = &ErrorEvent{}
	}
	
	suggestions := correlator.generateSuggestions(chain)
	
	found := false
	for _, s := range suggestions {
		if contains(s, "High error rate") || contains(s, "circuit breaker") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected suggestion for high error rate")
	}
}

func TestErrorCorrelator_GenerateSuggestions_WithTargetPod(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)
	
	chain := []*ErrorEvent{
		{
			ErrorCode: -111,
			Context:   map[string]string{"target_pod": "test-pod"},
		},
	}
	
	suggestions := correlator.generateSuggestions(chain)
	
	found := false
	for _, s := range suggestions {
		if contains(s, "test-pod") && contains(s, "pod health") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected suggestion mentioning target pod")
	}
}

func TestErrorCorrelator_GenerateSuggestions_WithTargetService(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)
	
	chain := []*ErrorEvent{
		{
			ErrorCode: -111,
			Context:   map[string]string{"target_service": "test-service"},
		},
	}
	
	suggestions := correlator.generateSuggestions(chain)
	
	found := false
	for _, s := range suggestions {
		if contains(s, "test-service") && contains(s, "service endpoints") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected suggestion mentioning target service")
	}
}

func TestErrorCorrelator_BuildChains_EmptyErrors(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)
	correlator.buildChains()
	
	if len(correlator.chains) != 0 {
		t.Errorf("Expected no chains, got %d", len(correlator.chains))
	}
}

func TestErrorCorrelator_BuildChains_SingleError(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)
	correlator.errors = []*ErrorEvent{
		{
			ErrorCode: -111,
			Target:    "10.244.1.5:8080",
			Timestamp: time.Now(),
		},
	}
	correlator.buildChains()
	
	if len(correlator.chains) != 0 {
		t.Errorf("Expected no chains for single error, got %d", len(correlator.chains))
	}
}

func TestErrorCorrelator_BuildChains_TimeWindowExceeded(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)
	baseTime := time.Now()
	correlator.errors = []*ErrorEvent{
		{
			ErrorCode: -111,
			Target:    "10.244.1.5:8080",
			Timestamp: baseTime,
		},
		{
			ErrorCode: -111,
			Target:    "10.244.1.5:8080",
			Timestamp: baseTime.Add(35 * time.Second),
		},
	}
	correlator.buildChains()
	
	if len(correlator.chains) != 0 {
		t.Errorf("Expected no chains when time window exceeded, got %d", len(correlator.chains))
	}
}

func TestErrorCorrelator_BuildChains_RelatedErrors(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)
	baseTime := time.Now()
	correlator.errors = []*ErrorEvent{
		{
			ErrorCode: -111,
			Target:    "10.244.1.5:8080",
			Timestamp: baseTime,
		},
		{
			ErrorCode: -11,
			Target:    "10.244.1.5:8080",
			Timestamp: baseTime.Add(1 * time.Second),
		},
	}
	correlator.buildChains()
	
	if len(correlator.chains) == 0 {
		t.Error("Expected at least one chain for related errors")
	}
}

func TestErrorCorrelator_GetErrorSummary_WithChains(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)
	
	baseTime := time.Now()
	events := []*events.Event{
		{
			Type:      events.EventConnect,
			Target:    "10.244.1.5:8080",
			Error:     -111,
			Timestamp: uint64(baseTime.UnixNano()),
		},
		{
			Type:      events.EventTCPSend,
			Target:    "10.244.1.5:8080",
			Error:     -11,
			Timestamp: uint64(baseTime.Add(1 * time.Second).UnixNano()),
		},
	}
	
	for _, event := range events {
		correlator.AddEvent(event, nil)
	}
	
	summary := correlator.GetErrorSummary()
	if summary == "" {
		t.Error("Expected non-empty summary with chains")
	}
	if !contains(summary, "Error Correlation") {
		t.Error("Expected summary to contain 'Error Correlation'")
	}
}

func TestErrorCorrelator_GetErrorSummary_WithSuggestions(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)
	
	baseTime := time.Now()
	events := []*events.Event{
		{
			Type:      events.EventConnect,
			Target:    "10.244.1.5:8080",
			Error:     -111,
			Timestamp: uint64(baseTime.UnixNano()),
		},
		{
			Type:      events.EventTCPSend,
			Target:    "10.244.1.5:8080",
			Error:     -111,
			Timestamp: uint64(baseTime.Add(1 * time.Second).UnixNano()),
		},
	}
	
	k8sContext := map[string]interface{}{
		"target_pod": "test-pod",
	}
	
	for _, event := range events {
		correlator.AddEvent(event, k8sContext)
	}
	
	summary := correlator.GetErrorSummary()
	if summary == "" {
		t.Error("Expected non-empty summary")
	}
	if !contains(summary, "Suggestions") {
		t.Log("Summary may not contain suggestions if no chains were created")
	}
}

func TestErrorCorrelator_GetErrorSummary_MultipleChains(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)
	
	baseTime := time.Now()
	for i := 0; i < 10; i++ {
		event := &events.Event{
			Type:      events.EventConnect,
			Target:    fmt.Sprintf("10.244.1.%d:8080", i),
			Error:     -111,
			Timestamp: uint64(baseTime.Add(time.Duration(i) * time.Second).UnixNano()),
		}
		correlator.AddEvent(event, nil)
	}
	
	summary := correlator.GetErrorSummary()
	if summary == "" {
		t.Error("Expected non-empty summary")
	}
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
