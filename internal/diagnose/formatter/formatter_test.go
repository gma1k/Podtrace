package formatter

import (
	"testing"

	"github.com/podtrace/podtrace/internal/diagnose/analyzer"
)

func TestSectionHeader(t *testing.T) {
	result := SectionHeader("DNS")
	if result != "DNS Statistics:\n" {
		t.Errorf("Expected 'DNS Statistics:\\n', got %q", result)
	}
}

func TestTotalWithRate(t *testing.T) {
	result := TotalWithRate("lookups", 100, 10.5)
	expected := "  Total lookups: 100 (10.5/sec)\n"
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

func TestLatencyMetrics(t *testing.T) {
	result := LatencyMetrics(5.5, 10.2)
	if !contains(result, "5.50") || !contains(result, "10.20") {
		t.Errorf("Expected latency metrics, got %q", result)
	}
}

func TestPercentiles(t *testing.T) {
	result := Percentiles(1.0, 2.0, 3.0)
	if !contains(result, "P50=1.00") || !contains(result, "P95=2.00") || !contains(result, "P99=3.00") {
		t.Errorf("Expected percentiles, got %q", result)
	}
}

func TestErrorRate_ZeroTotal(t *testing.T) {
	result := ErrorRate(5, 0)
	if !contains(result, "0.0%") {
		t.Errorf("Expected 0.0%% for zero total, got %q", result)
	}
}

func TestErrorRate_WithErrors(t *testing.T) {
	result := ErrorRate(5, 100)
	if !contains(result, "5.0%") {
		t.Errorf("Expected 5.0%% error rate, got %q", result)
	}
}

func TestTopTargets_Empty(t *testing.T) {
	result := TopTargets([]analyzer.TargetCount{}, 5, "targets", "counts")
	if result != "" {
		t.Errorf("Expected empty string for empty targets, got %q", result)
	}
}

func TestTopTargets_WithLimit(t *testing.T) {
	targets := []analyzer.TargetCount{
		{Target: "target1", Count: 10},
		{Target: "target2", Count: 20},
		{Target: "target3", Count: 30},
		{Target: "target4", Count: 40},
		{Target: "target5", Count: 50},
		{Target: "target6", Count: 60},
	}
	result := TopTargets(targets, 3, "targets", "counts")
	if countOccurrences(result, "-") > 3 {
		t.Errorf("Expected at most 3 targets, got more")
	}
}

func TestBytesSection_Empty(t *testing.T) {
	result := BytesSection(0, 0, 0)
	if result != "" {
		t.Errorf("Expected empty string for zero bytes, got %q", result)
	}
}

func TestBytesSection_WithBytes(t *testing.T) {
	result := BytesSection(1024, 512, 256)
	if result == "" {
		t.Error("Expected non-empty bytes section")
	}
	if !contains(result, "KB") && !contains(result, "B") {
		t.Errorf("Expected bytes section with formatted bytes, got %q", result)
	}
}

func TestRate_ZeroDuration(t *testing.T) {
	result := Rate(100, 0)
	if result != "" {
		t.Errorf("Expected empty string for zero duration, got %q", result)
	}
}

func TestRate_WithDuration(t *testing.T) {
	result := Rate(100, 10.0)
	if !contains(result, "10.0") {
		t.Errorf("Expected rate string, got %q", result)
	}
}

func TestTopItems_Empty(t *testing.T) {
	result := TopItems(map[string]int{}, 5, "items", "counts")
	if result != "" {
		t.Errorf("Expected empty string for empty items, got %q", result)
	}
}

func TestTopItems_WithLimit(t *testing.T) {
	items := map[string]int{
		"item1": 10,
		"item2": 20,
		"item3": 30,
		"item4": 40,
		"item5": 50,
		"item6": 60,
	}
	result := TopItems(items, 3, "items", "counts")
	if countOccurrences(result, "-") > 3 {
		t.Errorf("Expected at most 3 items, got more")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func countOccurrences(s, substr string) int {
	count := 0
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			count++
		}
	}
	return count
}

