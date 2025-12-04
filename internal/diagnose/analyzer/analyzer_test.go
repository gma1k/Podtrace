package analyzer

import (
	"sort"
	"testing"

	"github.com/podtrace/podtrace/internal/events"
)

func TestPercentile(t *testing.T) {
	tests := []struct {
		name       string
		data       []float64
		percentile float64
		expected   float64
	}{
		{"empty slice", []float64{}, 50, 0},
		{"single value p50", []float64{10}, 50, 10},
		{"single value p95", []float64{10}, 95, 10},
		{"two values p50", []float64{10, 20}, 50, 10},
		{"two values p95", []float64{10, 20}, 95, 10},
		{"ten values p50", []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 50, 5},
		{"ten values p95", []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 95, 9},
		{"ten values p99", []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 99, 9},
		{"unsorted", []float64{5, 1, 9, 3, 7}, 50, 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sorted := make([]float64, len(tt.data))
			copy(sorted, tt.data)
			sort.Float64s(sorted)
			result := Percentile(sorted, tt.percentile)
			if result != tt.expected {
				t.Errorf("Percentile() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    uint64
		expected string
	}{
		{"bytes", 512, "512 B"},
		{"kilobytes", 1024, "1.00 KB"},
		{"kilobytes", 1536, "1.50 KB"},
		{"megabytes", 1024 * 1024, "1.00 MB"},
		{"megabytes", 2 * 1024 * 1024, "2.00 MB"},
		{"gigabytes", 1024 * 1024 * 1024, "1.00 GB"},
		{"large", 5 * 1024 * 1024 * 1024, "5.00 GB"},
		{"zero", 0, "0 B"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatBytes(tt.input)
			if result != tt.expected {
				t.Errorf("FormatBytes() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestAnalyzeDNS(t *testing.T) {
	events := []*events.Event{
		{LatencyNS: 1000000, Error: 0, Target: "example.com"},
		{LatencyNS: 2000000, Error: 0, Target: "example.com"},
		{LatencyNS: 3000000, Error: 0, Target: "google.com"},
		{LatencyNS: 4000000, Error: 1, Target: "invalid.com"},
		{LatencyNS: 5000000, Error: 0, Target: "example.com"},
	}

	avg, max, errors, p50, _, _, topTargets := AnalyzeDNS(events)

	if avg != 3.0 {
		t.Errorf("Expected avg latency 3.0ms, got %.2f", avg)
	}
	if max != 5.0 {
		t.Errorf("Expected max latency 5.0ms, got %.2f", max)
	}
	if errors != 1 {
		t.Errorf("Expected 1 error, got %d", errors)
	}
	if p50 != 3.0 {
		t.Errorf("Expected p50 3.0ms, got %.2f", p50)
	}
	if len(topTargets) == 0 || topTargets[0].Target != "example.com" {
		t.Errorf("Expected top target 'example.com', got %v", topTargets)
	}
}

func TestAnalyzeDNS_Empty(t *testing.T) {
	avg, max, errors, p50, p95, p99, topTargets := AnalyzeDNS([]*events.Event{})

	if avg != 0 {
		t.Errorf("Expected avg 0, got %.2f", avg)
	}
	if max != 0 {
		t.Errorf("Expected max 0, got %.2f", max)
	}
	if errors != 0 {
		t.Errorf("Expected 0 errors, got %d", errors)
	}
	if p50 != 0 || p95 != 0 || p99 != 0 {
		t.Errorf("Expected percentiles 0, got p50=%.2f p95=%.2f p99=%.2f", p50, p95, p99)
	}
	if len(topTargets) != 0 {
		t.Errorf("Expected empty top targets, got %v", topTargets)
	}
}

func TestAnalyzeTCP(t *testing.T) {
	events := []*events.Event{
		{LatencyNS: 10000000, Error: 0, Bytes: 1024},
		{LatencyNS: 20000000, Error: 0, Bytes: 2048},
		{LatencyNS: 150000000, Error: 0, Bytes: 4096},
		{LatencyNS: 30000000, Error: -1, Bytes: 0},
		{LatencyNS: 5000000, Error: 0, Bytes: 512},
	}

	avg, max, spikes, _, _, _, errors, totalBytes, _, peakBytes := AnalyzeTCP(events, 100.0)

	if avg != 43.0 {
		t.Errorf("Expected avg RTT 43.0ms, got %.2f", avg)
	}
	if max != 150.0 {
		t.Errorf("Expected max RTT 150.0ms, got %.2f", max)
	}
	if spikes != 1 {
		t.Errorf("Expected 1 spike, got %d", spikes)
	}
	if errors != 1 {
		t.Errorf("Expected 1 error, got %d", errors)
	}
	if totalBytes != 7680 {
		t.Errorf("Expected total bytes 7680, got %d", totalBytes)
	}
	if peakBytes != 4096 {
		t.Errorf("Expected peak bytes 4096, got %d", peakBytes)
	}
}

func TestAnalyzeTCP_NoSpikes(t *testing.T) {
	events := []*events.Event{
		{LatencyNS: 10000000, Error: 0},
		{LatencyNS: 20000000, Error: 0},
		{LatencyNS: 30000000, Error: 0},
	}

	_, _, spikes, _, _, _, _, _, _, _ := AnalyzeTCP(events, 100.0)

	if spikes != 0 {
		t.Errorf("Expected 0 spikes, got %d", spikes)
	}
}

func TestAnalyzeConnections(t *testing.T) {
	events := []*events.Event{
		{LatencyNS: 1000000, Error: 0, Target: "example.com:80"},
		{LatencyNS: 2000000, Error: 0, Target: "example.com:80"},
		{LatencyNS: 3000000, Error: 111, Target: "invalid.com:80"},
		{LatencyNS: 4000000, Error: 0, Target: "google.com:443"},
	}

	avg, max, errors, _, _, _, topTargets, errorBreakdown := AnalyzeConnections(events)

	if avg != 2.5 {
		t.Errorf("Expected avg latency 2.5ms, got %.2f", avg)
	}
	if max != 4.0 {
		t.Errorf("Expected max latency 4.0ms, got %.2f", max)
	}
	if errors != 1 {
		t.Errorf("Expected 1 error, got %d", errors)
	}
	if errorBreakdown[111] != 1 {
		t.Errorf("Expected error 111 count 1, got %d", errorBreakdown[111])
	}
	if len(topTargets) == 0 || topTargets[0].Target != "example.com:80" {
		t.Errorf("Expected top target 'example.com:80', got %v", topTargets)
	}
}

func BenchmarkAnalyzeDNS(b *testing.B) {
	eventSlice := make([]*events.Event, 1000)
	for i := range eventSlice {
		eventSlice[i] = &events.Event{
			LatencyNS: uint64(i * 1000000),
			Error:     0,
			Target:    "example.com",
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _, _, _, _ = AnalyzeDNS(eventSlice)
	}
}

func BenchmarkAnalyzeTCP(b *testing.B) {
	eventSlice := make([]*events.Event, 1000)
	for i := range eventSlice {
		eventSlice[i] = &events.Event{
			LatencyNS: uint64(i * 1000000),
			Error:     0,
			Bytes:     uint64(i * 1024),
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _, _, _, _, _, _, _ = AnalyzeTCP(eventSlice, 100.0)
	}
}

func BenchmarkPercentile(b *testing.B) {
	data := make([]float64, 10000)
	for i := range data {
		data[i] = float64(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Percentile(data, 95)
	}
}

func BenchmarkFormatBytes(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FormatBytes(uint64(i * 1024 * 1024))
	}
}

func TestAnalyzeFS(t *testing.T) {
	events := []*events.Event{
		{LatencyNS: 5000000, Bytes: 1024},
		{LatencyNS: 10000000, Bytes: 2048},
		{LatencyNS: 15000000, Bytes: 4096},
		{LatencyNS: 2000000, Bytes: 512},
		{LatencyNS: 8000000, Bytes: 0},
	}

	avg, max, slowOps, _, _, _, totalBytes, avgBytes := AnalyzeFS(events, 10.0)

	if avg != 8.0 {
		t.Errorf("Expected avg latency 8.0ms, got %.2f", avg)
	}
	if max != 15.0 {
		t.Errorf("Expected max latency 15.0ms, got %.2f", max)
	}
	if slowOps != 1 {
		t.Errorf("Expected 1 slow operation, got %d", slowOps)
	}
	if totalBytes != 7680 {
		t.Errorf("Expected total bytes 7680, got %d", totalBytes)
	}
	if avgBytes != 1536 {
		t.Errorf("Expected avg bytes 1536, got %d", avgBytes)
	}
}

func TestAnalyzeFS_Empty(t *testing.T) {
	avg, max, slowOps, _, _, _, totalBytes, avgBytes := AnalyzeFS([]*events.Event{}, 10.0)

	if avg != 0 || max != 0 || slowOps != 0 {
		t.Errorf("Expected zeros for empty events, got avg=%.2f max=%.2f slowOps=%d", avg, max, slowOps)
	}
	if totalBytes != 0 || avgBytes != 0 {
		t.Errorf("Expected zero bytes for empty events, got total=%d avg=%d", totalBytes, avgBytes)
	}
}

func TestAnalyzeCPU(t *testing.T) {
	events := []*events.Event{
		{LatencyNS: 1000000},
		{LatencyNS: 2000000},
		{LatencyNS: 3000000},
		{LatencyNS: 4000000},
		{LatencyNS: 5000000},
	}

	avg, max, p50, _, _ := AnalyzeCPU(events)

	if avg != 3.0 {
		t.Errorf("Expected avg block time 3.0ms, got %.2f", avg)
	}
	if max != 5.0 {
		t.Errorf("Expected max block time 5.0ms, got %.2f", max)
	}
	if p50 != 3.0 {
		t.Errorf("Expected p50 3.0ms, got %.2f", p50)
	}
}

func TestAnalyzeCPU_Empty(t *testing.T) {
	avg, max, p50, p95, p99 := AnalyzeCPU([]*events.Event{})

	if avg != 0 || max != 0 {
		t.Errorf("Expected zeros for empty events, got avg=%.2f max=%.2f", avg, max)
	}
	if p50 != 0 || p95 != 0 || p99 != 0 {
		t.Errorf("Expected zero percentiles, got p50=%.2f p95=%.2f p99=%.2f", p50, p95, p99)
	}
}

func BenchmarkAnalyzeFS(b *testing.B) {
	eventSlice := make([]*events.Event, 1000)
	for i := range eventSlice {
		eventSlice[i] = &events.Event{
			LatencyNS: uint64(i * 1000000),
			Bytes:     uint64(i * 1024),
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _, _, _, _, _ = AnalyzeFS(eventSlice, 10.0)
	}
}

func BenchmarkAnalyzeCPU(b *testing.B) {
	eventSlice := make([]*events.Event, 1000)
	for i := range eventSlice {
		eventSlice[i] = &events.Event{
			LatencyNS: uint64(i * 1000000),
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _, _ = AnalyzeCPU(eventSlice)
	}
}
