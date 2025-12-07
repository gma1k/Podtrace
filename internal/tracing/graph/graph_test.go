package graph

import (
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/diagnose/tracker"
	"github.com/podtrace/podtrace/internal/events"
)

func TestNewGraphBuilder(t *testing.T) {
	gb := NewGraphBuilder()
	if gb == nil {
		t.Fatal("NewGraphBuilder() returned nil")
	}
	if gb.nodes == nil {
		t.Error("nodes map should be initialized")
	}
	if gb.edges == nil {
		t.Error("edges map should be initialized")
	}
}

func TestGraphBuilder_BuildFromTraces_Empty(t *testing.T) {
	gb := NewGraphBuilder()
	graph := gb.BuildFromTraces([]*tracker.Trace{})
	if graph == nil {
		t.Fatal("BuildFromTraces() returned nil")
	}
	if len(graph.Nodes) != 0 {
		t.Errorf("Expected 0 nodes, got %d", len(graph.Nodes))
	}
	if len(graph.Edges) != 0 {
		t.Errorf("Expected 0 edges, got %d", len(graph.Edges))
	}
}

func TestGraphBuilder_BuildFromTraces_WithSpans(t *testing.T) {
	gb := NewGraphBuilder()
	now := time.Now()
	trace := &tracker.Trace{
		TraceID:   "trace1",
		StartTime: now,
		EndTime:   now,
		Spans: []*tracker.Span{
			{
				TraceID:      "trace1",
				SpanID:       "span1",
				ParentSpanID: "",
				Service:      "service1",
				Operation:    "op1",
				StartTime:    now,
				Duration:     100 * time.Millisecond,
				Events: []*events.Event{
					{
						Type:      events.EventHTTPReq,
						Timestamp: uint64(now.UnixNano()),
					},
				},
			},
			{
				TraceID:      "trace1",
				SpanID:       "span2",
				ParentSpanID: "span1",
				Service:      "service2",
				Operation:    "op2",
				StartTime:    now.Add(50 * time.Millisecond),
				Duration:     50 * time.Millisecond,
				Events: []*events.Event{
					{
						Type:      events.EventHTTPResp,
						Timestamp: uint64(now.Add(50 * time.Millisecond).UnixNano()),
					},
				},
			},
		},
		Services: map[string]*tracker.ServiceInfo{
			"service1": {
				Name:      "service1",
				Namespace: "default",
			},
			"service2": {
				Name:      "service2",
				Namespace: "default",
			},
		},
	}

	graph := gb.BuildFromTraces([]*tracker.Trace{trace})
	if graph == nil {
		t.Fatal("BuildFromTraces() returned nil")
	}
	if len(graph.Nodes) == 0 {
		t.Error("Expected at least 1 node")
	}
}

func TestGraphBuilder_processTrace_NoSpans(t *testing.T) {
	gb := NewGraphBuilder()
	trace := &tracker.Trace{
		TraceID: "test",
		Spans:   []*tracker.Span{},
	}
	gb.processTrace(trace)
	if len(gb.nodes) != 0 {
		t.Error("Trace with no spans should not create nodes")
	}
}

func TestRequestFlowGraph_ToDOT(t *testing.T) {
	graph := &RequestFlowGraph{
		Nodes: []Node{
			{
				ID:          "node1",
				Service:     "service1",
				RequestCount: 10,
				ErrorCount:   1,
			},
		},
		Edges: []Edge{
			{
				Source:      "node1",
				Target:      "node2",
				RequestCount: 5,
				AvgLatency:  100 * time.Millisecond,
			},
		},
	}

	dot := graph.ToDOT()
	if dot == "" {
		t.Error("ToDOT() returned empty string")
	}
	if len(dot) < 10 {
		t.Error("DOT output seems too short")
	}
}

func TestGraphBuilder_getNodeID(t *testing.T) {
	gb := NewGraphBuilder()
	services := map[string]*tracker.ServiceInfo{
		"key1": {
			Name: "service1",
			Pod:  "pod1",
		},
	}

	tests := []struct {
		name      string
		service   string
		services  map[string]*tracker.ServiceInfo
		wantEmpty bool
	}{
		{"with service", "service1", services, false},
		{"empty service", "", services, false},
		{"unknown service", "unknown", services, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := gb.getNodeID(tt.service, tt.services)
			if tt.service == "" && result != "unknown" {
				t.Errorf("getNodeID() for empty service = %s, want 'unknown'", result)
			}
			if tt.service != "" && result == "" {
				t.Errorf("getNodeID() = %s, want non-empty", result)
			}
		})
	}
}

func TestGraphBuilder_ensureNode(t *testing.T) {
	gb := NewGraphBuilder()
	services := map[string]*tracker.ServiceInfo{
		"key1": {
			Name:      "service1",
			Namespace: "default",
			Pod:       "pod1",
		},
	}

	gb.ensureNode("key1", "service1", services)
	if len(gb.nodes) != 1 {
		t.Errorf("Expected 1 node, got %d", len(gb.nodes))
	}

	node := gb.nodes["key1"]
	if node == nil {
		t.Fatal("Node not found")
	}
	if node.Service != "service1" {
		t.Errorf("Node Service = %s, want service1", node.Service)
	}
}

func TestGraphBuilder_updateNode(t *testing.T) {
	gb := NewGraphBuilder()
	gb.nodes["node1"] = &Node{
		ID:          "node1",
		Service:     "service1",
		RequestCount: 0,
		ErrorCount:   0,
	}

	span := &tracker.Span{
		Service:   "service1",
		Error:     true,
		Duration:  100 * time.Millisecond,
		StartTime: time.Now(),
	}

	gb.updateNode("node1", span)
	node := gb.nodes["node1"]
	if node.RequestCount != 1 {
		t.Errorf("RequestCount = %d, want 1", node.RequestCount)
	}
	if node.ErrorCount != 1 {
		t.Errorf("ErrorCount = %d, want 1", node.ErrorCount)
	}
}

func TestGraphBuilder_updateEdge(t *testing.T) {
	gb := NewGraphBuilder()
	span := &tracker.Span{
		Service:   "service1",
		Error:     true,
		Duration:  100 * time.Millisecond,
		StartTime: time.Now(),
	}

	gb.updateEdge("source->target", "source", "target", span)
	if len(gb.edges) != 1 {
		t.Errorf("Expected 1 edge, got %d", len(gb.edges))
	}

	edge := gb.edges["source->target"]
	if edge == nil {
		t.Fatal("Edge not found")
	}
	if edge.RequestCount != 1 {
		t.Errorf("RequestCount = %d, want 1", edge.RequestCount)
	}
	if edge.ErrorCount != 1 {
		t.Errorf("ErrorCount = %d, want 1", edge.ErrorCount)
	}
}

