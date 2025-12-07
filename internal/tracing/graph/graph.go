package graph

import (
	"fmt"
	"sort"
	"time"

	"github.com/podtrace/podtrace/internal/diagnose/tracker"
)

type RequestFlowGraph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

type Node struct {
	ID           string            `json:"id"`
	Service      string            `json:"service"`
	Namespace    string            `json:"namespace,omitempty"`
	Pod          string            `json:"pod,omitempty"`
	Attributes   map[string]string `json:"attributes,omitempty"`
	RequestCount int               `json:"request_count"`
	ErrorCount   int               `json:"error_count"`
	TotalLatency time.Duration     `json:"total_latency"`
}

type Edge struct {
	Source       string            `json:"source"`
	Target       string            `json:"target"`
	RequestCount int               `json:"request_count"`
	ErrorCount   int               `json:"error_count"`
	TotalLatency time.Duration     `json:"total_latency"`
	AvgLatency   time.Duration     `json:"avg_latency"`
	Attributes   map[string]string `json:"attributes,omitempty"`
}

type GraphBuilder struct {
	nodes map[string]*Node
	edges map[string]*Edge
}

func NewGraphBuilder() *GraphBuilder {
	return &GraphBuilder{
		nodes: make(map[string]*Node),
		edges: make(map[string]*Edge),
	}
}

func (gb *GraphBuilder) BuildFromTraces(traces []*tracker.Trace) *RequestFlowGraph {
	gb.reset()

	for _, trace := range traces {
		gb.processTrace(trace)
	}

	return gb.buildGraph()
}

func (gb *GraphBuilder) reset() {
	gb.nodes = make(map[string]*Node)
	gb.edges = make(map[string]*Edge)
}

func (gb *GraphBuilder) processTrace(trace *tracker.Trace) {
	if len(trace.Spans) == 0 {
		return
	}

	sort.Slice(trace.Spans, func(i, j int) bool {
		return trace.Spans[i].StartTime.Before(trace.Spans[j].StartTime)
	})

	for i, span := range trace.Spans {
		span.UpdateDuration()

		sourceID := gb.getNodeID(span.Service, trace.Services)
		gb.ensureNode(sourceID, span.Service, trace.Services)

		if i > 0 {
			parentSpan := trace.Spans[i-1]
			if span.ParentSpanID == parentSpan.SpanID {
				targetID := gb.getNodeID(parentSpan.Service, trace.Services)
				gb.ensureNode(targetID, parentSpan.Service, trace.Services)

				edgeKey := fmt.Sprintf("%s->%s", targetID, sourceID)
				gb.updateEdge(edgeKey, targetID, sourceID, span)
			}
		}

		gb.updateNode(sourceID, span)
	}
}

func (gb *GraphBuilder) getNodeID(serviceName string, services map[string]*tracker.ServiceInfo) string {
	if serviceName == "" {
		return "unknown"
	}

	for key, info := range services {
		if info.Name == serviceName || info.Pod == serviceName {
			return key
		}
	}

	return serviceName
}

func (gb *GraphBuilder) ensureNode(id, serviceName string, services map[string]*tracker.ServiceInfo) {
	if _, exists := gb.nodes[id]; exists {
		return
	}

	node := &Node{
		ID:           id,
		Service:      serviceName,
		Attributes:   make(map[string]string),
		RequestCount: 0,
		ErrorCount:   0,
	}

	if info, ok := services[id]; ok {
		node.Namespace = info.Namespace
		node.Pod = info.Pod
		for k, v := range info.Labels {
			node.Attributes[k] = v
		}
	}

	gb.nodes[id] = node
}

func (gb *GraphBuilder) updateNode(id string, span *tracker.Span) {
	node := gb.nodes[id]
	if node == nil {
		return
	}

	node.RequestCount++
	if span.Error {
		node.ErrorCount++
	}
	node.TotalLatency += span.Duration
}

func (gb *GraphBuilder) updateEdge(key, source, target string, span *tracker.Span) {
	edge, exists := gb.edges[key]
	if !exists {
		edge = &Edge{
			Source:       source,
			Target:       target,
			Attributes:   make(map[string]string),
			RequestCount: 0,
			ErrorCount:   0,
		}
		gb.edges[key] = edge
	}

	edge.RequestCount++
	if span.Error {
		edge.ErrorCount++
	}
	edge.TotalLatency += span.Duration
	edge.AvgLatency = edge.TotalLatency / time.Duration(edge.RequestCount)
}

func (gb *GraphBuilder) buildGraph() *RequestFlowGraph {
	nodes := make([]Node, 0, len(gb.nodes))
	for _, node := range gb.nodes {
		nodes = append(nodes, *node)
	}

	edges := make([]Edge, 0, len(gb.edges))
	for _, edge := range gb.edges {
		edges = append(edges, *edge)
	}

	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].RequestCount > nodes[j].RequestCount
	})

	sort.Slice(edges, func(i, j int) bool {
		return edges[i].RequestCount > edges[j].RequestCount
	})

	return &RequestFlowGraph{
		Nodes: nodes,
		Edges: edges,
	}
}

func (g *RequestFlowGraph) ToDOT() string {
	var buf string
	buf += "digraph RequestFlow {\n"
	buf += "  rankdir=LR;\n"
	buf += "  node [shape=box];\n\n"

	for _, node := range g.Nodes {
		label := fmt.Sprintf("%s\\nRequests: %d\\nErrors: %d", node.Service, node.RequestCount, node.ErrorCount)
		buf += fmt.Sprintf("  \"%s\" [label=\"%s\"];\n", node.ID, label)
	}

	buf += "\n"

	for _, edge := range g.Edges {
		label := fmt.Sprintf("Count: %d\\nAvg: %v", edge.RequestCount, edge.AvgLatency)
		if edge.ErrorCount > 0 {
			label += fmt.Sprintf("\\nErrors: %d", edge.ErrorCount)
		}
		buf += fmt.Sprintf("  \"%s\" -> \"%s\" [label=\"%s\"];\n", edge.Source, edge.Target, label)
	}

	buf += "}\n"
	return buf
}
