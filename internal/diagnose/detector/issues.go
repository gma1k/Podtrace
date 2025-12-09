package detector

import (
	"fmt"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
)

func DetectIssues(allEvents []*events.Event, errorRateThreshold, rttSpikeThreshold float64) []string {
	var issues []string

	var connectEvents []*events.Event
	for _, e := range allEvents {
		if e.Type == events.EventConnect {
			connectEvents = append(connectEvents, e)
		}
	}

	if len(connectEvents) > 0 {
		errors := 0
		for _, e := range connectEvents {
			if e.Error != 0 {
				errors++
			}
		}
		errorRate := float64(errors) / float64(len(connectEvents)) * 100
		if errorRate > errorRateThreshold {
			issues = append(issues, fmt.Sprintf("High connection failure rate: %.1f%% (%d/%d) (threshold: %.1f%%)", errorRate, errors, len(connectEvents), errorRateThreshold))
		}
	}

	var tcpEvents []*events.Event
	for _, e := range allEvents {
		if e.Type == events.EventTCPSend || e.Type == events.EventTCPRecv {
			tcpEvents = append(tcpEvents, e)
		}
	}

	if len(tcpEvents) > 0 {
		spikes := 0
		for _, e := range tcpEvents {
			if float64(e.LatencyNS)/float64(config.NSPerMS) > rttSpikeThreshold {
				spikes++
			}
		}
		spikeRate := float64(spikes) / float64(len(tcpEvents)) * 100
		if spikeRate > config.SpikeRateThreshold {
			issues = append(issues, fmt.Sprintf("High TCP RTT spike rate: %.1f%% (%d/%d) (threshold: %.1fms)", spikeRate, spikes, len(tcpEvents), rttSpikeThreshold))
		}
	}

	var resourceAlerts = make(map[string]int)
	for _, e := range allEvents {
		if e.Type == events.EventResourceLimit {
			utilization := uint32(e.Error)
			resourceType := e.TCPState
			
			var resourceName string
			switch resourceType {
			case 0:
				resourceName = "CPU"
			case 1:
				resourceName = "Memory"
			case 2:
				resourceName = "I/O"
			default:
				resourceName = "Resource"
			}
			
			key := resourceName
			if current, ok := resourceAlerts[key]; !ok || utilization > uint32(current) {
				resourceAlerts[key] = int(utilization)
			}
		}
	}
	
	for resourceName, maxUtil := range resourceAlerts {
		var severity string
		if maxUtil >= 95 {
			severity = "EMERGENCY"
		} else if maxUtil >= 90 {
			severity = "CRITICAL"
		} else if maxUtil >= 80 {
			severity = "WARNING"
		}
		
		if severity != "" {
			issues = append(issues, fmt.Sprintf("Resource limit %s: %s - %d%% utilization (threshold: 80%% warning, 90%% critical, 95%% emergency)", 
				severity, resourceName, maxUtil))
		}
	}

	return issues
}
