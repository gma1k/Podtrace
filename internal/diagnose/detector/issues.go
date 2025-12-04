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
			if float64(e.LatencyNS)/1e6 > rttSpikeThreshold {
				spikes++
			}
		}
		spikeRate := float64(spikes) / float64(len(tcpEvents)) * 100
		if spikeRate > config.SpikeRateThreshold {
			issues = append(issues, fmt.Sprintf("High TCP RTT spike rate: %.1f%% (%d/%d) (threshold: %.1fms)", spikeRate, spikes, len(tcpEvents), rttSpikeThreshold))
		}
	}

	return issues
}
