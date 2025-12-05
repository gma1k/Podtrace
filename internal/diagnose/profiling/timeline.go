package profiling

import (
	"fmt"
	"time"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
)

type TimelineBucket struct {
	Period     string
	Count      int
	Percentage float64
}

type BurstInfo struct {
	Time       time.Time
	Rate       float64
	Multiplier float64
}

func AnalyzeTimeline(events []*events.Event, startTime time.Time, duration time.Duration) []TimelineBucket {
	if len(events) == 0 {
		return nil
	}

	numBuckets := config.TimelineBuckets
	bucketDuration := duration / time.Duration(numBuckets)
	buckets := make([]int, numBuckets)

	for _, e := range events {
		eventTime := time.Unix(0, int64(e.Timestamp))
		elapsed := eventTime.Sub(startTime)
		bucketIndex := int(elapsed / bucketDuration)
		if bucketIndex >= numBuckets {
			bucketIndex = numBuckets - 1
		}
		if bucketIndex < 0 {
			bucketIndex = 0
		}
		buckets[bucketIndex]++
	}

	var timeline []TimelineBucket
	totalEvents := len(events)
	for i, count := range buckets {
		startTime := startTime.Add(time.Duration(i) * bucketDuration)
		endTime := startTime.Add(time.Duration(i+1) * bucketDuration)
		period := fmt.Sprintf("%s-%s", startTime.Format("15:04:05"), endTime.Format("15:04:05"))
		percentage := float64(count) / float64(totalEvents) * 100
		timeline = append(timeline, TimelineBucket{
			Period:     period,
			Count:      count,
			Percentage: percentage,
		})
	}

	return timeline
}

func DetectBursts(events []*events.Event, startTime time.Time, duration time.Duration) []BurstInfo {
	if len(events) < 10 {
		return nil
	}

	var avgRate float64
	if duration.Seconds() > 0 {
		avgRate = float64(len(events)) / duration.Seconds()
	}
	windowDuration := 1 * time.Second
	numWindows := int(duration / windowDuration)
	if numWindows < 2 {
		return nil
	}

	var bursts []BurstInfo
	windowStart := startTime

	for i := 0; i < numWindows; i++ {
		windowEnd := windowStart.Add(windowDuration)
		count := 0
		for _, e := range events {
			eventTime := time.Unix(0, int64(e.Timestamp))
			if eventTime.After(windowStart) && eventTime.Before(windowEnd) {
				count++
			}
		}
		rate := float64(count) / windowDuration.Seconds()
		if rate > avgRate*2.0 {
			multiplier := rate / avgRate
			bursts = append(bursts, BurstInfo{
				Time:       windowStart,
				Rate:       rate,
				Multiplier: multiplier,
			})
		}
		windowStart = windowEnd
	}

	return bursts
}

type ConnectionPattern struct {
	Pattern       string
	AvgRate       float64
	BurstRate     float64
	UniqueTargets int
}

func AnalyzeConnectionPattern(connectEvents []*events.Event, startTime, endTime time.Time, duration time.Duration) ConnectionPattern {
	if len(connectEvents) == 0 {
		return ConnectionPattern{}
	}

	var avgRate float64
	if duration.Seconds() > 0 {
		avgRate = float64(len(connectEvents)) / duration.Seconds()
	}
	windowDuration := duration / 10
	if windowDuration < config.MinBurstWindowDuration {
		windowDuration = config.MinBurstWindowDuration
	}

	var windowCounts []int
	windowStart := startTime
	for windowStart.Before(endTime) {
		windowEnd := windowStart.Add(windowDuration)
		count := 0
		for _, e := range connectEvents {
			eventTime := time.Unix(0, int64(e.Timestamp))
			if eventTime.After(windowStart) && eventTime.Before(windowEnd) {
				count++
			}
		}
		windowCounts = append(windowCounts, count)
		windowStart = windowEnd
	}

	if len(windowCounts) == 0 {
		return ConnectionPattern{Pattern: "steady"}
	}
	var sum, sumSq float64
	for _, count := range windowCounts {
		sum += float64(count)
		sumSq += float64(count) * float64(count)
	}
	var mean float64
	if len(windowCounts) > 0 {
		mean = sum / float64(len(windowCounts))
	}
	variance := (sumSq / float64(len(windowCounts))) - (mean * mean)
	stdDev := variance

	var pattern string
	if stdDev > mean*0.5 {
		pattern = "bursty"
	} else if stdDev < mean*0.1 {
		pattern = "steady"
	} else {
		pattern = "sporadic"
	}

	peakRate := 0.0
	for _, count := range windowCounts {
		rate := float64(count) / windowDuration.Seconds()
		if rate > peakRate {
			peakRate = rate
		}
	}

	targetMap := make(map[string]bool)
	for _, e := range connectEvents {
		if e.Target != "" && e.Target != "?" && e.Target != "unknown" && e.Target != "file" {
			targetMap[e.Target] = true
		}
	}

	return ConnectionPattern{
		Pattern:       pattern,
		AvgRate:       avgRate,
		BurstRate:     peakRate,
		UniqueTargets: len(targetMap),
	}
}

type IOPattern struct {
	SendRecvRatio  float64
	AvgThroughput  float64
	PeakThroughput float64
}

func AnalyzeIOPattern(tcpEvents []*events.Event, startTime time.Time, duration time.Duration) IOPattern {
	sendCount := 0
	recvCount := 0
	for _, e := range tcpEvents {
		if e.Type == events.EventTCPSend {
			sendCount++
		} else if e.Type == events.EventTCPRecv {
			recvCount++
		}
	}

	sendRecvRatio := 1.0
	if recvCount > 0 {
		sendRecvRatio = float64(sendCount) / float64(recvCount)
	}

	var avgThroughput float64
	if duration.Seconds() > 0 {
		avgThroughput = float64(len(tcpEvents)) / duration.Seconds()
	}
	windowDuration := 1 * time.Second
	numWindows := int(duration / windowDuration)
	if numWindows < 1 {
		numWindows = 1
	}

	peakThroughput := 0.0
	windowStart := startTime
	for i := 0; i < numWindows; i++ {
		windowEnd := windowStart.Add(windowDuration)
		count := 0
		for _, e := range tcpEvents {
			eventTime := time.Unix(0, int64(e.Timestamp))
			if eventTime.After(windowStart) && eventTime.Before(windowEnd) {
				count++
			}
		}
		rate := float64(count) / windowDuration.Seconds()
		if rate > peakThroughput {
			peakThroughput = rate
		}
		windowStart = windowEnd
	}

	return IOPattern{
		SendRecvRatio:  sendRecvRatio,
		AvgThroughput:  avgThroughput,
		PeakThroughput: peakThroughput,
	}
}
