package profiling

import (
	"fmt"
	"math"
	"time"

	"github.com/gma1k/podtrace/internal/clock"
	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/safeconv"
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

// minEventTimestamp returns the smallest BPF timestamp among the events.
func minEventTimestamp(evs []*events.Event) uint64 {
	origin := evs[0].Timestamp
	for _, e := range evs {
		if e.Timestamp < origin {
			origin = e.Timestamp
		}
	}
	return origin
}

// eventOffsetNS returns an event's nanosecond offset from the origin timestamp.
func eventOffsetNS(e *events.Event, origin uint64) int64 {
	return safeconv.Uint64ToInt64(e.Timestamp) - safeconv.Uint64ToInt64(origin)
}

// labelOrigin is the wall-clock time of origin, the timestamp the buckets are
// measured from, so a bucket's label names the time its events happened.
func labelOrigin(origin uint64, startTime time.Time, duration time.Duration) time.Time {
	at := clock.BPFTimestampToWall(origin)
	if at.Before(startTime.Add(-time.Second)) || at.After(startTime.Add(duration)) {
		return startTime
	}
	return at
}

// windowCounts counts the events in each of n consecutive windows of
// windowNS starting at origin, in one pass.
func windowCounts(evs []*events.Event, origin uint64, windowNS int64, n int) []int {
	counts := make([]int, n)
	if windowNS <= 0 {
		return counts
	}
	for _, e := range evs {
		off := eventOffsetNS(e, origin)
		if off < 0 {
			continue
		}
		if i := off / windowNS; i < int64(n) {
			counts[i]++
		}
	}
	return counts
}

func AnalyzeTimeline(events []*events.Event, startTime time.Time, duration time.Duration) []TimelineBucket {
	if len(events) == 0 {
		return nil
	}

	numBuckets := config.TimelineBuckets
	bucketDuration := duration / time.Duration(numBuckets)
	if bucketDuration <= 0 {
		bucketDuration = time.Nanosecond
	}
	bucketNS := int64(bucketDuration)
	buckets := make([]int, numBuckets)

	origin := minEventTimestamp(events)
	for _, e := range events {
		bucketIndex := int(eventOffsetNS(e, origin) / bucketNS)
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
	labelStart := labelOrigin(origin, startTime, duration)
	for i, count := range buckets {
		bucketStart := labelStart.Add(time.Duration(i) * bucketDuration)
		bucketEnd := labelStart.Add(time.Duration(i+1) * bucketDuration)
		period := fmt.Sprintf("%s-%s", bucketStart.Format("15:04:05"), bucketEnd.Format("15:04:05"))
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

	if avgRate <= 0 {
		return nil
	}

	origin := minEventTimestamp(events)
	windowNS := int64(windowDuration)
	labelStart := labelOrigin(origin, startTime, duration)

	var bursts []BurstInfo
	for i, count := range windowCounts(events, origin, windowNS, numWindows) {
		rate := float64(count) / windowDuration.Seconds()
		if rate > avgRate*2.0 {
			multiplier := rate / avgRate
			bursts = append(bursts, BurstInfo{
				Time:       labelStart.Add(time.Duration(int64(i) * windowNS)),
				Rate:       rate,
				Multiplier: multiplier,
			})
		}
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

	// Span the trace by offset from the earliest event (CLOCK_MONOTONIC domain)
	// rather than comparing event times to the wall-clock startTime/endTime.
	span := endTime.Sub(startTime)
	if span <= 0 {
		span = duration
	}
	numWindows := int(span / windowDuration)
	if numWindows < 1 {
		numWindows = 1
	}
	origin := minEventTimestamp(connectEvents)
	counts := windowCounts(connectEvents, origin, int64(windowDuration), numWindows)

	if len(counts) == 0 {
		return ConnectionPattern{Pattern: "steady"}
	}
	var sum, sumSq float64
	for _, count := range counts {
		sum += float64(count)
		sumSq += float64(count) * float64(count)
	}
	mean := sum / float64(len(counts))
	variance := (sumSq / float64(len(counts))) - (mean * mean)
	if variance < 0 {
		variance = 0
	}
	stdDev := math.Sqrt(variance)

	var pattern string
	if stdDev > mean*0.5 {
		pattern = "bursty"
	} else if stdDev < mean*0.1 {
		pattern = "steady"
	} else {
		pattern = "sporadic"
	}

	peakRate := 0.0
	for _, count := range counts {
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
		switch e.Type {
		case events.EventTCPSend:
			sendCount++
		case events.EventTCPRecv:
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
	if len(tcpEvents) > 0 {
		origin := minEventTimestamp(tcpEvents)
		for _, count := range windowCounts(tcpEvents, origin, int64(windowDuration), numWindows) {
			rate := float64(count) / windowDuration.Seconds()
			if rate > peakThroughput {
				peakThroughput = rate
			}
		}
	}

	return IOPattern{
		SendRecvRatio:  sendRecvRatio,
		AvgThroughput:  avgThroughput,
		PeakThroughput: peakThroughput,
	}
}
