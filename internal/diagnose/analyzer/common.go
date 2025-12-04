package analyzer

import (
	"fmt"

	"github.com/podtrace/podtrace/internal/config"
)

func Percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	index := int(float64(len(sorted)-1) * p / 100)
	return sorted[index]
}

func FormatBytes(bytes uint64) string {
	if bytes < config.KB {
		return fmt.Sprintf("%d B", bytes)
	} else if bytes < config.MB {
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(config.KB))
	} else if bytes < config.GB {
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(config.MB))
	} else {
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(config.GB))
	}
}

type TargetCount struct {
	Target string
	Count  int
}
