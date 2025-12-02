package validation

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	podNameRegex           = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	namespaceRegex         = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	containerNameRegex     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9_.]*[a-z0-9])?$`)
	maxPodNameLength       = 63
	maxNamespaceLength     = 253
	maxContainerNameLength = 63
	maxExportFormatLength  = 10
	maxEventFilterLength   = 100
)

func ValidatePodName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("pod name cannot be empty")
	}
	if len(name) > maxPodNameLength {
		return fmt.Errorf("pod name exceeds maximum length of %d characters", maxPodNameLength)
	}
	if !podNameRegex.MatchString(name) {
		return fmt.Errorf("pod name must match RFC 1123 subdomain format (lowercase alphanumeric and hyphens)")
	}
	return nil
}

func ValidateNamespace(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("namespace cannot be empty")
	}
	if len(name) > maxNamespaceLength {
		return fmt.Errorf("namespace exceeds maximum length of %d characters", maxNamespaceLength)
	}
	if !namespaceRegex.MatchString(name) {
		return fmt.Errorf("namespace must match RFC 1123 subdomain format (lowercase alphanumeric and hyphens)")
	}
	return nil
}

func ValidateContainerName(name string) error {
	if name == "" {
		return nil
	}
	if len(name) > maxContainerNameLength {
		return fmt.Errorf("container name exceeds maximum length of %d characters", maxContainerNameLength)
	}
	if !containerNameRegex.MatchString(name) {
		return fmt.Errorf("container name must match RFC 1123 subdomain format (lowercase alphanumeric, hyphens, underscores, and dots)")
	}
	return nil
}

func ValidateExportFormat(format string) error {
	if format == "" {
		return nil
	}
	if len(format) > maxExportFormatLength {
		return fmt.Errorf("export format exceeds maximum length of %d characters", maxExportFormatLength)
	}
	format = strings.ToLower(format)
	if format != "json" && format != "csv" {
		return fmt.Errorf("export format must be 'json' or 'csv'")
	}
	return nil
}

func ValidateEventFilter(filter string) error {
	if filter == "" {
		return nil
	}
	if len(filter) > maxEventFilterLength {
		return fmt.Errorf("event filter exceeds maximum length of %d characters", maxEventFilterLength)
	}
	validFilters := map[string]bool{
		"dns":  true,
		"net":  true,
		"fs":   true,
		"cpu":  true,
		"proc": true,
	}
	filters := strings.Split(strings.ToLower(filter), ",")
	for _, f := range filters {
		f = strings.TrimSpace(f)
		if f != "" && !validFilters[f] {
			return fmt.Errorf("invalid event filter: %s (valid: dns, net, fs, cpu, proc)", f)
		}
	}
	return nil
}

func ValidatePID(pid uint32) bool {
	return pid > 0 && pid < 4194304
}

func SanitizeProcessName(name string) string {
	name = strings.TrimSpace(name)
	var result strings.Builder
	result.Grow(len(name))
	for _, r := range name {
		if r >= 32 && r < 127 && r != '%' {
			result.WriteRune(r)
		}
	}
	return result.String()
}

var containerIDRegex = regexp.MustCompile(`^[a-f0-9]{64}$|^[a-f0-9]{12,}$`)

func ValidateContainerID(containerID string) bool {
	if len(containerID) == 0 || len(containerID) > 128 {
		return false
	}
	if strings.Contains(containerID, "..") || strings.Contains(containerID, "/") {
		return false
	}
	return containerIDRegex.MatchString(containerID)
}

func SanitizeCSVField(field string) string {
	if strings.ContainsAny(field, ",\"\n\r") {
		field = strings.ReplaceAll(field, "\"", "\"\"")
		return "\"" + field + "\""
	}
	return field
}

func ValidateErrorRateThreshold(value float64) error {
	if value < 0 || value > 100 {
		return fmt.Errorf("error threshold must be between 0 and 100")
	}
	return nil
}

func ValidateRTTThreshold(value float64) error {
	if value < 0 {
		return fmt.Errorf("RTT threshold must be non-negative")
	}
	return nil
}

func ValidateFSThreshold(value float64) error {
	if value < 0 {
		return fmt.Errorf("file system threshold must be non-negative")
	}
	return nil
}

func ValidateDiagnoseDuration(duration time.Duration) error {
	if duration <= 0 {
		return fmt.Errorf("duration must be positive")
	}
	if duration > 24*time.Hour {
		return fmt.Errorf("duration cannot exceed 24 hours")
	}
	return nil
}
