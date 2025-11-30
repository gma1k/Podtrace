package validation

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	podNameRegex     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	namespaceRegex   = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	maxPodNameLength = 63
	maxNamespaceLength = 253
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

func ValidatePID(pid uint32) bool {
	return pid > 0 && pid < 4194304
}

func SanitizeProcessName(name string) string {
	name = strings.TrimSpace(name)
	var result strings.Builder
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
