//go:build !linux

package safeelf

import "os"

// PinnedPath returns path unchanged where /proc/self/fd is unavailable.
func PinnedPath(_ *os.File, path string) string { return path }
