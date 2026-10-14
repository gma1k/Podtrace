package probes

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/gma1k/podtrace/internal/config"
)

const maxRootSymlinks = 40

// procRoot is the host path of pid's root directory.
func procRoot(pid uint32) string {
	return filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "root")
}

// fileInProcRoot resolves a path reported by a traced process against that
// process's own rootfs.
func fileInProcRoot(pid uint32, containerPath string) string {
	if containerPath == "" || strings.HasPrefix(containerPath, "[") {
		return ""
	}
	return fileWithinRoot(procRoot(pid), containerPath)
}

// fileWithinRoot returns the host path of the regular file containerPath
// names inside root, or "" when there is none.
func fileWithinRoot(root, containerPath string) string {
	resolved, ok := resolveWithinRoot(root, containerPath)
	if !ok {
		return ""
	}
	hostPath := filepath.Join(root, resolved)
	if !confirmWithinRoot(root, resolved, hostPath) {
		return ""
	}
	return hostPath
}

// resolveWithinRoot expands every symlink in containerPath as if root were
// "/", returning a clean absolute path relative to root.
func resolveWithinRoot(root, containerPath string) (string, bool) {
	pending := splitPath(containerPath)
	resolved := "/"
	links := 0
	for len(pending) > 0 {
		name := pending[0]
		pending = pending[1:]
		if name == ".." {
			resolved = filepath.Dir(resolved)
			continue
		}
		next := filepath.Join(resolved, name)
		target, err := os.Readlink(filepath.Join(root, next))
		if errors.Is(err, syscall.EINVAL) {
			resolved = next
			continue
		}
		if err != nil {
			return "", false
		}
		links++
		if links > maxRootSymlinks {
			return "", false
		}
		if filepath.IsAbs(target) {
			resolved = "/"
		}
		pending = append(splitPath(target), pending...)
	}
	return resolved, true
}

// splitPath returns the non-empty, non-"." segments of p.
func splitPath(p string) []string {
	var out []string
	for _, seg := range strings.Split(p, "/") {
		if seg != "" && seg != "." {
			out = append(out, seg)
		}
	}
	return out
}
