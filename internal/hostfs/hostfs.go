// Package hostfs provides explicit, audited access to filesystem
// paths that intentionally cross trust boundaries.
//
// Most filesystem access in podtrace is scoped via internal/procfs and
// internal/sysfs, which use os.Root to prevent traversal escapes. A
// few code paths must legitimately operate on paths that no os.Root
// can scope:
//
//   - /proc/<pid>/root/<container-path> — traversing through the
//     kernel's per-process mount-namespace symlink to find a libc or
//     SSL library inside a container's rootfs. The kernel's pid/root
//     symlink IS the trust boundary; constraining the destination
//     defeats the purpose of the lookup.
//
//   - $HOME/.kube/config / /home/<sudoUser>/.kube/config — explicit
//     CLI behaviour that follows the operator's environment.
//
//   - filepath.Walk over a host directory derived from ld.so.conf —
//     the entries returned by the linker config are themselves under
//     /usr or /lib and the walker honours symlinks the linker would.
package hostfs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

var ErrInvalidPath = errors.New("hostfs: path must be absolute and contain no '..' elements")

var ErrUnsafeMode = errors.New("hostfs: refusing to write with a group/other-writable mode")

func validate(path string) error {
	if !filepath.IsAbs(path) {
		return ErrInvalidPath
	}
	for _, seg := range strings.Split(path, string(filepath.Separator)) {
		if seg == ".." {
			return ErrInvalidPath
		}
	}
	return nil
}

// Stat returns FileInfo for an absolute host path. The path is
// validated to be absolute and free of ".." segments before the
// underlying os.Stat fires.
func Stat(path string) (os.FileInfo, error) {
	if err := validate(path); err != nil {
		return nil, err
	}
	return os.Stat(path) // #nosec G304,G703 -- intentional cross-namespace stat; validated absolute path with no ".." segments. See package docs.
}

// IsRegularFile reports whether path names a regular file, following
// symlinks. FIFOs, sockets and device nodes are not regular: opening one to
// parse it can block forever.
func IsRegularFile(path string) bool {
	info, err := Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// WalkRegular invokes fn for every regular file under root. Symlinks are
// not followed: filepath.Walk reports them by their own mode, so they are
// skipped along with FIFOs, sockets and devices.
func WalkRegular(root string, fn func(path string, info os.FileInfo) error) error {
	if err := validate(root); err != nil {
		return err
	}
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error { // #nosec G304,G703 -- root is validated absolute path; per-entry "info" is kernel-provided.
		if err != nil || info == nil || !info.Mode().IsRegular() {
			return nil
		}
		return fn(path, info)
	})
}

func Open(path string) (*os.File, error) {
	if err := validate(path); err != nil {
		return nil, err
	}
	return os.Open(path) // #nosec G304 -- intentional cross-namespace open; validated absolute path with no ".." segments.
}

// ReadFile reads a file the operator has explicitly designated via a
// CLI flag or environment variable.
func ReadFile(path string) ([]byte, error) {
	if err := validate(path); err != nil {
		return nil, err
	}
	return os.ReadFile(path) // #nosec G304 -- operator-supplied path validated above; CLI flag / env var is the intended source.
}

// WriteFile writes data to a path the operator has explicitly
// designated via a CLI flag.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	if err := validate(path); err != nil {
		return err
	}
	if perm&0o022 != 0 {
		return fmt.Errorf("%w: %#o (%s)", ErrUnsafeMode, perm, path)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, perm) // #nosec G304 -- path validated absolute/no-".."; mode asserted non-group/other-writable above; O_NOFOLLOW blocks symlink redirection; some handoffs pass 0644 so a nonroot sidecar can read a root-written file over a pod-private emptyDir.
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// ErrOutsideBase is returned by WriteFileWithin when the target path
// resolves outside the permitted base directory.
var ErrOutsideBase = errors.New("hostfs: path escapes the permitted base directory")

// WriteFileWithin is WriteFile plus a base-directory jail: it refuses to
// write anywhere outside baseDir.
func WriteFileWithin(baseDir, path string, data []byte, perm os.FileMode) error {
	if err := ensureWithin(baseDir, path); err != nil {
		return err
	}
	return WriteFile(path, data, perm)
}

// ensureWithin validates baseDir and path (absolute, no "..") and confirms
// path does not escape baseDir.
func ensureWithin(baseDir, path string) error {
	if err := validate(baseDir); err != nil {
		return err
	}
	if err := validate(path); err != nil {
		return err
	}
	rel, err := filepath.Rel(filepath.Clean(baseDir), filepath.Clean(path))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: %s not under %s", ErrOutsideBase, path, baseDir)
	}
	return nil
}

// WriteFileAtomic writes data via a temp file + rename so a concurrent reader
// (e.g. the report-uploader sidecar polling the shared emptyDir) never sees a
// partially-written or empty file.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := validate(path); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// Compile-time check that fs.FileInfo and os.FileInfo are the same.
var _ fs.FileInfo = os.FileInfo(nil)
