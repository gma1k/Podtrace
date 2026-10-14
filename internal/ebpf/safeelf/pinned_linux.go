//go:build linux

package safeelf

import (
	"fmt"
	"os"
)

// PinnedPath names the file f has open as /proc/self/fd/<n>, so a later open
// of the returned path reaches exactly the inode f was checked against even
// when the original path has since been replaced. It is valid only while f
// stays open.
func PinnedPath(f *os.File, _ string) string {
	return fmt.Sprintf("/proc/self/fd/%d", f.Fd())
}
