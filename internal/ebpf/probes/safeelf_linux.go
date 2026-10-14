//go:build linux

package probes

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// openELFWithinRoot opens rel as an ELF resolved strictly within rootDir using
// openat2(RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS): a "..", an absolute segment,
// or a symlink in the container-controlled path cannot escape rootDir, closing
// the .gnu_debuglink traversal that let the root agent open host files such as
// /proc/kcore.
func openELFWithinRoot(rootDir, rel string) (*elf.File, error) {
	rootFd, err := unix.Open(rootDir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(rootFd) }()

	how := &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_NONBLOCK | unix.O_NOCTTY | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	}
	fd, err := unix.Openat2(rootFd, rel, how)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), rel)
	defer func() { _ = file.Close() }()

	fi, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("debug file %q is not a regular file", rel)
	}
	if fi.Size() > maxELFFileSize {
		return nil, fmt.Errorf("debug file %q too large: %d bytes", rel, fi.Size())
	}
	buf := make([]byte, fi.Size())
	if _, err := io.ReadFull(file, buf); err != nil {
		return nil, err
	}
	return elf.NewFile(bytes.NewReader(buf))
}

var openat2 = unix.Openat2

// statWithinRoot stats rel resolved strictly within rootDir, the same
// confinement openELFWithinRoot applies. supported is false on a kernel
// without openat2, where no such check is possible.
func statWithinRoot(rootDir, rel string) (st unix.Stat_t, supported bool, err error) {
	rootFd, err := unix.Open(rootDir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return st, true, err
	}
	defer func() { _ = unix.Close(rootFd) }()

	how := &unix.OpenHow{
		Flags:   uint64(unix.O_PATH | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	}
	fd, err := openat2(rootFd, rel, how)
	if errors.Is(err, unix.ENOSYS) {
		return st, false, nil
	}
	if err != nil {
		return st, true, err
	}
	defer func() { _ = unix.Close(fd) }()
	err = unix.Fstat(fd, &st)
	return st, true, err
}

// confirmWithinRoot reports whether hostPath, a path under rootDir with no
// symlink left in it, names the same regular file that rel resolves to when
// the lookup is held inside rootDir.
func confirmWithinRoot(rootDir, rel, hostPath string) bool {
	fi, err := os.Stat(hostPath)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	st, supported, err := statWithinRoot(rootDir, rel)
	if !supported {
		return true
	}
	if err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return false
	}
	sys, ok := fi.Sys().(*syscall.Stat_t)
	return ok && uint64(sys.Dev) == st.Dev && sys.Ino == st.Ino
}
