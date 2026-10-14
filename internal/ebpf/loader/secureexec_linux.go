//go:build linux

package loader

import "golang.org/x/sys/unix"

const atSecure = 23

var auxv = unix.Auxv

// secureExec reports whether this process runs with privilege its caller does
// not hold, in which case nothing the caller controls may pick what it loads.
// An unreadable auxiliary vector counts as secure.
func secureExec() bool {
	vec, err := auxv()
	if err != nil {
		return true
	}
	for _, kv := range vec {
		if kv[0] == atSecure {
			return kv[1] != 0
		}
	}
	return false
}
