//go:build !linux

package loader

func secureExec() bool { return false }
