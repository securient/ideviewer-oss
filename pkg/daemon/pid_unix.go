//go:build !windows

package daemon

import (
	"os"
	"syscall"
)

// processAlive reports whether pid names a live process.
//
// Signal 0 performs the kernel's permission and existence checks without
// delivering anything, which is the standard POSIX liveness probe.
func processAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}
