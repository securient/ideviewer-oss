//go:build !windows

package main

import (
	"os"
	"syscall"
)

// stopProcess asks pid to shut down gracefully. SIGTERM lets the daemon run
// its signal handler, which posts the "daemon_stopping" tamper alert to the
// portal before exiting.
func stopProcess(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return proc.Signal(syscall.SIGTERM)
}
