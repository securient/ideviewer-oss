//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// stopProcess asks pid to shut down gracefully.
//
// Windows has no SIGTERM. The closest equivalent for a console program is a
// Ctrl+Break sent to its process group, which Go's os/signal maps to
// syscall.SIGTERM in the daemon -- so the daemon's existing handler runs and
// posts the "daemon_stopping" tamper alert before exiting. This works because
// the daemon is launched with CREATE_NEW_PROCESS_GROUP (see procattr_windows.go),
// making its PID a valid process-group id.
//
// GenerateConsoleCtrlEvent only reaches processes attached to *our* console, so
// it fails when stopping a daemon started from a different session (a scheduled
// task, or another terminal). TerminateProcess is the fallback: abrupt, but a
// daemon that keeps running after 'ideviewer stop' is worse -- that is what
// wedged updates on Windows.
func stopProcess(pid int) error {
	if err := windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, uint32(pid)); err == nil {
		return nil
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return proc.Kill()
}
