//go:build windows

package daemon

import (
	"golang.org/x/sys/windows"
)

// processAlive reports whether pid names a live process.
//
// The POSIX "signal 0" probe cannot be used here: os.Process.Signal on Windows
// rejects everything except Kill with EWINDOWS, so the shared implementation
// reported *every* process as dead. That made CreatePIDFile's duplicate check
// a no-op, and a Windows machine could accumulate several daemons at once --
// each holding whichever config it started with, and only one of them picking
// up the portal's scan requests.
//
// OpenProcess with PROCESS_QUERY_LIMITED_INFORMATION is the Win32 equivalent:
// it succeeds only for a process that exists, and needs no elevation. A PID
// that has exited but whose handle is still open reports a real exit code,
// which STILL_ACTIVE (259) distinguishes from a running process.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)

	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		// The handle opened, so the process object exists; treat it as alive
		// rather than risk a second daemon.
		return true
	}
	const stillActive = 259
	return code == stillActive
}
