//go:build windows

package main

import "os/exec"

// setSysProcAttr is a no-op on Windows (Setsid is Unix-only).
func setSysProcAttr(cmd *exec.Cmd) {
	// Windows doesn't support Setsid. The process will still run
	// after the parent exits because we call Process.Release().
}
