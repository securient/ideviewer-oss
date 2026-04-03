//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

// setSysProcAttr detaches the child process from the parent session (Unix).
func setSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
