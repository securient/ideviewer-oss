//go:build windows

package main

import (
	"os/exec"

	"golang.org/x/sys/windows"
)

// setSysProcAttr detaches the child daemon from the launching console.
//
// This used to be a no-op, on the assumption that Process.Release() was enough
// to outlive the parent. It is not: a child that inherits its parent's console
// receives CTRL_CLOSE_EVENT when that console window closes, so the daemon died
// the moment the user shut the terminal they registered from. To the portal
// that looks exactly like "the daemon never picks up scan requests".
//
//   - DETACHED_PROCESS         — do not inherit the parent's console at all
//   - CREATE_NEW_PROCESS_GROUP — give the daemon its own group so 'ideviewer
//     stop' can address it with GenerateConsoleCtrlEvent
//   - CREATE_NO_WINDOW         — never flash a console window for a background
//     service
func setSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &windows.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS |
			windows.CREATE_NEW_PROCESS_GROUP |
			windows.CREATE_NO_WINDOW,
	}
}
