package main

import (
	"fmt"
	"os"
	"time"

	"github.com/securient/ideviewer-oss/internal/platform"
	"github.com/securient/ideviewer-oss/pkg/daemon"
	"github.com/spf13/cobra"
)

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the running daemon",
	RunE:  runStop,
}

func init() {
	stopCmd.Flags().String("pid-file", "", "PID file path")
	stopCmd.Flags().Duration("timeout", 10*time.Second, "How long to wait for the daemon to exit")
}

func runStop(cmd *cobra.Command, args []string) error {
	pidFile, _ := cmd.Flags().GetString("pid-file")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	if pidFile == "" {
		pidFile = platform.DefaultPIDFile()
	}

	pid, err := daemon.ReadPIDFile(pidFile)
	if err != nil {
		if os.IsNotExist(err) {
			colorYellow.Println("No daemon is running (PID file not found)")
			return nil
		}
		return err
	}

	if !daemon.IsRunning(pidFile) {
		colorYellow.Printf("Daemon is not running (stale PID %d); removing PID file\n", pid)
		daemon.RemovePIDFile(pidFile)
		return nil
	}

	// stopProcess asks the daemon to shut down gracefully. Previously this sent
	// SIGTERM unconditionally, which os.Process.Signal rejects on Windows: stop
	// printed "already stopped", deleted the PID file, and left the daemon
	// running. Anyone updating IDEViewer on Windows then hit a locked
	// ideviewer.exe and an old daemon still talking to the portal.
	if err := stopProcess(pid); err != nil {
		return fmt.Errorf("could not stop daemon (PID %d): %w", pid, err)
	}
	colorGreen.Printf("Sent stop signal to daemon (PID: %d)\n", pid)

	// Only drop the PID file once the process is actually gone, so a failed
	// stop stays visible to the next 'ideviewer status' instead of being
	// papered over.
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !daemon.IsRunning(pidFile) {
			daemon.RemovePIDFile(pidFile)
			colorGreen.Println("Daemon stopped.")
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}

	colorYellow.Printf("Daemon (PID %d) did not exit within %s; it may still be shutting down.\n", pid, timeout)
	colorDim.Printf("Check with: ideviewer status\n")
	return nil
}
