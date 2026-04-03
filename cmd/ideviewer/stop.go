package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/securient/ideviewer-oss/internal/platform"
	"github.com/spf13/cobra"
)

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the running daemon",
	RunE:  runStop,
}

func init() {
	stopCmd.Flags().String("pid-file", "", "PID file path")
}

func runStop(cmd *cobra.Command, args []string) error {
	pidFile, _ := cmd.Flags().GetString("pid-file")
	if pidFile == "" {
		pidFile = platform.DefaultPIDFile()
	}

	data, err := os.ReadFile(pidFile)
	if err != nil {
		colorYellow.Println("No daemon is running (PID file not found)")
		return nil
	}

	pidStr := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return fmt.Errorf("invalid PID in file: %s", pidStr)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		colorYellow.Println("Daemon process not found (already stopped?)")
		_ = os.Remove(pidFile)
		return nil
	}

	if err := proc.Signal(syscall.SIGTERM); err != nil {
		colorYellow.Println("Daemon process not found (already stopped?)")
		_ = os.Remove(pidFile)
		return nil
	}

	colorGreen.Printf("Sent stop signal to daemon (PID: %d)\n", pid)
	_ = os.Remove(pidFile)
	return nil
}
