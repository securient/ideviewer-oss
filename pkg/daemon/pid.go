package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// CreatePIDFile writes the current process's PID to the given path.
// It returns an error if another process is already running with the PID
// recorded in an existing file.
func CreatePIDFile(path string) error {
	if IsRunning(path) {
		return fmt.Errorf("daemon already running (PID file: %s)", path)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create PID directory: %w", err)
	}

	pid := os.Getpid()
	if err := os.WriteFile(path, []byte(strconv.Itoa(pid)), 0644); err != nil {
		return fmt.Errorf("write PID file: %w", err)
	}

	return nil
}

// RemovePIDFile removes the PID file at path if it exists.
func RemovePIDFile(path string) {
	_ = os.Remove(path)
}

// IsRunning checks if a daemon process is already running by reading the PID
// file and sending signal 0 to the recorded PID. Returns false if the file
// does not exist or the process is not alive.
func IsRunning(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return false
	}

	// Signal 0 checks whether the process exists without actually signalling.
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	err = proc.Signal(syscall.Signal(0))
	return err == nil
}
