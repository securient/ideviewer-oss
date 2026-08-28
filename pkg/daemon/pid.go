package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// ReadPIDFile returns the PID recorded at path, or an error if the file is
// missing or does not hold an integer.
func ReadPIDFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("invalid PID in %s: %q", path, strings.TrimSpace(string(data)))
	}
	return pid, nil
}

// IsRunning reports whether the PID recorded at path belongs to a live
// process. A missing or unparseable file, or a dead PID, is false.
func IsRunning(path string) bool {
	pid, err := ReadPIDFile(path)
	if err != nil {
		return false
	}
	return processAlive(pid)
}
