package detectors

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/process"
)

// FindExecutable looks for name on PATH and then in additionalPaths.
// Returns the first found path, or empty string.
func FindExecutable(name string, additionalPaths ...string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, p := range additionalPaths {
		expanded := ExpandPath(p)
		if info, err := os.Stat(expanded); err == nil && !info.IsDir() {
			return expanded
		}
	}
	return ""
}

// GetVersion runs executable with the given args (default --version) and
// returns the first line of combined stdout/stderr output.
func GetVersion(executable string, args ...string) string {
	if len(args) == 0 {
		args = []string{"--version"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(out))
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		s = s[:idx]
	}
	return s
}

// IsProcessRunning checks whether any of the given process names are currently
// running. It silently returns false on any error.
func IsProcessRunning(names ...string) bool {
	set := make(map[string]struct{}, len(names))
	for _, n := range names {
		set[n] = struct{}{}
	}
	procs, err := process.Processes()
	if err != nil {
		return false
	}
	for _, p := range procs {
		n, err := p.Name()
		if err != nil {
			continue
		}
		if _, ok := set[n]; ok {
			return true
		}
	}
	return false
}

// ExpandPath expands ~ and environment variables in a path.
func ExpandPath(p string) string {
	if strings.HasPrefix(p, "~/") || p == "~" {
		home, err := os.UserHomeDir()
		if err == nil {
			p = filepath.Join(home, p[1:])
		}
	}
	return os.ExpandEnv(p)
}

// PathExists returns true if the expanded path exists.
func PathExists(p string) bool {
	_, err := os.Stat(ExpandPath(p))
	return err == nil
}

// HomeDir returns the current user's home directory.
func HomeDir() string {
	h, _ := os.UserHomeDir()
	return h
}

// PlatformKey returns "darwin", "linux", or "windows".
func PlatformKey() string {
	return runtime.GOOS
}
