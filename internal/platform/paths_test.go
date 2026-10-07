package platform

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The regression this guards: the detached daemon wrote to
// /var/log/ideviewer/daemon.log, which an unprivileged user cannot create, so
// os.OpenFile failed, the log handle was nil, and every line the daemon
// produced went nowhere. Whatever path this returns must be one the current
// user can actually open for writing.
func TestDaemonLogFileIsWritable(t *testing.T) {
	path := DaemonLogFile()
	if path == "" {
		t.Fatal("DaemonLogFile returned an empty path")
	}
	if !filepath.IsAbs(path) {
		t.Errorf("expected an absolute path, got %q", path)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatalf("DaemonLogFile() = %q, which cannot be opened for writing: %v", path, err)
	}
	defer f.Close()

	if _, err := f.WriteString(""); err != nil {
		t.Errorf("writing to %q failed: %v", path, err)
	}
}

// status, register and reset each used to hardcode their own path, and on
// macOS two of them disagreed. They now all call this, so the value must at
// least be stable within a run.
func TestDaemonLogFileIsStable(t *testing.T) {
	if a, b := DaemonLogFile(), DaemonLogFile(); a != b {
		t.Errorf("DaemonLogFile is not stable: %q then %q", a, b)
	}
}

// On macOS the .pkg installs a LaunchAgent that redirects stdout and stderr to
// a fixed path (build_scripts/build_macos.sh). The fallback spawn has to agree
// with it, or the log location depends on how the daemon happened to start.
func TestDaemonLogFileMatchesLaunchAgentOnDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("LaunchAgent path only applies to macOS")
	}
	const launchAgentPath = "/tmp/ideviewer-daemon.log"
	if got := DaemonLogFile(); got != launchAgentPath {
		t.Errorf("DaemonLogFile() = %q, want %q to match the LaunchAgent plist", got, launchAgentPath)
	}
}

func TestIsWritableDir(t *testing.T) {
	if dir := t.TempDir(); !isWritableDir(dir) {
		t.Errorf("a fresh temp dir %q should be writable", dir)
	}

	if isWritableDir(filepath.Join(t.TempDir(), "does-not-exist")) {
		t.Error("a directory that does not exist is not writable")
	}

	// A probe must not leave anything behind -- this runs against real
	// directories on an operator's machine.
	dir := t.TempDir()
	isWritableDir(dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "ideviewer-write-probe") {
			t.Errorf("probe file left behind: %s", e.Name())
		}
	}
	if len(entries) != 0 {
		t.Errorf("expected the directory to be left empty, found %d entries", len(entries))
	}
}
