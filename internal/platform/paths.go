package platform

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// HomeDir returns the user's home directory.
func HomeDir() string {
	home, _ := os.UserHomeDir()
	return home
}

// ExpandPath expands ~ and environment variables in a path.
// Handles both Unix ($VAR) and Windows (%VAR%) syntax.
func ExpandPath(p string) string {
	if strings.HasPrefix(p, "~/") || p == "~" {
		p = filepath.Join(HomeDir(), p[1:])
	}
	if runtime.GOOS == "windows" && strings.Contains(p, "%") {
		for {
			start := strings.Index(p, "%")
			if start == -1 {
				break
			}
			end := strings.Index(p[start+1:], "%")
			if end == -1 {
				break
			}
			end += start + 1
			varName := p[start+1 : end]
			varValue := os.Getenv(varName)
			if varValue != "" {
				p = p[:start] + varValue + p[end+1:]
			} else {
				break
			}
		}
	}
	return os.ExpandEnv(p)
}

// PathExists checks if a path exists.
func PathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// IsWindows returns true on Windows.
func IsWindows() bool { return runtime.GOOS == "windows" }

// IsMacOS returns true on macOS.
func IsMacOS() bool { return runtime.GOOS == "darwin" }

// IsLinux returns true on Linux.
func IsLinux() bool { return runtime.GOOS == "linux" }

// ConfigDir returns the platform-specific config directory for IDEViewer.
func ConfigDir() string {
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("LOCALAPPDATA")
		if base == "" {
			base = filepath.Join(HomeDir(), "AppData", "Local")
		}
		return filepath.Join(base, "IDEViewer")
	case "darwin":
		return filepath.Join(HomeDir(), ".ideviewer")
	default: // linux
		return filepath.Join(HomeDir(), ".ideviewer")
	}
}

// SystemConfigDir returns the system-level config directory.
func SystemConfigDir() string {
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("PROGRAMDATA")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "IDEViewer")
	case "darwin":
		return "/Library/Application Support/IDEViewer"
	default:
		return "/etc/ideviewer"
	}
}

// LogDir returns the platform-specific log directory.
func LogDir() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(ConfigDir(), "logs")
	case "darwin":
		return "/var/log/ideviewer"
	default:
		return "/var/log/ideviewer"
	}
}

// DaemonLogFile returns the file the daemon's own output is written to.
//
// One function so the spawner, `status` and `reset` cannot disagree. They used
// to hardcode a path each, and on macOS two of them did not match: `register`
// started the detached fallback writing to /var/log/ideviewer/daemon.log --
// which an unprivileged user cannot create, so the output was discarded
// silently -- while `status` reported /tmp/ideviewer-daemon.log and found
// nothing there. "Last written: never" was the only clue, on a file nothing
// had ever been pointed at.
func DaemonLogFile() string {
	// macOS: the LaunchAgent the .pkg installs redirects stdout/stderr here
	// (see build_scripts/build_macos.sh). The fallback process must use the
	// same file, or the log moves depending on how the daemon happened to be
	// started.
	if runtime.GOOS == "darwin" {
		return "/tmp/ideviewer-daemon.log"
	}

	dir := LogDir()
	if err := os.MkdirAll(dir, 0o755); err == nil && isWritableDir(dir) {
		return filepath.Join(dir, "daemon.log")
	}

	// An unprivileged run cannot create /var/log/ideviewer. A log in the temp
	// directory beats no log at all, which is what happened before.
	return filepath.Join(os.TempDir(), "ideviewer-daemon.log")
}

// isWritableDir reports whether dir can be written to, by trying rather than by
// inspecting permission bits -- which say nothing about ACLs, read-only mounts
// or container user mappings.
func isWritableDir(dir string) bool {
	f, err := os.CreateTemp(dir, ".ideviewer-write-probe-*")
	if err != nil {
		return false
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return true
}

// DefaultPIDFile returns the default PID file path.
func DefaultPIDFile() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(ConfigDir(), "ideviewer.pid")
	}
	return "/tmp/ideviewer.pid"
}

// BinaryInstallPath returns where the ideviewer binary is expected.
func BinaryInstallPath() string {
	switch runtime.GOOS {
	case "windows":
		pf := os.Getenv("ProgramFiles")
		if pf == "" {
			pf = `C:\Program Files`
		}
		return filepath.Join(pf, "IDEViewer", "ideviewer.exe")
	default:
		return "/usr/local/bin/ideviewer"
	}
}

// ServiceFilePath returns the path to the daemon service file.
func ServiceFilePath() string {
	switch runtime.GOOS {
	case "darwin":
		return "/Library/LaunchDaemons/com.ideviewer.daemon.plist"
	case "linux":
		return "/etc/systemd/system/ideviewer.service"
	default:
		return ""
	}
}

// GitleaksBinDir returns the directory for the gitleaks binary.
func GitleaksBinDir() string {
	return filepath.Join(HomeDir(), ".ideviewer", "bin")
}

// GitleaksBinPath returns the full path to the gitleaks binary.
func GitleaksBinPath() string {
	name := "gitleaks"
	if runtime.GOOS == "windows" {
		name = "gitleaks.exe"
	}
	return filepath.Join(GitleaksBinDir(), name)
}

// HooksDir returns the directory for git hooks.
func HooksDir() string {
	return filepath.Join(HomeDir(), ".ideviewer", "hooks")
}

// BypassesDir returns the directory for hook bypass records.
func BypassesDir() string {
	return filepath.Join(HomeDir(), ".ideviewer", "bypasses")
}

// QuarantineDir returns the directory where quarantined extensions are moved.
func QuarantineDir() string {
	return filepath.Join(HomeDir(), ".ideviewer", "quarantine")
}

// BypassesPendingFile returns the path to the pending bypasses file.
func BypassesPendingFile() string {
	return filepath.Join(BypassesDir(), "pending.jsonl")
}
