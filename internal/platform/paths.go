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
func ExpandPath(p string) string {
	if strings.HasPrefix(p, "~/") || p == "~" {
		p = filepath.Join(HomeDir(), p[1:])
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

// BypassesPendingFile returns the path to the pending bypasses file.
func BypassesPendingFile() string {
	return filepath.Join(BypassesDir(), "pending.jsonl")
}
