// Package hooks manages IDEViewer global git pre-commit and post-commit hooks.
package hooks

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/securient/ideviewer-oss/internal/platform"
	"github.com/securient/ideviewer-oss/pkg/gitleaks"
)

// HookStatus describes the current state of the hook installation.
type HookStatus struct {
	Installed       bool   `json:"installed"`
	HookPath        string `json:"hook_path"`
	ScannerType     string `json:"scanner_type"`     // "gitleaks" or "built-in"
	GitleaksVersion string `json:"gitleaks_version"`
}

// Install writes pre-commit and post-commit hooks to ~/.ideviewer/hooks/
// and sets git config --global core.hooksPath to point there.
func Install() error {
	if _, err := exec.LookPath("git"); err != nil {
		return fmt.Errorf("git is not installed: %w", err)
	}

	hooksDir := platform.HooksDir()
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		return fmt.Errorf("failed to create hooks directory: %w", err)
	}

	isWindows := runtime.GOOS == "windows"

	// Select scripts based on platform.
	preCommitContent := preCommitBash
	postCommitContent := postCommitBash
	if isWindows {
		preCommitContent = preCommitBatch
		postCommitContent = postCommitBatch
	}

	// Write pre-commit hook.
	preCommitPath := filepath.Join(hooksDir, "pre-commit")
	if err := os.WriteFile(preCommitPath, []byte(preCommitContent), 0o644); err != nil {
		return fmt.Errorf("failed to write pre-commit hook: %w", err)
	}
	if !isWindows {
		if err := os.Chmod(preCommitPath, 0o755); err != nil {
			return fmt.Errorf("failed to set pre-commit executable: %w", err)
		}
	}

	// Write post-commit hook.
	postCommitPath := filepath.Join(hooksDir, "post-commit")
	if err := os.WriteFile(postCommitPath, []byte(postCommitContent), 0o644); err != nil {
		return fmt.Errorf("failed to write post-commit hook: %w", err)
	}
	if !isWindows {
		if err := os.Chmod(postCommitPath, 0o755); err != nil {
			return fmt.Errorf("failed to set post-commit executable: %w", err)
		}
	}

	// Set global hooks path.
	cmd := exec.Command("git", "config", "--global", "core.hooksPath", hooksDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set global hooksPath: %s: %w", strings.TrimSpace(string(out)), err)
	}

	return nil
}

// Uninstall removes the hook scripts and unsets git config --global core.hooksPath.
func Uninstall() error {
	if _, err := exec.LookPath("git"); err != nil {
		return fmt.Errorf("git is not installed: %w", err)
	}

	// Unset global hooks path (ignore error if not set).
	_ = exec.Command("git", "config", "--global", "--unset", "core.hooksPath").Run()

	hooksDir := platform.HooksDir()
	for _, name := range []string{"pre-commit", "post-commit"} {
		hookPath := filepath.Join(hooksDir, name)
		if err := os.Remove(hookPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove %s: %w", name, err)
		}
	}

	return nil
}

// Status returns the current hook installation status.
func Status() (*HookStatus, error) {
	hooksDir := platform.HooksDir()
	preCommitPath := filepath.Join(hooksDir, "pre-commit")

	// Check if hook file exists.
	fileExists := platform.PathExists(preCommitPath)

	// Check if git global hooksPath is set to our directory.
	hooksPathConfigured := false
	if _, err := exec.LookPath("git"); err == nil {
		out, err := exec.Command("git", "config", "--global", "core.hooksPath").Output()
		if err == nil {
			configured := strings.TrimSpace(string(out))
			if configured != "" {
				// Resolve both to absolute paths for comparison.
				absConfigured, err1 := filepath.Abs(configured)
				absHooksDir, err2 := filepath.Abs(hooksDir)
				if err1 == nil && err2 == nil && absConfigured == absHooksDir {
					hooksPathConfigured = true
				}
			}
		}
	}

	installed := fileExists && hooksPathConfigured

	// Determine scanner type.
	scannerType := "built-in"
	gitleaksVersion := ""
	if gitleaks.IsInstalled() {
		scannerType = "gitleaks"
		if v, err := gitleaks.GetVersion(); err == nil {
			gitleaksVersion = v
		}
	}

	return &HookStatus{
		Installed:       installed,
		HookPath:        hooksDir,
		ScannerType:     scannerType,
		GitleaksVersion: gitleaksVersion,
	}, nil
}
