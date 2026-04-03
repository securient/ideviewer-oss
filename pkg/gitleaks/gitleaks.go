// Package gitleaks manages installation and version detection of the gitleaks binary.
package gitleaks

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/securient/ideviewer-oss/internal/platform"
)

const githubReleasesURL = "https://api.github.com/repos/gitleaks/gitleaks/releases/latest"

// IsInstalled returns true if gitleaks is available (ideviewer-managed or system PATH).
func IsInstalled() bool {
	binPath := platform.GitleaksBinPath()
	if info, err := os.Stat(binPath); err == nil && !info.IsDir() {
		return true
	}
	_, err := exec.LookPath("gitleaks")
	return err == nil
}

// GetVersion returns the installed gitleaks version string, or an error.
func GetVersion() (string, error) {
	gitleaksCmd := ""

	binPath := platform.GitleaksBinPath()
	if info, err := os.Stat(binPath); err == nil && !info.IsDir() {
		gitleaksCmd = binPath
	} else if p, err := exec.LookPath("gitleaks"); err == nil {
		gitleaksCmd = p
	}

	if gitleaksCmd == "" {
		return "", fmt.Errorf("gitleaks not found")
	}

	out, err := exec.Command(gitleaksCmd, "version").Output()
	if err != nil {
		return "", fmt.Errorf("failed to get gitleaks version: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// Install downloads and installs gitleaks. On macOS it tries brew first.
func Install() error {
	if IsInstalled() {
		return nil // already installed
	}

	// macOS: try Homebrew first.
	if runtime.GOOS == "darwin" {
		if err := installViaBrew(); err == nil {
			return nil
		}
	}

	return downloadFromGitHub()
}

// installViaBrew attempts to install gitleaks via Homebrew.
func installViaBrew() error {
	if _, err := exec.LookPath("brew"); err != nil {
		return fmt.Errorf("brew not found")
	}
	cmd := exec.Command("brew", "install", "gitleaks")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// normalizedArch returns the gitleaks asset architecture string.
func normalizedArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x64"
	case "arm64":
		return "arm64"
	case "386":
		return "x32"
	default:
		return runtime.GOARCH
	}
}

// githubRelease is the subset of the GitHub release API we need.
type githubRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// downloadFromGitHub downloads the latest gitleaks release for this platform.
func downloadFromGitHub() error {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", githubReleasesURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "IDEViewer")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch GitHub release info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return fmt.Errorf("failed to parse GitHub release: %w", err)
	}

	if release.TagName == "" || len(release.Assets) == 0 {
		return fmt.Errorf("no release version or assets found")
	}

	// Find matching asset.
	system := runtime.GOOS
	arch := normalizedArch()

	var targetAsset *githubAsset
	for i, asset := range release.Assets {
		name := strings.ToLower(asset.Name)
		switch system {
		case "darwin":
			if strings.Contains(name, "darwin") && strings.Contains(name, arch) {
				targetAsset = &release.Assets[i]
			}
		case "linux":
			if strings.Contains(name, "linux") && strings.Contains(name, arch) &&
				!strings.HasSuffix(name, ".rpm") && !strings.HasSuffix(name, ".deb") {
				targetAsset = &release.Assets[i]
			}
		case "windows":
			if strings.Contains(name, "windows") && strings.Contains(name, arch) {
				targetAsset = &release.Assets[i]
			}
		}
		if targetAsset != nil {
			break
		}
	}

	if targetAsset == nil {
		return fmt.Errorf("no suitable gitleaks binary found for %s/%s", system, arch)
	}

	// Download the asset.
	dlClient := &http.Client{Timeout: 120 * time.Second}
	dlReq, err := http.NewRequest("GET", targetAsset.BrowserDownloadURL, nil)
	if err != nil {
		return err
	}
	dlReq.Header.Set("User-Agent", "IDEViewer")

	dlResp, err := dlClient.Do(dlReq)
	if err != nil {
		return fmt.Errorf("failed to download gitleaks: %w", err)
	}
	defer dlResp.Body.Close()

	archiveData, err := io.ReadAll(dlResp.Body)
	if err != nil {
		return fmt.Errorf("failed to read download: %w", err)
	}

	// Create bin directory.
	binDir := platform.GitleaksBinDir()
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return fmt.Errorf("failed to create bin directory: %w", err)
	}

	binaryName := "gitleaks"
	if runtime.GOOS == "windows" {
		binaryName = "gitleaks.exe"
	}

	destPath := platform.GitleaksBinPath()

	// Extract based on archive type.
	assetName := strings.ToLower(targetAsset.Name)
	if strings.HasSuffix(assetName, ".tar.gz") || strings.HasSuffix(assetName, ".tgz") {
		if err := extractTarGz(archiveData, binaryName, destPath); err != nil {
			return err
		}
	} else if strings.HasSuffix(assetName, ".zip") {
		if err := extractZip(archiveData, binaryName, destPath); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("unknown archive format: %s", targetAsset.Name)
	}

	// Make executable on Unix.
	if runtime.GOOS != "windows" {
		if err := os.Chmod(destPath, 0o755); err != nil {
			return fmt.Errorf("failed to set executable permission: %w", err)
		}
	}

	return nil
}

// extractTarGz extracts the named binary from a tar.gz archive.
func extractTarGz(data []byte, binaryName, destPath string) error {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to open gzip: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar read error: %w", err)
		}
		base := filepath.Base(hdr.Name)
		if base == binaryName || base == "gitleaks" {
			f, err := os.Create(destPath)
			if err != nil {
				return fmt.Errorf("failed to create binary file: %w", err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("failed to write binary: %w", err)
			}
			f.Close()
			return nil
		}
	}
	return fmt.Errorf("gitleaks binary not found in archive")
}

// extractZip extracts the named binary from a zip archive.
func extractZip(data []byte, binaryName, destPath string) error {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("failed to open zip: %w", err)
	}
	for _, f := range r.File {
		base := filepath.Base(f.Name)
		if base == binaryName || base == "gitleaks" {
			rc, err := f.Open()
			if err != nil {
				return fmt.Errorf("failed to open zip entry: %w", err)
			}
			defer rc.Close()
			out, err := os.Create(destPath)
			if err != nil {
				return fmt.Errorf("failed to create binary file: %w", err)
			}
			if _, err := io.Copy(out, rc); err != nil {
				out.Close()
				return fmt.Errorf("failed to write binary: %w", err)
			}
			out.Close()
			return nil
		}
	}
	return fmt.Errorf("gitleaks binary not found in zip archive")
}
