// Package updater checks for and installs IDEViewer updates from GitHub releases.
package updater

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/securient/ideviewer-oss/internal/version"
)

const githubAPIURL = "https://api.github.com/repos/securient/ideviewer-oss/releases/latest"

// UpdateInfo holds the result of an update check.
type UpdateInfo struct {
	CurrentVersion  string `json:"current_version"`
	LatestVersion   string `json:"latest_version"`
	UpdateAvailable bool   `json:"update_available"`
	DownloadURL     string `json:"download_url"`
	AssetName       string `json:"asset_name"`
}

// githubRelease is the subset of the GitHub release API we need.
type githubRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// CheckForUpdate queries GitHub for the latest release and compares versions.
func CheckForUpdate() (*UpdateInfo, error) {
	current := version.Version

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", githubAPIURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "IDEViewer-Updater")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to check for updates: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("failed to parse release info: %w", err)
	}

	latest := strings.TrimPrefix(release.TagName, "v")

	// Find the platform asset.
	prefix, suffix := platformAssetPattern()
	var downloadURL, assetName string
	for _, asset := range release.Assets {
		if strings.HasPrefix(asset.Name, prefix) && strings.HasSuffix(asset.Name, suffix) {
			downloadURL = asset.BrowserDownloadURL
			assetName = asset.Name
			break
		}
	}

	info := &UpdateInfo{
		CurrentVersion:  current,
		LatestVersion:   latest,
		UpdateAvailable: compareVersions(latest, current) > 0,
		DownloadURL:     downloadURL,
		AssetName:       assetName,
	}

	return info, nil
}

// DownloadAndInstall downloads the release asset and runs the platform installer.
func DownloadAndInstall(info *UpdateInfo) error {
	if info.DownloadURL == "" {
		return fmt.Errorf("no download URL for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	// Download to a temp directory.
	tmpDir, err := os.MkdirTemp("", "ideviewer-update-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	destPath := filepath.Join(tmpDir, info.AssetName)

	client := &http.Client{Timeout: 120 * time.Second}
	req, err := http.NewRequest("GET", info.DownloadURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "IDEViewer-Updater")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download update: %w", err)
	}
	defer resp.Body.Close()

	f, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return fmt.Errorf("failed to write update file: %w", err)
	}
	f.Close()

	return installUpdate(destPath)
}

// platformAssetPattern returns the (prefix, suffix) for matching release assets.
func platformAssetPattern() (string, string) {
	switch runtime.GOOS {
	case "darwin":
		return "IDEViewer-", ".pkg"
	case "windows":
		return "IDEViewer-Setup-", ".exe"
	case "linux":
		if runtime.GOARCH == "arm64" {
			return "ideviewer_", "_arm64.deb"
		}
		return "ideviewer_", "_amd64.deb"
	default:
		return "ideviewer_", "_amd64.deb"
	}
}

// installUpdate runs the platform-specific installer.
func installUpdate(filePath string) error {
	switch runtime.GOOS {
	case "darwin":
		// Remove quarantine attribute.
		_ = exec.Command("xattr", "-rd", "com.apple.quarantine", filePath).Run()
		cmd := exec.Command("sudo", "installer", "-pkg", filePath, "-target", "/")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("macOS installer failed: %w", err)
		}
		return nil

	case "linux":
		cmd := exec.Command("sudo", "dpkg", "-i", filePath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("dpkg install failed: %w", err)
		}
		return nil

	case "windows":
		cmd := exec.Command(filePath, "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("Windows installer failed: %w", err)
		}
		return nil

	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// parseVersion converts a version string like "0.2.1" into a slice of ints.
func parseVersion(v string) []int {
	v = strings.TrimPrefix(v, "v")
	parts := strings.Split(v, ".")
	nums := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			n = 0
		}
		nums[i] = n
	}
	return nums
}

// compareVersions returns >0 if a > b, <0 if a < b, 0 if equal.
func compareVersions(a, b string) int {
	av := parseVersion(a)
	bv := parseVersion(b)

	// Pad to same length.
	for len(av) < len(bv) {
		av = append(av, 0)
	}
	for len(bv) < len(av) {
		bv = append(bv, 0)
	}

	for i := range av {
		if av[i] > bv[i] {
			return 1
		}
		if av[i] < bv[i] {
			return -1
		}
	}
	return 0
}
