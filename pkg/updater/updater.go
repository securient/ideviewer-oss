// Package updater checks for and installs IDEViewer updates from GitHub releases.
package updater

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

// updatePublicKeyB64 is the base64-encoded ed25519 public key (32 bytes)
// that release artifacts are signed with. It is compiled into the binary so
// an attacker who can MITM the download or tamper with a release asset cannot
// get a malicious installer to run.
//
// SETUP (one-time, by the maintainer):
//
//	# generate a keypair (keep the private key offline / in CI secrets)
//	openssl genpkey -algorithm ed25519 -out ideviewer-update.key
//	openssl pkey -in ideviewer-update.key -pubout -outform DER | tail -c 32 | base64
//	# paste the output below, then sign each release artifact:
//	#   openssl pkeyutl -sign -inkey ideviewer-update.key -rawin -in <asset> -out <asset>.sig
//	#   base64 -w0 <asset>.sig > <asset>.sig.b64   # upload <asset>.sig.b64 as "<asset>.sig"
//
// Until this is populated, auto-update fails closed (refuses to install).
const updatePublicKeyB64 = ""

// ErrUpdateUnverified means the downloaded artifact could not be
// cryptographically verified against the pinned signing key.
var errUpdateUnverified = fmt.Errorf("update signature verification failed")

// UpdateInfo holds the result of an update check.
type UpdateInfo struct {
	CurrentVersion  string `json:"current_version"`
	LatestVersion   string `json:"latest_version"`
	UpdateAvailable bool   `json:"update_available"`
	DownloadURL     string `json:"download_url"`
	AssetName       string `json:"asset_name"`
	SignatureURL    string `json:"signature_url"`
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

	// Find the matching detached signature ("<asset>.sig").
	var signatureURL string
	if assetName != "" {
		want := assetName + ".sig"
		for _, asset := range release.Assets {
			if asset.Name == want {
				signatureURL = asset.BrowserDownloadURL
				break
			}
		}
	}

	info := &UpdateInfo{
		CurrentVersion:  current,
		LatestVersion:   latest,
		UpdateAvailable: compareVersions(latest, current) > 0,
		DownloadURL:     downloadURL,
		AssetName:       assetName,
		SignatureURL:    signatureURL,
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

	// Verify the artifact against the pinned signing key BEFORE running any
	// installer. This is the line of defense against a MITM'd download or a
	// tampered release asset being executed with elevated privileges.
	if err := verifyArtifact(destPath, info.SignatureURL); err != nil {
		return err
	}

	return installUpdate(destPath)
}

// verifyArtifact verifies the downloaded file against the pinned ed25519
// public key using the detached signature at signatureURL. It fails closed:
// a missing pinned key, missing signature, or any mismatch aborts the update.
func verifyArtifact(filePath, signatureURL string) error {
	pubB64 := strings.TrimSpace(updatePublicKeyB64)
	if pubB64 == "" {
		return fmt.Errorf("%w: no signing key is pinned in this build; "+
			"auto-update is disabled until releases are signed (see pkg/updater)", errUpdateUnverified)
	}
	pubBytes, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: pinned public key is malformed", errUpdateUnverified)
	}

	if signatureURL == "" {
		return fmt.Errorf("%w: release has no detached signature (.sig) asset", errUpdateUnverified)
	}

	sig, err := fetchSignature(signatureURL)
	if err != nil {
		return fmt.Errorf("%w: %v", errUpdateUnverified, err)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("%w: cannot read downloaded artifact: %v", errUpdateUnverified, err)
	}

	if !ed25519.Verify(ed25519.PublicKey(pubBytes), data, sig) {
		return fmt.Errorf("%w: signature does not match the pinned key", errUpdateUnverified)
	}

	sum := sha256.Sum256(data)
	fmt.Printf("  Verified update signature (sha256 %s)\n", hex.EncodeToString(sum[:]))
	return nil
}

// fetchSignature downloads a detached signature asset. The asset is expected
// to contain a base64-encoded 64-byte ed25519 signature over the artifact
// bytes (optionally with surrounding whitespace).
func fetchSignature(signatureURL string) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", signatureURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "IDEViewer-Updater")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download signature: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signature download returned %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("signature is not valid base64: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("signature has wrong length (%d)", len(sig))
	}
	return sig, nil
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
		// NOTE: we intentionally do NOT strip the com.apple.quarantine
		// attribute. Gatekeeper should still evaluate the signed .pkg;
		// the artifact has already been verified against the pinned key.
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
