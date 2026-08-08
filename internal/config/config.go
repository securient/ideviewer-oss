package config

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/securient/ideviewer-oss/internal/platform"
)

// Config holds daemon configuration, persisted as HMAC-signed JSON.
type Config struct {
	PortalURL           string `json:"portal_url"`
	CustomerKey         string `json:"customer_key"`
	HostToken           string `json:"host_token,omitempty"`
	ScanIntervalMinutes int    `json:"scan_interval_minutes"`
	HostID              string `json:"host_id,omitempty"`
	// EnforcementEnabled is the legacy local kill-switch for the enforcement
	// plane. Superseded by EnforcementMode but still honored for backward
	// compatibility with configs written before signed commands existed.
	EnforcementEnabled bool `json:"enforcement_enabled,omitempty"`
	// EnforcementMode controls how the daemon treats enforcement commands:
	//   "off"      — never poll/execute (explicit opt-out kill-switch)
	//   "verified" — execute only commands whose signature verifies against a
	//                pinned CommandPublicKeys entry (the default once signing
	//                exists; a missing/forged signature blocks execution, which
	//                is strictly safer than the old boolean flag)
	// Empty string is resolved at runtime from EnforcementEnabled for
	// backward compatibility (see daemon.resolveEnforcementMode).
	EnforcementMode string `json:"enforcement_mode,omitempty"`
	// CommandPublicKeys holds the base64 ed25519 public key(s) the daemon pins
	// to verify portal-issued command envelopes. Multiple entries support
	// key rotation. Populated at enrollment and refreshable via /api/signing-key.
	CommandPublicKeys []string `json:"command_public_keys,omitempty"`
	Signature         string   `json:"signature,omitempty"`
}

// configCandidates returns the config file paths in priority order: the
// system dir first (written by the installer for the daemon service), then
// the user dir, then the legacy Python location. Duplicates are dropped —
// on macOS and Linux ConfigDir() is already ~/.ideviewer, so the legacy entry
// collapses into the user one and only Windows yields three distinct paths.
func configCandidates() []string {
	paths := []string{
		filepath.Join(platform.SystemConfigDir(), "config.json"),
		filepath.Join(platform.ConfigDir(), "config.json"),
		filepath.Join(platform.HomeDir(), ".ideviewer", "config.json"),
	}

	seen := make(map[string]bool, len(paths))
	out := paths[:0:0]
	for _, p := range paths {
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// configPath returns the first candidate path that exists, falling back to
// the system path when none do so error messages name the canonical location.
// Note this only stats: a path it returns may still be unreadable — Load does
// not depend on it for that reason.
func configPath() string {
	candidates := configCandidates()
	for _, p := range candidates {
		if platform.PathExists(p) {
			return p
		}
	}
	return candidates[0]
}

// Load reads and validates the config from disk, trying each candidate path
// in priority order.
//
// A candidate that cannot be read is skipped rather than treated as fatal: the
// macOS .pkg installs the system config root-owned 0600 while the LaunchAgent
// runs as the logged-in user, so stat-ing that path succeeds but reading it
// returns EACCES. Failing there would mask a perfectly good user-level config
// and crash-loop the daemon with EX_CONFIG.
//
// Malformed and signature-invalid configs are NOT skipped — those are hard
// failures. Falling through on them would let anyone able to corrupt a
// high-priority config silently downgrade the daemon to a lower-priority one.
func Load() (*Config, error) {
	return loadFrom(configCandidates())
}

// loadFrom implements Load against an explicit candidate list (see Load for
// the fall-through rules). Split out so tests can supply temp paths.
func loadFrom(candidates []string) (*Config, error) {
	var readErrs []error

	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			// Unreadable (missing, permission denied, I/O error) — try the next.
			readErrs = append(readErrs, err)
			continue
		}
		cfg, err := parseAndVerify(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return cfg, nil
	}

	return nil, fmt.Errorf("no readable config found (run 'ideviewer register' first): %w",
		errors.Join(readErrs...))
}

// parseAndVerify unmarshals config JSON and checks its HMAC signature.
func parseAndVerify(data []byte) (*Config, error) {
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Verify HMAC signature
	if cfg.Signature != "" {
		sig := cfg.Signature
		cfg.Signature = ""
		expected, err := computeSignature(&cfg)
		if err != nil {
			return nil, fmt.Errorf("config verification failed: %w", err)
		}
		if !hmac.Equal([]byte(sig), []byte(expected)) {
			return nil, fmt.Errorf("config signature invalid — file may have been tampered with")
		}
		cfg.Signature = sig
	}

	return &cfg, nil
}

// Save writes the config to the user-level directory with an HMAC signature.
func Save(cfg *Config) error {
	userPath := filepath.Join(platform.ConfigDir(), "config.json")
	return saveToPath(cfg, userPath)
}

// SaveSystem writes the config to the system-level directory so the
// launchd/systemd daemon (running as root) can find it.
func SaveSystem(cfg *Config) error {
	systemPath := filepath.Join(platform.SystemConfigDir(), "config.json")
	return saveToPath(cfg, systemPath)
}

// SystemConfigPath returns the system-level config file path.
func SystemConfigPath() string {
	return filepath.Join(platform.SystemConfigDir(), "config.json")
}

func saveToPath(cfg *Config, path string) error {
	cfg.Signature = ""
	sig, err := computeSignature(cfg)
	if err != nil {
		return fmt.Errorf("failed to sign config: %w", err)
	}
	cfg.Signature = sig

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	// Ensure mode is 0600 even when the file already existed with different bits.
	if err := os.Chmod(path, 0600); err != nil {
		return err
	}

	return nil
}

// SaveToPath writes the config (with HMAC signature) to an explicit path.
// Intended for tests; production code should use Save / SaveSystem.
func SaveToPath(cfg *Config, path string) error {
	return saveToPath(cfg, path)
}

// LoadFromPath reads and HMAC-verifies a config from an explicit path.
// Intended for tests; production code should use Load.
func LoadFromPath(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config not found at %s: %w", path, err)
	}
	return parseAndVerify(data)
}

// Path returns the config file path.
func Path() string {
	return configPath()
}

// computeSignature generates an HMAC-SHA256 of the config payload.
func computeSignature(cfg *Config) (string, error) {
	key, err := signingKey()
	if err != nil {
		return "", err
	}

	// Serialize without signature field
	saved := cfg.Signature
	cfg.Signature = ""
	data, err := json.Marshal(cfg)
	cfg.Signature = saved
	if err != nil {
		return "", err
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// signingKey derives a machine-specific HMAC key.
func signingKey() ([]byte, error) {
	machineID, err := getMachineID()
	if err != nil {
		// Fallback: use hostname + a fixed salt
		host, _ := os.Hostname()
		machineID = host
	}

	// Derive key from machine ID + embedded salt
	h := sha256.New()
	h.Write([]byte("ideviewer-config-v1:"))
	h.Write([]byte(machineID))
	return h.Sum(nil), nil
}

// getMachineID returns a platform-specific machine identifier.
func getMachineID() (string, error) {
	switch runtime.GOOS {
	case "linux":
		data, err := os.ReadFile("/etc/machine-id")
		if err != nil {
			data, err = os.ReadFile("/var/lib/dbus/machine-id")
		}
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil

	case "darwin":
		out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
		if err != nil {
			return "", err
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "IOPlatformUUID") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					return strings.Trim(strings.TrimSpace(parts[1]), "\""), nil
				}
			}
		}
		return "", fmt.Errorf("IOPlatformUUID not found")

	case "windows":
		out, err := exec.Command("reg", "query",
			`HKLM\SOFTWARE\Microsoft\Cryptography`,
			"/v", "MachineGuid").Output()
		if err != nil {
			return "", err
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "MachineGuid") {
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					return fields[len(fields)-1], nil
				}
			}
		}
		return "", fmt.Errorf("MachineGuid not found in registry")

	default:
		return "", fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}
