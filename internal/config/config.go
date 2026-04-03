package config

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	ScanIntervalMinutes int    `json:"scan_interval_minutes"`
	HostID              string `json:"host_id,omitempty"`
	Signature           string `json:"signature,omitempty"`
}

// configPath returns the config file path, checking system dir first
// (for launchd/systemd which run as root), then user dir.
func configPath() string {
	// System-level config (written during registration for the daemon service)
	systemPath := filepath.Join(platform.SystemConfigDir(), "config.json")
	if platform.PathExists(systemPath) {
		return systemPath
	}
	// User-level config
	userPath := filepath.Join(platform.ConfigDir(), "config.json")
	if platform.PathExists(userPath) {
		return userPath
	}
	// Legacy Python location
	legacyPath := filepath.Join(platform.HomeDir(), ".ideviewer", "config.json")
	if platform.PathExists(legacyPath) {
		return legacyPath
	}
	return systemPath
}

// Load reads and validates the config from disk.
func Load() (*Config, error) {
	path := configPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config not found at %s: %w (run 'ideviewer register' first)", path, err)
	}

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

	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}

	return nil
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
