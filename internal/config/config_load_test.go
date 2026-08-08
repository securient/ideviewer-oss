package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeSignedConfig writes a validly-signed config to path with the given mode.
func writeSignedConfig(t *testing.T, path string, cfg *Config, mode os.FileMode) {
	t.Helper()
	if err := SaveToPath(cfg, path); err != nil {
		t.Fatalf("SaveToPath(%s): %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("Chmod(%s): %v", path, err)
	}
}

// TestLoad_SkipsUnreadableCandidate is the regression test for the macOS
// LaunchAgent crash-loop: the .pkg installs the system config root-owned 0600
// while the daemon runs as the logged-in user, so the high-priority path stats
// fine but reads EACCES. Load must fall through to the user config.
func TestLoad_SkipsUnreadableCandidate(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode 0000 is still readable")
	}

	tmpDir := t.TempDir()
	systemPath := filepath.Join(tmpDir, "system", "config.json")
	userPath := filepath.Join(tmpDir, "user", "config.json")

	// A valid config at the system path, but unreadable by this user.
	writeSignedConfig(t, systemPath, &Config{
		PortalURL:   "https://system.example.com",
		CustomerKey: "system-key",
	}, 0000)

	writeSignedConfig(t, userPath, &Config{
		PortalURL:           "https://user.example.com",
		CustomerKey:         "user-key",
		ScanIntervalMinutes: 5,
	}, 0600)

	got, err := loadFrom([]string{systemPath, userPath})
	if err != nil {
		t.Fatalf("loadFrom: expected fall-through to the user config, got error: %v", err)
	}
	if got.CustomerKey != "user-key" {
		t.Errorf("CustomerKey = %q, want %q", got.CustomerKey, "user-key")
	}
	if got.ScanIntervalMinutes != 5 {
		t.Errorf("ScanIntervalMinutes = %d, want 5", got.ScanIntervalMinutes)
	}
}

// TestLoad_PrefersFirstReadableCandidate confirms priority order is unchanged
// when the high-priority config IS readable.
func TestLoad_PrefersFirstReadableCandidate(t *testing.T) {
	tmpDir := t.TempDir()
	systemPath := filepath.Join(tmpDir, "system", "config.json")
	userPath := filepath.Join(tmpDir, "user", "config.json")

	writeSignedConfig(t, systemPath, &Config{
		PortalURL:   "https://system.example.com",
		CustomerKey: "system-key",
	}, 0600)
	writeSignedConfig(t, userPath, &Config{
		PortalURL:   "https://user.example.com",
		CustomerKey: "user-key",
	}, 0600)

	got, err := loadFrom([]string{systemPath, userPath})
	if err != nil {
		t.Fatalf("loadFrom: %v", err)
	}
	if got.CustomerKey != "system-key" {
		t.Errorf("CustomerKey = %q, want %q (priority order broken)", got.CustomerKey, "system-key")
	}
}

// TestLoad_SkipsMissingCandidates covers the ordinary case where higher-priority
// paths simply don't exist.
func TestLoad_SkipsMissingCandidates(t *testing.T) {
	tmpDir := t.TempDir()
	missing := filepath.Join(tmpDir, "nope", "config.json")
	userPath := filepath.Join(tmpDir, "user", "config.json")

	writeSignedConfig(t, userPath, &Config{
		PortalURL:   "https://user.example.com",
		CustomerKey: "user-key",
	}, 0600)

	got, err := loadFrom([]string{missing, userPath})
	if err != nil {
		t.Fatalf("loadFrom: %v", err)
	}
	if got.CustomerKey != "user-key" {
		t.Errorf("CustomerKey = %q, want %q", got.CustomerKey, "user-key")
	}
}

// TestLoad_TamperedConfigDoesNotFallThrough is the security half of the fix: a
// readable-but-tampered high-priority config must be a hard failure, never a
// silent downgrade to a lower-priority (more writable) config.
func TestLoad_TamperedConfigDoesNotFallThrough(t *testing.T) {
	tmpDir := t.TempDir()
	systemPath := filepath.Join(tmpDir, "system", "config.json")
	userPath := filepath.Join(tmpDir, "user", "config.json")

	writeSignedConfig(t, systemPath, &Config{
		PortalURL:   "https://system.example.com",
		CustomerKey: "system-key",
	}, 0600)

	// Tamper: change a field but keep the now-stale signature.
	var tampered Config
	data, err := os.ReadFile(systemPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if err := json.Unmarshal(data, &tampered); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	tampered.CustomerKey = "attacker-key"
	tamperedData, err := json.MarshalIndent(&tampered, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	if err := os.WriteFile(systemPath, tamperedData, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	writeSignedConfig(t, userPath, &Config{
		PortalURL:   "https://user.example.com",
		CustomerKey: "user-key",
	}, 0600)

	got, err := loadFrom([]string{systemPath, userPath})
	if err == nil {
		t.Fatalf("expected a hard failure on the tampered config, got config with key %q", got.CustomerKey)
	}
	if !strings.Contains(err.Error(), "signature invalid") {
		t.Errorf("error = %v, want a signature-invalid failure", err)
	}
	if strings.Contains(err.Error(), "no readable config") {
		t.Error("tampered config fell through to the next candidate instead of failing hard")
	}
}

// TestLoad_MalformedConfigDoesNotFallThrough is the same rule for unparseable
// JSON at a readable high-priority path.
func TestLoad_MalformedConfigDoesNotFallThrough(t *testing.T) {
	tmpDir := t.TempDir()
	systemPath := filepath.Join(tmpDir, "system", "config.json")
	userPath := filepath.Join(tmpDir, "user", "config.json")

	if err := os.MkdirAll(filepath.Dir(systemPath), 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(systemPath, []byte("{not json"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	writeSignedConfig(t, userPath, &Config{
		PortalURL:   "https://user.example.com",
		CustomerKey: "user-key",
	}, 0600)

	if _, err := loadFrom([]string{systemPath, userPath}); err == nil {
		t.Fatal("expected a hard failure on malformed config, got nil")
	} else if !strings.Contains(err.Error(), "invalid config") {
		t.Errorf("error = %v, want an invalid-config failure", err)
	}
}

// TestLoad_AllCandidatesUnreadable checks the aggregate error names every path
// it tried and stays matchable with errors.Is.
func TestLoad_AllCandidatesUnreadable(t *testing.T) {
	tmpDir := t.TempDir()
	a := filepath.Join(tmpDir, "a", "config.json")
	b := filepath.Join(tmpDir, "b", "config.json")

	_, err := loadFrom([]string{a, b})
	if err == nil {
		t.Fatal("expected an error when no candidate is readable, got nil")
	}
	for _, p := range []string{a, b} {
		if !strings.Contains(err.Error(), p) {
			t.Errorf("error %v does not name attempted path %s", err, p)
		}
	}
	if !strings.Contains(err.Error(), "ideviewer register") {
		t.Errorf("error %v lost the actionable 'run ideviewer register' hint", err)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("errors.Is(err, os.ErrNotExist) = false; joined read errors should stay matchable")
	}
}

// TestConfigCandidates_NoDuplicates guards the dedupe: on macOS and Linux the
// legacy path is identical to ConfigDir(), which otherwise surfaces as a
// repeated line in Load's aggregate error.
func TestConfigCandidates_NoDuplicates(t *testing.T) {
	candidates := configCandidates()
	if len(candidates) == 0 {
		t.Fatal("configCandidates() returned nothing")
	}

	seen := make(map[string]bool, len(candidates))
	for _, p := range candidates {
		if seen[p] {
			t.Errorf("duplicate candidate path %s in %v", p, candidates)
		}
		seen[p] = true
	}

	// The system path must stay highest priority.
	if candidates[0] != SystemConfigPath() {
		t.Errorf("candidates[0] = %s, want the system path %s", candidates[0], SystemConfigPath())
	}
}
