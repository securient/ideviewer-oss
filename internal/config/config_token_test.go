package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestSaveEnforcesMode0600 verifies that a config file written via the
// package's save logic has POSIX permissions 0600. The host token is
// sensitive, so this guard prevents accidental loosening.
func TestSaveEnforcesMode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes do not apply on Windows")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cfg := &Config{
		PortalURL:           "https://example.test",
		CustomerKey:         "00000000-0000-0000-0000-000000000000",
		HostToken:           "test-token-abc123",
		ScanIntervalMinutes: 30,
	}

	if err := SaveToPath(cfg, path); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	mode := info.Mode().Perm()
	if mode != 0600 {
		t.Errorf("expected mode 0600, got %o", mode)
	}
}

// TestSaveEnforcesParentDirMode0700 verifies the parent directory is
// created with mode 0700 when it does not already exist.
func TestSaveEnforcesParentDirMode0700(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes do not apply on Windows")
	}

	tmp := t.TempDir()
	// Use a nested directory that does not exist yet so SaveToPath has
	// to create it via os.MkdirAll(dir, 0700).
	dir := filepath.Join(tmp, "ideviewer")
	path := filepath.Join(dir, "config.json")

	cfg := &Config{
		PortalURL:           "https://example.test",
		CustomerKey:         "key",
		HostToken:           "tok",
		ScanIntervalMinutes: 60,
	}
	if err := SaveToPath(cfg, path); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat parent dir: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("expected directory at %s", dir)
	}
	mode := info.Mode().Perm()
	if mode != 0700 {
		t.Errorf("expected parent dir mode 0700, got %o", mode)
	}
}

// TestHostTokenRoundTrip writes a config containing a HostToken and
// reads it back, verifying the field survives JSON marshal/unmarshal and
// HMAC verification.
func TestHostTokenRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cfg := &Config{
		PortalURL:           "https://example.test",
		CustomerKey:         "cust-key-xyz",
		HostToken:           "hosttoken-roundtrip-value-9876",
		ScanIntervalMinutes: 15,
		HostID:              "host-1",
	}

	if err := SaveToPath(cfg, path); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := LoadFromPath(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.HostToken != cfg.HostToken {
		t.Errorf("HostToken not round-tripped: got %q want %q", loaded.HostToken, cfg.HostToken)
	}
	if loaded.CustomerKey != cfg.CustomerKey {
		t.Errorf("CustomerKey not round-tripped: got %q want %q", loaded.CustomerKey, cfg.CustomerKey)
	}
	if loaded.PortalURL != cfg.PortalURL {
		t.Errorf("PortalURL not round-tripped: got %q want %q", loaded.PortalURL, cfg.PortalURL)
	}
}

// TestEmptyHostTokenIsOmitted ensures the omitempty tag keeps backwards
// compatibility: a config without a host token must not write a
// "host_token" key at all.
func TestEmptyHostTokenIsOmitted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cfg := &Config{
		PortalURL:           "https://example.test",
		CustomerKey:         "k",
		ScanIntervalMinutes: 30,
	}
	if err := SaveToPath(cfg, path); err != nil {
		t.Fatalf("save: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if contains(raw, []byte("host_token")) {
		t.Errorf("expected host_token field to be omitted when empty, got: %s", string(raw))
	}
}

func contains(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}
