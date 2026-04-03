package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveAndLoad_RoundTrip(t *testing.T) {
	// Use a temp directory so we don't touch the real config.
	tmpDir := t.TempDir()
	tmpConfigPath := filepath.Join(tmpDir, "config.json")

	cfg := &Config{
		PortalURL:           "https://portal.example.com",
		CustomerKey:         "test-key-12345",
		ScanIntervalMinutes: 30,
		HostID:              "host-abc",
	}

	// Sign and write directly to temp path (bypass configPath()).
	cfg.Signature = ""
	sig, err := computeSignature(cfg)
	if err != nil {
		t.Fatalf("computeSignature: %v", err)
	}
	cfg.Signature = sig

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	if err := os.WriteFile(tmpConfigPath, data, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Read back and verify.
	readData, err := os.ReadFile(tmpConfigPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var loaded Config
	if err := json.Unmarshal(readData, &loaded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	// Verify HMAC.
	savedSig := loaded.Signature
	loaded.Signature = ""
	expectedSig, err := computeSignature(&loaded)
	if err != nil {
		t.Fatalf("computeSignature on loaded: %v", err)
	}
	if savedSig != expectedSig {
		t.Errorf("signature mismatch: got %q, want %q", savedSig, expectedSig)
	}

	// Verify fields.
	if loaded.PortalURL != cfg.PortalURL {
		t.Errorf("PortalURL = %q, want %q", loaded.PortalURL, cfg.PortalURL)
	}
	if loaded.CustomerKey != cfg.CustomerKey {
		t.Errorf("CustomerKey = %q, want %q", loaded.CustomerKey, cfg.CustomerKey)
	}
	if loaded.ScanIntervalMinutes != cfg.ScanIntervalMinutes {
		t.Errorf("ScanIntervalMinutes = %d, want %d", loaded.ScanIntervalMinutes, cfg.ScanIntervalMinutes)
	}
	if loaded.HostID != cfg.HostID {
		t.Errorf("HostID = %q, want %q", loaded.HostID, cfg.HostID)
	}
}

func TestHMACSignatureVerification(t *testing.T) {
	cfg := &Config{
		PortalURL:           "https://portal.example.com",
		CustomerKey:         "key-123",
		ScanIntervalMinutes: 15,
	}

	cfg.Signature = ""
	sig1, err := computeSignature(cfg)
	if err != nil {
		t.Fatalf("computeSignature: %v", err)
	}

	// Compute again; should be deterministic.
	sig2, err := computeSignature(cfg)
	if err != nil {
		t.Fatalf("computeSignature: %v", err)
	}

	if sig1 != sig2 {
		t.Errorf("signatures not deterministic: %q != %q", sig1, sig2)
	}

	if sig1 == "" {
		t.Error("signature should not be empty")
	}
}

func TestTamperedConfigIsRejected(t *testing.T) {
	cfg := &Config{
		PortalURL:           "https://portal.example.com",
		CustomerKey:         "key-123",
		ScanIntervalMinutes: 15,
	}

	// Compute valid signature.
	cfg.Signature = ""
	sig, err := computeSignature(cfg)
	if err != nil {
		t.Fatalf("computeSignature: %v", err)
	}
	cfg.Signature = sig

	// Write to temp file.
	tmpDir := t.TempDir()
	tmpConfigPath := filepath.Join(tmpDir, "config.json")

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	if err := os.WriteFile(tmpConfigPath, data, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Tamper: modify the customer key but keep the old signature.
	var tampered Config
	readData, _ := os.ReadFile(tmpConfigPath)
	json.Unmarshal(readData, &tampered)
	tampered.CustomerKey = "tampered-key"
	// Keep the old signature.

	tamperedData, _ := json.MarshalIndent(tampered, "", "  ")
	os.WriteFile(tmpConfigPath, tamperedData, 0600)

	// Verify that the signature no longer matches.
	readData2, _ := os.ReadFile(tmpConfigPath)
	var loaded Config
	json.Unmarshal(readData2, &loaded)

	loadedSig := loaded.Signature
	loaded.Signature = ""
	expectedSig, err := computeSignature(&loaded)
	if err != nil {
		t.Fatalf("computeSignature: %v", err)
	}

	if loadedSig == expectedSig {
		t.Error("tampered config should have invalid signature, but it matched")
	}
}

func TestSigningKey_Deterministic(t *testing.T) {
	key1, err := signingKey()
	if err != nil {
		t.Fatalf("signingKey: %v", err)
	}
	key2, err := signingKey()
	if err != nil {
		t.Fatalf("signingKey: %v", err)
	}

	if len(key1) == 0 {
		t.Error("signing key should not be empty")
	}
	if string(key1) != string(key2) {
		t.Error("signing key should be deterministic")
	}
}
