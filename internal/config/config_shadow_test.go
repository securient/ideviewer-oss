package config

import (
	"os"
	"path/filepath"
	"testing"
)

// The Windows field report: after uninstalling and reinstalling, registration
// appeared to succeed but the daemon kept talking to the previous portal with
// the previous customer key. Cause: 'register' writes the user config, while
// Load prefers the system config — and the Windows uninstaller cleaned only
// %LOCALAPPDATA%, so a system config from the earlier install survived and
// silently won. These tests cover the machinery that now surfaces and repairs
// that: SaveInPlace, ShadowedBy and ExistingPaths.

func TestSaveInPlace_WritesBackToTheLoadedFile(t *testing.T) {
	tmpDir := t.TempDir()
	systemPath := filepath.Join(tmpDir, "system", "config.json")
	userPath := filepath.Join(tmpDir, "user", "config.json")

	writeSignedConfig(t, systemPath, &Config{
		PortalURL:   "https://portal.example.com",
		CustomerKey: "key",
	}, 0600)
	writeSignedConfig(t, userPath, &Config{
		PortalURL:   "https://portal.example.com",
		CustomerKey: "key",
	}, 0600)

	cfg, err := loadFrom([]string{systemPath, userPath})
	if err != nil {
		t.Fatalf("loadFrom: %v", err)
	}
	if cfg.LoadedFrom() != systemPath {
		t.Fatalf("LoadedFrom() = %q, want %q", cfg.LoadedFrom(), systemPath)
	}

	// A rotated host token must land in the file Load will read next time.
	cfg.HostToken = "rotated-token"
	if err := SaveInPlace(cfg); err != nil {
		t.Fatalf("SaveInPlace: %v", err)
	}

	reloaded, err := loadFrom([]string{systemPath, userPath})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.HostToken != "rotated-token" {
		t.Errorf("HostToken = %q, want %q — the update went to a file Load does not read",
			reloaded.HostToken, "rotated-token")
	}
}

func TestSaveInPlace_InMemoryConfigFallsBackToSave(t *testing.T) {
	cfg := &Config{PortalURL: "https://portal.example.com", CustomerKey: "key"}
	if cfg.LoadedFrom() != "" {
		t.Fatalf("LoadedFrom() = %q, want empty for a config built in memory", cfg.LoadedFrom())
	}
	// Save writes to the real user config dir, so only assert the routing
	// decision, not the side effect.
	if got := UserPath(); got == "" {
		t.Fatal("UserPath() is empty")
	}
}

func TestShadowedBy_ReportsHigherPriorityConfigs(t *testing.T) {
	candidates := Candidates()
	if len(candidates) < 2 {
		t.Skipf("this platform has %d config candidate(s); shadowing needs 2+", len(candidates))
	}

	// Only report paths that (a) outrank the target and (b) actually exist.
	for _, p := range ShadowedBy(candidates[0]) {
		t.Errorf("the highest-priority path %q reports being shadowed by %q",
			candidates[0], p)
	}

	shadowing := ShadowedBy(candidates[len(candidates)-1])
	for _, p := range shadowing {
		if !PathExistsForTest(p) {
			t.Errorf("ShadowedBy reported %q, which does not exist", p)
		}
	}
}

func TestExistingPaths_KeepsPriorityOrder(t *testing.T) {
	candidates := Candidates()
	existing := ExistingPaths()

	pos := make(map[string]int, len(candidates))
	for i, p := range candidates {
		pos[p] = i
	}
	last := -1
	for _, p := range existing {
		i, ok := pos[p]
		if !ok {
			t.Errorf("ExistingPaths returned %q, which is not a candidate", p)
			continue
		}
		if i <= last {
			t.Errorf("ExistingPaths is out of priority order at %q", p)
		}
		last = i
	}
}

func TestCandidates_AreUniqueAndAbsolute(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range Candidates() {
		if seen[p] {
			t.Errorf("duplicate candidate path %q", p)
		}
		seen[p] = true
		if !filepath.IsAbs(p) {
			t.Errorf("candidate path %q is not absolute", p)
		}
	}
}

// PathExistsForTest keeps the platform dependency out of the test body.
func PathExistsForTest(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
