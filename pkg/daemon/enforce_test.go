package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securient/ideviewer-oss/internal/config"
	"github.com/securient/ideviewer-oss/pkg/scanner"
)

// newEnforceFixture builds a daemon whose latest scan contains one extension
// installed under a temp "extensions" dir, with HOME pointed at a temp dir so
// the quarantine area is sandboxed. Returns the daemon, the extensions dir,
// and the extension's install path.
func newEnforceFixture(t *testing.T, builtin bool) (*Daemon, string, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)

	extsDir := filepath.Join(t.TempDir(), "extensions")
	extPath := filepath.Join(extsDir, "evil.ext-1.0.0")
	if err := os.MkdirAll(extPath, 0o755); err != nil {
		t.Fatalf("mkdir ext: %v", err)
	}
	if err := os.WriteFile(filepath.Join(extPath, "extension.js"), []byte("// payload"), 0o644); err != nil {
		t.Fatalf("write ext file: %v", err)
	}

	d := &Daemon{config: &config.Config{EnforcementEnabled: true}}
	d.setResult(&scanner.ScanResult{
		IDEs: []scanner.IDE{{
			IDEType:        scanner.IDETypeVSCode,
			Name:           "VS Code",
			ExtensionsPath: extsDir,
			Extensions: []scanner.Extension{{
				ID:          "evil.ext",
				Name:        "Evil Extension",
				Version:     "1.0.0",
				InstallPath: extPath,
				Builtin:     builtin,
			}},
		}},
	})
	return d, extsDir, extPath
}

func TestQuarantineThenRestore(t *testing.T) {
	d, _, extPath := newEnforceFixture(t, false)

	status, detail, orig, quar := d.applyQuarantine("evil.ext", "vscode")
	if status != "applied" {
		t.Fatalf("quarantine status = %q (%s), want applied", status, detail)
	}
	if _, err := os.Stat(extPath); !os.IsNotExist(err) {
		t.Errorf("extension still present at original path after quarantine")
	}
	if _, err := os.Stat(filepath.Join(quar, "evil.ext-1.0.0")); err != nil {
		t.Errorf("moved extension not found in quarantine slot: %v", err)
	}
	if _, err := os.Stat(filepath.Join(quar, "manifest.json")); err != nil {
		t.Errorf("manifest not written: %v", err)
	}
	if orig != extPath {
		t.Errorf("reported original_path = %q, want %q", orig, extPath)
	}

	// Restore puts it back.
	status, detail = d.applyRestore(orig, quar)
	if status != "reverted" {
		t.Fatalf("restore status = %q (%s), want reverted", status, detail)
	}
	if _, err := os.Stat(extPath); err != nil {
		t.Errorf("extension not restored to original path: %v", err)
	}
	if _, err := os.Stat(quar); !os.IsNotExist(err) {
		t.Errorf("quarantine slot not cleaned up after restore")
	}
}

func TestQuarantineRefusesBuiltin(t *testing.T) {
	d, _, extPath := newEnforceFixture(t, true)
	status, _, _, _ := d.applyQuarantine("evil.ext", "vscode")
	if status != "failed" {
		t.Errorf("status = %q, want failed for builtin extension", status)
	}
	if _, err := os.Stat(extPath); err != nil {
		t.Errorf("builtin extension must not be moved: %v", err)
	}
}

func TestQuarantineRefusesOutOfTreePath(t *testing.T) {
	d, _, _ := newEnforceFixture(t, false)
	// Point the extension's install path somewhere outside the IDE's
	// extensions dir; the safety check must refuse it.
	outside := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	res := d.snapshotResult()
	res.IDEs[0].Extensions[0].InstallPath = outside
	d.setResult(res)

	status, detail, _, _ := d.applyQuarantine("evil.ext", "vscode")
	if status != "failed" {
		t.Errorf("status = %q (%s), want failed for out-of-tree path", status, detail)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Errorf("out-of-tree path must not be moved: %v", err)
	}
}

func TestQuarantineUnknownExtension(t *testing.T) {
	d, _, _ := newEnforceFixture(t, false)
	status, _, _, _ := d.applyQuarantine("does.not-exist", "vscode")
	if status != "failed" {
		t.Errorf("status = %q, want failed for unknown extension", status)
	}
}

func TestKillSwitchDisabledIsNoOp(t *testing.T) {
	// EnforcementEnabled=false and a nil API client: must return without
	// panicking and without touching the network.
	d := &Daemon{config: &config.Config{EnforcementEnabled: false}}
	d.checkEnforcementActions()
}
