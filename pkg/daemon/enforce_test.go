package daemon

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/securient/ideviewer-oss/internal/config"
	"github.com/securient/ideviewer-oss/pkg/api"
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

func TestEnforcementModeOffIsNoOp(t *testing.T) {
	// Mode "off" must skip polling entirely. We point the client at a server
	// that fails the test if it is ever called.
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := &Daemon{
		config:     &config.Config{EnforcementMode: "off"},
		apiClient:  api.NewClientWithToken(srv.URL, "cust", "tok"),
		nonceCache: api.NewNonceCache(),
	}
	d.checkEnforcementActions()
	if called {
		t.Error("mode=off must not poll the portal")
	}
}

func TestCheckEnforcementActions_NilClientIsSafe(t *testing.T) {
	d := &Daemon{config: &config.Config{EnforcementMode: "verified"}}
	d.checkEnforcementActions() // must not panic with a nil apiClient
}

// signEnvelope builds a signed command envelope the way the portal does.
func signEnvelope(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey, actions []map[string]any) map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"actions": actions})
	bodyB64 := base64.StdEncoding.EncodeToString(body)
	issued := time.Now().Unix()
	nonce := "nonce-" + t.Name()
	sig := ed25519.Sign(priv, fmt.Appendf(nil, "%d.%s.%s", issued, nonce, bodyB64))
	return map[string]any{
		"actions": actions,
		"sig": map[string]any{
			"key_id":        api.CommandKeyID(pub),
			"alg":           "ed25519",
			"issued_at":     issued,
			"nonce":         nonce,
			"body_b64":      bodyB64,
			"signature_b64": base64.StdEncoding.EncodeToString(sig),
		},
	}
}

// enforceServer stands in for the portal: it serves a (caller-built) envelope
// at the pending endpoint and records the reported status.
func enforceServer(t *testing.T, envelope map[string]any, reported *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/enforcement-actions/pending"):
			_ = json.NewEncoder(w).Encode(envelope)
		case strings.Contains(r.URL.Path, "/enforcement-actions/") && strings.HasSuffix(r.URL.Path, "/report"):
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if s, ok := body["status"].(string); ok {
				*reported = s
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{})
		}
	}))
}

func TestCheckEnforcementActions_VerifiedExecutes(t *testing.T) {
	d, _, extPath := newEnforceFixture(t, false)
	pub, priv, _ := ed25519.GenerateKey(nil)

	envelope := signEnvelope(t, priv, pub, []map[string]any{
		{"id": 7, "action": "quarantine", "extension_id": "evil.ext", "ide_type": "vscode"},
	})
	var reported string
	srv := enforceServer(t, envelope, &reported)
	defer srv.Close()

	d.config.EnforcementMode = "verified"
	d.config.CommandPublicKeys = []string{base64.StdEncoding.EncodeToString(pub)}
	d.apiClient = api.NewClientWithToken(srv.URL, "cust", "tok")
	d.nonceCache = api.NewNonceCache()

	d.checkEnforcementActions()

	if _, err := os.Stat(extPath); !os.IsNotExist(err) {
		t.Errorf("verified command should have quarantined the extension")
	}
	if reported != "applied" {
		t.Errorf("reported status = %q, want applied", reported)
	}
}

func TestCheckEnforcementActions_ForgedRejected(t *testing.T) {
	d, _, extPath := newEnforceFixture(t, false)
	pub, priv, _ := ed25519.GenerateKey(nil)

	envelope := signEnvelope(t, priv, pub, []map[string]any{
		{"id": 7, "action": "quarantine", "extension_id": "evil.ext", "ide_type": "vscode"},
	})
	var reported string
	srv := enforceServer(t, envelope, &reported)
	defer srv.Close()

	d.config.EnforcementMode = "verified"
	// Pin a DIFFERENT key than the one that signed the command.
	otherPub, _, _ := ed25519.GenerateKey(nil)
	d.config.CommandPublicKeys = []string{base64.StdEncoding.EncodeToString(otherPub)}
	d.apiClient = api.NewClientWithToken(srv.URL, "cust", "tok")
	d.nonceCache = api.NewNonceCache()

	d.checkEnforcementActions()

	if _, err := os.Stat(extPath); err != nil {
		t.Errorf("forged/unverifiable command must NOT move the extension: %v", err)
	}
	if reported == "applied" {
		t.Error("an unverified command must never be reported as applied")
	}
}
