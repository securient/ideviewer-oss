package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/securient/ideviewer-oss/internal/config"
	"github.com/securient/ideviewer-oss/internal/platform"
	"github.com/securient/ideviewer-oss/pkg/api"
	"github.com/securient/ideviewer-oss/pkg/scanner"
)

// quarantineManifest records what was moved so a restore can put it back even
// if the portal lost track of the original path.
type quarantineManifest struct {
	ExtensionID   string `json:"extension_id"`
	IDEType       string `json:"ide_type"`
	OriginalPath  string `json:"original_path"`
	QuarantinedAt string `json:"quarantined_at"`
}

// Enforcement modes (see config.Config.EnforcementMode).
const (
	enforcementOff      = "off"
	enforcementVerified = "verified"
)

// resolveEnforcementMode maps config (including the legacy EnforcementEnabled
// boolean) to an effective mode. Default is "verified": the daemon executes
// only commands whose signature verifies against a pinned key. There is no
// "execute unsigned" mode — a missing/forged signature always blocks execution,
// which is strictly safer than the old boolean kill-switch.
func (d *Daemon) resolveEnforcementMode() string {
	switch strings.ToLower(strings.TrimSpace(d.config.EnforcementMode)) {
	case enforcementOff:
		return enforcementOff
	case enforcementVerified:
		return enforcementVerified
	}
	// Mode unset (older config): default to verified. An unset legacy
	// EnforcementEnabled=false host stays effectively off in practice until it
	// has both a pinned key and validly-signed commands to act on.
	return enforcementVerified
}

// checkEnforcementActions polls the portal for the signed command envelope and
// executes the actions inside it — but ONLY after verifying the envelope's
// ed25519 signature against a pinned key. Mode "off" is an explicit opt-out
// that skips polling entirely.
func (d *Daemon) checkEnforcementActions() {
	if d.config == nil || d.apiClient == nil {
		return
	}
	if d.resolveEnforcementMode() == enforcementOff {
		return
	}
	// Self-heal: a daemon enrolled before signing existed has no pinned key.
	// Fetch it once so enforcement can become active without a re-register.
	d.ensureCommandKey()

	var envelope map[string]any
	err := d.withReauth(func() error {
		var callErr error
		envelope, callErr = d.apiClient.GetPendingEnforcementActions()
		return callErr
	})
	if err != nil {
		log.Printf("Error checking enforcement actions: %v", err)
		return
	}
	if envelope == nil {
		return
	}

	// Verify before acting on anything. If verification fails while the portal
	// did hand out actions, surface it as a tamper signal (could be a spoofed
	// portal, a key mismatch, or an unconfigured host).
	body, verr := api.VerifyEnvelope(envelope, d.config.CommandPublicKeys, time.Now(), d.nonceCache)
	if verr != nil {
		if envelopeHasActions(envelope) {
			log.Printf("Refusing unverified enforcement command: %v", verr)
			_ = d.withReauth(func() error {
				_, e := d.apiClient.SendTamperAlert("command_unverified",
					fmt.Sprintf("enforcement command failed signature verification: %v", verr))
				return e
			})
		}
		return
	}

	actions, perr := api.ParseEnforcementActions(body)
	if perr != nil {
		log.Printf("Error parsing enforcement command body: %v", perr)
		return
	}
	for _, act := range actions {
		d.executeEnforcementAction(act)
	}
}

// ensureCommandKey lazily pins the portal's command-signing key when the config
// has none (e.g. a daemon that enrolled before signing existed). Best-effort:
// if the fetch fails, verification simply keeps failing and no action runs.
func (d *Daemon) ensureCommandKey() {
	if d.config == nil || len(d.config.CommandPublicKeys) > 0 || d.apiClient == nil {
		return
	}
	var pub string
	err := d.withReauth(func() error {
		var e error
		_, pub, e = d.apiClient.GetSigningKey()
		return e
	})
	if err != nil || pub == "" {
		return
	}
	d.config.CommandPublicKeys = []string{pub}
	if saveErr := config.Save(d.config); saveErr != nil {
		log.Printf("warn: could not persist command signing key: %v", saveErr)
	}
}

// envelopeHasActions reports whether the (unverified) envelope claims any
// actions, used only to decide whether a verification failure is worth alarming
// on (vs. a routine empty poll from a host with no pinned key yet).
func envelopeHasActions(env map[string]any) bool {
	if acts, ok := env["actions"].([]any); ok {
		return len(acts) > 0
	}
	return false
}

func (d *Daemon) executeEnforcementAction(act map[string]any) {
	idFloat, ok := act["id"].(float64)
	if !ok {
		return
	}
	actionID := int(idFloat)
	actionType, _ := act["action"].(string)
	extID, _ := act["extension_id"].(string)
	ideType, _ := act["ide_type"].(string)
	origPath, _ := act["original_path"].(string)
	quarPath, _ := act["quarantine_path"].(string)

	var status, detail, resOrig, resQuar string
	switch actionType {
	case "quarantine":
		status, detail, resOrig, resQuar = d.applyQuarantine(extID, ideType)
	case "restore":
		status, detail = d.applyRestore(origPath, quarPath)
	default:
		status, detail = "failed", "unknown action type: "+actionType
	}

	params := map[string]any{"status": status, "result_detail": detail}
	if resOrig != "" {
		params["original_path"] = resOrig
	}
	if resQuar != "" {
		params["quarantine_path"] = resQuar
	}
	if err := d.withReauth(func() error {
		_, e := d.apiClient.ReportEnforcementResult(actionID, params)
		return e
	}); err != nil {
		log.Printf("Failed to report enforcement action #%d: %v", actionID, err)
	}
	log.Printf("Enforcement #%d (%s %s): %s — %s", actionID, actionType, extID, status, detail)
}

// applyQuarantine moves the extension's install dir into the quarantine area.
// Returns (status, detail, originalPath, quarantinePath).
func (d *Daemon) applyQuarantine(extID, ideType string) (string, string, string, string) {
	ext, ide, found := d.resolveExtension(ideType, extID)
	if !found {
		return "failed", fmt.Sprintf("extension %q not found in latest scan", extID), "", ""
	}
	if err := validateQuarantineTarget(ext, ide); err != nil {
		return "failed", err.Error(), "", ""
	}

	qroot := platform.QuarantineDir()
	if err := os.MkdirAll(qroot, 0o700); err != nil {
		return "failed", "cannot create quarantine dir: " + err.Error(), "", ""
	}
	slot := filepath.Join(qroot, fmt.Sprintf("%s-%s-%d",
		sanitizeName(string(ide.IDEType)), sanitizeName(extID), time.Now().Unix()))
	if err := os.MkdirAll(slot, 0o700); err != nil {
		return "failed", "cannot create quarantine slot: " + err.Error(), "", ""
	}

	dest := filepath.Join(slot, filepath.Base(ext.InstallPath))
	if err := moveDir(ext.InstallPath, dest); err != nil {
		_ = os.RemoveAll(slot)
		return "failed", "move failed: " + err.Error(), "", ""
	}
	// Best-effort manifest; restore can also fall back to the portal's record.
	_ = writeManifest(filepath.Join(slot, "manifest.json"), quarantineManifest{
		ExtensionID:   extID,
		IDEType:       string(ide.IDEType),
		OriginalPath:  ext.InstallPath,
		QuarantinedAt: time.Now().UTC().Format(time.RFC3339),
	})
	return "applied", fmt.Sprintf("quarantined %s", extID), ext.InstallPath, slot
}

// applyRestore moves a quarantined extension back to its original location.
func (d *Daemon) applyRestore(origPath, quarPath string) (string, string) {
	if quarPath == "" {
		return "failed", "no quarantine path recorded for restore"
	}
	if m, err := readManifest(filepath.Join(quarPath, "manifest.json")); err == nil && m.OriginalPath != "" {
		origPath = m.OriginalPath // manifest is authoritative
	}
	if origPath == "" {
		return "failed", "no original path recorded for restore"
	}

	src := filepath.Join(quarPath, filepath.Base(origPath))
	if _, err := os.Stat(src); err != nil {
		return "failed", "quarantined extension not found at " + src
	}
	if _, err := os.Stat(origPath); err == nil {
		return "failed", "original path already occupied: " + origPath
	}
	if err := os.MkdirAll(filepath.Dir(origPath), 0o755); err != nil {
		return "failed", "cannot create parent dir: " + err.Error()
	}
	if err := moveDir(src, origPath); err != nil {
		return "failed", "restore move failed: " + err.Error()
	}
	_ = os.RemoveAll(quarPath) // clean up the now-empty slot
	return "reverted", "restored " + origPath
}

// resolveExtension finds the extension locally from the latest scan. When
// ideType is empty (e.g. a manual quarantine), it matches across all IDEs.
func (d *Daemon) resolveExtension(ideType, extID string) (scanner.Extension, scanner.IDE, bool) {
	res := d.snapshotResult()
	if res == nil {
		return scanner.Extension{}, scanner.IDE{}, false
	}
	for _, ide := range res.IDEs {
		if ideType != "" && string(ide.IDEType) != ideType {
			continue
		}
		for _, ext := range ide.Extensions {
			if ext.ID == extID {
				return ext, ide, true
			}
		}
	}
	return scanner.Extension{}, scanner.IDE{}, false
}

// validateQuarantineTarget enforces the safety invariants: never touch a
// builtin extension, and only ever move a path that resolves to somewhere
// strictly under the owning IDE's extensions directory.
func validateQuarantineTarget(ext scanner.Extension, ide scanner.IDE) error {
	if ext.Builtin {
		return fmt.Errorf("refusing to quarantine builtin extension %q", ext.ID)
	}
	if ext.InstallPath == "" {
		return fmt.Errorf("extension %q has no install path", ext.ID)
	}
	if ide.ExtensionsPath == "" {
		return fmt.Errorf("IDE %q has no extensions path", ide.Name)
	}

	realExt, err := filepath.EvalSymlinks(ext.InstallPath)
	if err != nil {
		return fmt.Errorf("cannot resolve extension path: %w", err)
	}
	realParent, err := filepath.EvalSymlinks(ide.ExtensionsPath)
	if err != nil {
		return fmt.Errorf("cannot resolve IDE extensions path: %w", err)
	}

	rel, err := filepath.Rel(realParent, realExt)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("extension path %q is not under IDE extensions dir %q", realExt, realParent)
	}

	if home, _ := os.UserHomeDir(); realExt == home || realExt == string(os.PathSeparator) {
		return fmt.Errorf("refusing to quarantine sensitive path %q", realExt)
	}
	return nil
}

// ── helpers ─────────────────────────────────────────────────────────────

// sanitizeName makes a string safe to use as a single path segment.
func sanitizeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		return "ext"
	}
	return out
}

// moveDir renames src to dst, falling back to copy+remove across filesystems.
func moveDir(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	} else if !errors.Is(err, syscall.EXDEV) {
		return err
	}
	if err := copyTree(src, dst); err != nil {
		return err
	}
	return os.RemoveAll(src)
}

func copyTree(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if info.IsDir() {
		if err := os.MkdirAll(dst, info.Mode().Perm()); err != nil {
			return err
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if err := copyTree(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func writeManifest(path string, m quarantineManifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func readManifest(path string) (quarantineManifest, error) {
	var m quarantineManifest
	data, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	err = json.Unmarshal(data, &m)
	return m, err
}
