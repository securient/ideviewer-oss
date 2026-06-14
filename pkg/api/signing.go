package api

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// CommandReplayWindow bounds how stale a signed command may be. Mirrors the
// portal's REPLAY_WINDOW_SECONDS (and the webhook receiver's window).
const CommandReplayWindow = 5 * time.Minute

// CommandSig is the signature block of a signed command envelope. The portal
// signs the ASCII string fmt.Sprintf("%d.%s.%s", IssuedAt, Nonce, BodyB64); we
// verify over the exact BodyB64 we received and only then decode it, so there
// is no JSON canonicalization to disagree on between Python and Go.
type CommandSig struct {
	KeyID        string `json:"key_id"`
	Alg          string `json:"alg"`
	IssuedAt     int64  `json:"issued_at"`
	Nonce        string `json:"nonce"`
	BodyB64      string `json:"body_b64"`
	SignatureB64 string `json:"signature_b64"`
}

// CommandKeyID is the short fingerprint the portal uses to identify a signing
// key: the first 8 bytes of sha256(public key), hex-encoded. Matches
// app/signing.py:_key_id.
func CommandKeyID(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// NonceCache rejects a command nonce replayed within the replay window. It is a
// within-window optimization; the IssuedAt window is the primary defense, so a
// per-process cache is sufficient (a replay across a restart is still blocked
// by the timestamp).
type NonceCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

// NewNonceCache returns an empty, ready-to-use nonce cache.
func NewNonceCache() *NonceCache {
	return &NonceCache{seen: make(map[string]time.Time)}
}

// checkAndAdd returns true if nonce is fresh (and records it), false if it was
// already seen within the window. Expired entries are evicted on each call.
func (n *NonceCache) checkAndAdd(nonce string, now time.Time) bool {
	if n == nil {
		return true
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for k, t := range n.seen {
		if now.Sub(t) > CommandReplayWindow {
			delete(n.seen, k)
		}
	}
	if _, ok := n.seen[nonce]; ok {
		return false
	}
	n.seen[nonce] = now
	return true
}

// matchPinnedKey finds the pinned ed25519 key whose fingerprint equals keyID.
func matchPinnedKey(pinnedB64 []string, keyID string) (ed25519.PublicKey, error) {
	if len(pinnedB64) == 0 {
		return nil, fmt.Errorf("no command signing key is pinned")
	}
	for _, kb := range pinnedB64 {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(kb))
		if err != nil || len(raw) != ed25519.PublicKeySize {
			continue
		}
		if CommandKeyID(raw) == keyID {
			return ed25519.PublicKey(raw), nil
		}
	}
	return nil, fmt.Errorf("no pinned key matches key_id %q", keyID)
}

// VerifyEnvelope verifies a signed command envelope against the pinned public
// keys, the replay window, and the nonce cache, then returns the decoded body
// bytes (the canonical JSON that was signed). It fails closed: any missing
// field, unknown key, stale timestamp, replayed nonce, or signature mismatch
// returns an error and an empty body.
func VerifyEnvelope(env map[string]any, pinnedKeysB64 []string, now time.Time, nonces *NonceCache) ([]byte, error) {
	rawSig, ok := env["sig"]
	if !ok {
		return nil, fmt.Errorf("command envelope is not signed")
	}
	sigBytes, err := json.Marshal(rawSig)
	if err != nil {
		return nil, fmt.Errorf("malformed signature block: %w", err)
	}
	var sig CommandSig
	if err := json.Unmarshal(sigBytes, &sig); err != nil {
		return nil, fmt.Errorf("malformed signature block: %w", err)
	}

	if sig.Alg != "ed25519" {
		return nil, fmt.Errorf("unsupported signature algorithm %q", sig.Alg)
	}
	if sig.BodyB64 == "" || sig.SignatureB64 == "" || sig.Nonce == "" {
		return nil, fmt.Errorf("command envelope missing signature fields")
	}

	skew := now.Unix() - sig.IssuedAt
	if skew < 0 {
		skew = -skew
	}
	if time.Duration(skew)*time.Second > CommandReplayWindow {
		return nil, fmt.Errorf("command outside replay window (%ds skew)", skew)
	}

	pub, err := matchPinnedKey(pinnedKeysB64, sig.KeyID)
	if err != nil {
		return nil, err
	}

	signature, err := base64.StdEncoding.DecodeString(sig.SignatureB64)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("malformed command signature")
	}

	message := fmt.Appendf(nil, "%d.%s.%s", sig.IssuedAt, sig.Nonce, sig.BodyB64)
	if !ed25519.Verify(pub, message, signature) {
		return nil, fmt.Errorf("command signature does not match pinned key")
	}

	// Only consume the nonce after the signature verifies, so an attacker
	// cannot poison the cache with forged nonces.
	if !nonces.checkAndAdd(sig.Nonce, now) {
		return nil, fmt.Errorf("replayed command nonce")
	}

	body, err := base64.StdEncoding.DecodeString(sig.BodyB64)
	if err != nil {
		return nil, fmt.Errorf("malformed command body: %w", err)
	}
	return body, nil
}

// ParseEnforcementActions extracts the action list from a verified command
// body (the JSON {"actions": [...]}).
func ParseEnforcementActions(body []byte) ([]map[string]any, error) {
	var parsed struct {
		Actions []map[string]any `json:"actions"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("parse command body: %w", err)
	}
	return parsed.Actions, nil
}
