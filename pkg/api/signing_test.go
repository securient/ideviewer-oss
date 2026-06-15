package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// makeEnvelope builds a signed command envelope the way the portal does:
// body_b64 = base64(canonical JSON), signature over "issued_at.nonce.body_b64".
func makeEnvelope(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey, issuedAt int64, nonce string, body []byte) map[string]any {
	t.Helper()
	bodyB64 := base64.StdEncoding.EncodeToString(body)
	msg := fmt.Appendf(nil, "%d.%s.%s", issuedAt, nonce, bodyB64)
	sig := ed25519.Sign(priv, msg)

	var top map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		top = map[string]any{}
	}
	top["sig"] = map[string]any{
		"key_id":        CommandKeyID(pub),
		"alg":           "ed25519",
		"issued_at":     issuedAt,
		"nonce":         nonce,
		"body_b64":      bodyB64,
		"signature_b64": base64.StdEncoding.EncodeToString(sig),
	}
	return top
}

func newKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, []string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pinned := []string{base64.StdEncoding.EncodeToString(pub)}
	return pub, priv, pinned
}

func TestVerifyEnvelope_Valid(t *testing.T) {
	pub, priv, pinned := newKeypair(t)
	now := time.Now()
	body := []byte(`{"actions":[{"id":7,"action":"quarantine"}]}`)
	env := makeEnvelope(t, priv, pub, now.Unix(), "nonce-1", body)

	got, err := VerifyEnvelope(env, pinned, now, NewNonceCache())
	if err != nil {
		t.Fatalf("VerifyEnvelope: %v", err)
	}
	actions, err := ParseEnforcementActions(got)
	if err != nil {
		t.Fatalf("ParseEnforcementActions: %v", err)
	}
	if len(actions) != 1 || actions[0]["action"] != "quarantine" {
		t.Errorf("unexpected actions: %v", actions)
	}
}

func TestVerifyEnvelope_TamperedBody(t *testing.T) {
	pub, priv, pinned := newKeypair(t)
	now := time.Now()
	env := makeEnvelope(t, priv, pub, now.Unix(), "n", []byte(`{"actions":[]}`))
	// Swap the signed body for a different one — signature no longer matches.
	env["sig"].(map[string]any)["body_b64"] =
		base64.StdEncoding.EncodeToString([]byte(`{"actions":[{"id":99,"action":"quarantine"}]}`))

	if _, err := VerifyEnvelope(env, pinned, now, NewNonceCache()); err == nil {
		t.Fatal("expected verification failure for tampered body")
	}
}

func TestVerifyEnvelope_WrongKey(t *testing.T) {
	pub, priv, _ := newKeypair(t)
	now := time.Now()
	env := makeEnvelope(t, priv, pub, now.Unix(), "n", []byte(`{"actions":[]}`))

	// Pin a DIFFERENT key — key_id won't match.
	otherPub, _, _ := ed25519.GenerateKey(nil)
	pinnedOther := []string{base64.StdEncoding.EncodeToString(otherPub)}

	if _, err := VerifyEnvelope(env, pinnedOther, now, NewNonceCache()); err == nil {
		t.Fatal("expected failure when no pinned key matches")
	}
}

func TestVerifyEnvelope_NoPinnedKey(t *testing.T) {
	pub, priv, _ := newKeypair(t)
	now := time.Now()
	env := makeEnvelope(t, priv, pub, now.Unix(), "n", []byte(`{"actions":[]}`))

	if _, err := VerifyEnvelope(env, nil, now, NewNonceCache()); err == nil {
		t.Fatal("expected failure when no key is pinned (legacy host)")
	}
}

func TestVerifyEnvelope_Expired(t *testing.T) {
	pub, priv, pinned := newKeypair(t)
	now := time.Now()
	// Signed 10 minutes ago — outside the 5-minute replay window.
	env := makeEnvelope(t, priv, pub, now.Add(-10*time.Minute).Unix(), "n", []byte(`{"actions":[]}`))

	if _, err := VerifyEnvelope(env, pinned, now, NewNonceCache()); err == nil {
		t.Fatal("expected failure for command outside the replay window")
	}
}

func TestVerifyEnvelope_TamperedTimestamp(t *testing.T) {
	pub, priv, pinned := newKeypair(t)
	now := time.Now()
	env := makeEnvelope(t, priv, pub, now.Unix(), "n", []byte(`{"actions":[]}`))
	// Move the timestamp; signature was over the original — must fail.
	env["sig"].(map[string]any)["issued_at"] = now.Add(-time.Minute).Unix()

	if _, err := VerifyEnvelope(env, pinned, now, NewNonceCache()); err == nil {
		t.Fatal("expected failure when issued_at is altered after signing")
	}
}

func TestVerifyEnvelope_ReplayedNonce(t *testing.T) {
	pub, priv, pinned := newKeypair(t)
	now := time.Now()
	cache := NewNonceCache()
	body := []byte(`{"actions":[]}`)
	env := makeEnvelope(t, priv, pub, now.Unix(), "dup-nonce", body)

	if _, err := VerifyEnvelope(env, pinned, now, cache); err != nil {
		t.Fatalf("first verify should succeed: %v", err)
	}
	// Same nonce again within the window — must be rejected as a replay.
	env2 := makeEnvelope(t, priv, pub, now.Unix(), "dup-nonce", body)
	if _, err := VerifyEnvelope(env2, pinned, now, cache); err == nil {
		t.Fatal("expected replayed nonce to be rejected")
	}
}

func TestVerifyEnvelope_NonceReusableAfterWindow(t *testing.T) {
	pub, priv, pinned := newKeypair(t)
	cache := NewNonceCache()
	body := []byte(`{"actions":[]}`)

	t0 := time.Now()
	env := makeEnvelope(t, priv, pub, t0.Unix(), "n", body)
	if _, err := VerifyEnvelope(env, pinned, t0, cache); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	// Far in the future: the old nonce has been evicted and a fresh command
	// (new timestamp, same nonce string) verifies.
	t1 := t0.Add(10 * time.Minute)
	env2 := makeEnvelope(t, priv, pub, t1.Unix(), "n", body)
	if _, err := VerifyEnvelope(env2, pinned, t1, cache); err != nil {
		t.Fatalf("verify after window should succeed: %v", err)
	}
}

func TestVerifyEnvelope_Unsigned(t *testing.T) {
	now := time.Now()
	_, _, pinned := newKeypair(t)
	// An old-style unsigned response: just {"actions":[...]}.
	env := map[string]any{"actions": []any{}}
	if _, err := VerifyEnvelope(env, pinned, now, NewNonceCache()); err == nil {
		t.Fatal("expected failure for an unsigned envelope")
	}
}

func TestVerifyEnvelope_MalformedSignature(t *testing.T) {
	pub, priv, pinned := newKeypair(t)
	now := time.Now()
	env := makeEnvelope(t, priv, pub, now.Unix(), "n", []byte(`{"actions":[]}`))
	env["sig"].(map[string]any)["signature_b64"] = "not-base64!!!"
	if _, err := VerifyEnvelope(env, pinned, now, NewNonceCache()); err == nil {
		t.Fatal("expected failure for malformed signature")
	}
}
