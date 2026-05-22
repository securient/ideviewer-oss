package daemon

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/securient/ideviewer-oss/internal/config"
	"github.com/securient/ideviewer-oss/pkg/api"
	"github.com/securient/ideviewer-oss/pkg/scanner"
)

// TestWithReauth_NoError_PassesThrough verifies that if the wrapped call
// succeeds, withReauth simply returns nil and does not attempt to
// re-enroll.
func TestWithReauth_NoError_PassesThrough(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test relies on HOME redirection which is POSIX-specific")
	}
	t.Setenv("HOME", t.TempDir())

	cfg := &config.Config{
		PortalURL:           "http://unused.test",
		CustomerKey:         "cust",
		HostToken:           "tok",
		ScanIntervalMinutes: 30,
	}
	d, err := New(cfg, scanner.New())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	calls := 0
	gotErr := d.withReauth(func() error {
		calls++
		return nil
	})
	if gotErr != nil {
		t.Errorf("withReauth returned %v, want nil", gotErr)
	}
	if calls != 1 {
		t.Errorf("call invoked %d times, want 1", calls)
	}
}

// TestWithReauth_NonRevokedError_PassesThrough verifies that an error
// that is not ErrTokenRevoked is returned to the caller unchanged.
func TestWithReauth_NonRevokedError_PassesThrough(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test relies on HOME redirection which is POSIX-specific")
	}
	t.Setenv("HOME", t.TempDir())

	cfg := &config.Config{
		PortalURL:           "http://unused.test",
		CustomerKey:         "cust",
		ScanIntervalMinutes: 30,
	}
	d, err := New(cfg, scanner.New())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	sentinel := errors.New("some other error")
	calls := 0
	gotErr := d.withReauth(func() error {
		calls++
		return sentinel
	})
	if !errors.Is(gotErr, sentinel) {
		t.Errorf("withReauth returned %v, want %v", gotErr, sentinel)
	}
	if calls != 1 {
		t.Errorf("call invoked %d times, want 1 (no retry for non-revoked errors)", calls)
	}
}

// TestWithReauth_RecoversFromRevokedToken simulates the full re-auth
// flow: the first heartbeat returns 401 (token revoked), the daemon
// re-registers, the portal issues a new token, and the retried call
// succeeds. We also verify the new token is persisted to config.
func TestWithReauth_RecoversFromRevokedToken(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test relies on HOME redirection which is POSIX-specific")
	}
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	const oldToken = "old-revoked-token"
	const newToken = "fresh-token-from-portal"

	var heartbeatCalls int32
	var registerCalls int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/heartbeat":
			atomic.AddInt32(&heartbeatCalls, 1)
			tok := r.Header.Get("X-Host-Token")
			// First call carries the old token -> revoked.
			if tok == oldToken {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "revoked"})
				return
			}
			// Retried call must carry the new token.
			if tok != newToken {
				t.Errorf("retry heartbeat had X-Host-Token=%q, want %q", tok, newToken)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"ack": true})

		case "/api/register-host":
			atomic.AddInt32(&registerCalls, 1)
			// Re-enrollment uses customer key auth (token was cleared).
			if r.Header.Get("X-Host-Token") != "" {
				t.Errorf("register-host should not carry X-Host-Token, got %q",
					r.Header.Get("X-Host-Token"))
			}
			if r.Header.Get("X-Customer-Key") == "" {
				t.Error("register-host should carry X-Customer-Key after token clear")
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"message":    "ok",
				"host_token": newToken,
			})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	cfg := &config.Config{
		PortalURL:           ts.URL,
		CustomerKey:         "cust-key",
		HostToken:           oldToken,
		ScanIntervalMinutes: 30,
	}
	d, err := New(cfg, scanner.New())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Drive the wrapper via the public sendHeartbeat path. We use
	// withReauth directly so we can assert returned values.
	wrapped := func() error {
		_, callErr := d.apiClient.SendHeartbeat()
		return callErr
	}

	if err := d.withReauth(wrapped); err != nil {
		t.Fatalf("withReauth returned %v, want nil on retry success", err)
	}

	if got := atomic.LoadInt32(&heartbeatCalls); got != 2 {
		t.Errorf("heartbeatCalls = %d, want 2 (one failure + one retry)", got)
	}
	if got := atomic.LoadInt32(&registerCalls); got != 1 {
		t.Errorf("registerCalls = %d, want 1", got)
	}

	// In-memory state.
	if d.apiClient.HostToken != newToken {
		t.Errorf("client HostToken = %q, want %q", d.apiClient.HostToken, newToken)
	}
	if d.config.HostToken != newToken {
		t.Errorf("config HostToken = %q, want %q", d.config.HostToken, newToken)
	}

	// Persisted state: config.Save writes to ConfigDir under HOME.
	loaded, loadErr := config.Load()
	if loadErr != nil {
		t.Fatalf("config.Load: %v", loadErr)
	}
	if loaded.HostToken != newToken {
		t.Errorf("persisted HostToken = %q, want %q", loaded.HostToken, newToken)
	}
}

// TestWithReauth_GivesUpIfReEnrollFails ensures the wrapper does not
// retry the original call if re-enrollment itself fails.
func TestWithReauth_GivesUpIfReEnrollFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test relies on HOME redirection which is POSIX-specific")
	}
	t.Setenv("HOME", t.TempDir())

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/register-host":
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "down"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	cfg := &config.Config{
		PortalURL:           ts.URL,
		CustomerKey:         "cust",
		HostToken:           "tok",
		ScanIntervalMinutes: 30,
	}
	d, err := New(cfg, scanner.New())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	calls := 0
	gotErr := d.withReauth(func() error {
		calls++
		// Always say "revoked".
		return api.ErrTokenRevoked
	})
	if gotErr == nil {
		t.Fatal("expected error from failed re-enrollment, got nil")
	}
	if calls != 1 {
		t.Errorf("original call invoked %d times, want 1 (no retry when re-enroll fails)", calls)
	}
}
