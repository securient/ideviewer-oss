package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestClientPrefersHostTokenOverCustomerKey verifies the header logic:
// when HostToken is set, the X-Host-Token header is sent and X-Customer-Key
// is NOT sent; when HostToken is empty the legacy X-Customer-Key is sent.
func TestClientPrefersHostTokenOverCustomerKey(t *testing.T) {
	cases := []struct {
		name         string
		customerKey  string
		hostToken    string
		wantTokenHdr string
		wantCustHdr  string
	}{
		{"token only", "cust-key", "tok-abc", "tok-abc", ""},
		{"key only", "cust-key", "", "", "cust-key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotToken, gotKey string
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotToken = r.Header.Get("X-Host-Token")
				gotKey = r.Header.Get("X-Customer-Key")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]any{"valid": true})
			}))
			defer ts.Close()

			c := NewClientWithToken(ts.URL, tc.customerKey, tc.hostToken)
			if _, err := c.ValidateKey(); err != nil {
				t.Fatalf("ValidateKey: %v", err)
			}
			if gotToken != tc.wantTokenHdr {
				t.Errorf("X-Host-Token: got %q want %q", gotToken, tc.wantTokenHdr)
			}
			if gotKey != tc.wantCustHdr {
				t.Errorf("X-Customer-Key: got %q want %q", gotKey, tc.wantCustHdr)
			}
		})
	}
}

// TestSetHostTokenSwitchesAuth verifies that calling SetHostToken on an
// existing client changes which header is sent on subsequent requests.
func TestSetHostTokenSwitchesAuth(t *testing.T) {
	var gotToken, gotKey string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Host-Token")
		gotKey = r.Header.Get("X-Customer-Key")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"ack": true})
	}))
	defer ts.Close()

	c := NewClient(ts.URL, "cust-key")
	if _, err := c.SendHeartbeat(); err != nil {
		t.Fatalf("first heartbeat: %v", err)
	}
	if gotKey != "cust-key" {
		t.Errorf("initial X-Customer-Key: got %q want %q", gotKey, "cust-key")
	}
	if gotToken != "" {
		t.Errorf("initial X-Host-Token should be empty, got %q", gotToken)
	}

	c.SetHostToken("new-tok")
	if _, err := c.SendHeartbeat(); err != nil {
		t.Fatalf("second heartbeat: %v", err)
	}
	if gotToken != "new-tok" {
		t.Errorf("after SetHostToken X-Host-Token: got %q want %q", gotToken, "new-tok")
	}
	if gotKey != "" {
		t.Errorf("after SetHostToken X-Customer-Key should be empty, got %q", gotKey)
	}

	// And clearing the token should fall back to customer-key auth.
	c.SetHostToken("")
	if _, err := c.SendHeartbeat(); err != nil {
		t.Fatalf("third heartbeat: %v", err)
	}
	if gotKey != "cust-key" {
		t.Errorf("after clearing token X-Customer-Key: got %q want %q", gotKey, "cust-key")
	}
	if gotToken != "" {
		t.Errorf("after clearing token X-Host-Token should be empty, got %q", gotToken)
	}
}

// TestClient401WithTokenReturnsErrTokenRevoked verifies that a 401
// response on a token-authenticated request maps to ErrTokenRevoked and
// is detectable via errors.Is.
func TestClient401WithTokenReturnsErrTokenRevoked(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Host-Token") != "" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "revoked"})
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c := NewClientWithToken(ts.URL, "cust", "bad-token")
	_, err := c.SendHeartbeat()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrTokenRevoked) {
		t.Errorf("expected ErrTokenRevoked, got %v", err)
	}
}

// TestClient401WithCustomerKeyDoesNotReturnErrTokenRevoked verifies the
// legacy behaviour is preserved: a 401 under customer-key auth returns
// the existing APIError type, not ErrTokenRevoked.
func TestClient401WithCustomerKeyDoesNotReturnErrTokenRevoked(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "unauthorized"})
	}))
	defer ts.Close()

	c := NewClient(ts.URL, "cust")
	_, err := c.SendHeartbeat()
	if err == nil {
		t.Fatal("expected an error")
	}
	if errors.Is(err, ErrTokenRevoked) {
		t.Error("customer-key 401 should not be ErrTokenRevoked")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Errorf("expected *APIError, got %T: %v", err, err)
	} else if apiErr.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want 401", apiErr.StatusCode)
	}
}
