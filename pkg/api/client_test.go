package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidateKey(t *testing.T) {
	var receivedHeaders http.Header
	var receivedBody map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header

		decoder := json.NewDecoder(r.Body)
		decoder.Decode(&receivedBody)

		if r.URL.Path != "/api/validate-key" {
			t.Errorf("path = %q, want /api/validate-key", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("method = %q, want POST", r.Method)
		}

		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]any{"valid": true})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key-123")
	result, err := client.ValidateKey()
	if err != nil {
		t.Fatalf("ValidateKey() error: %v", err)
	}

	if receivedHeaders.Get("X-Customer-Key") != "test-key-123" {
		t.Errorf("X-Customer-Key = %q, want %q", receivedHeaders.Get("X-Customer-Key"), "test-key-123")
	}
	if receivedHeaders.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", receivedHeaders.Get("Content-Type"))
	}
	if receivedBody["hostname"] == nil {
		t.Error("expected hostname in request body")
	}
	if receivedBody["platform"] == nil {
		t.Error("expected platform in request body")
	}
	if result["valid"] != true {
		t.Errorf("result[valid] = %v, want true", result["valid"])
	}
}

func TestRegisterHost(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/register-host" {
			t.Errorf("path = %q, want /api/register-host", r.URL.Path)
		}
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]any{"host_id": "host-abc"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "key")
	result, err := client.RegisterHost()
	if err != nil {
		t.Fatalf("RegisterHost() error: %v", err)
	}
	if result["host_id"] != "host-abc" {
		t.Errorf("host_id = %v, want host-abc", result["host_id"])
	}
}

func TestSubmitReport(t *testing.T) {
	var receivedBody map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/report" {
			t.Errorf("path = %q, want /api/report", r.URL.Path)
		}
		decoder := json.NewDecoder(r.Body)
		decoder.Decode(&receivedBody)

		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "key")
	scanData := map[string]any{"total_ides": 2}
	result, err := client.SubmitReport(scanData)
	if err != nil {
		t.Fatalf("SubmitReport() error: %v", err)
	}
	if result["status"] != "ok" {
		t.Errorf("status = %v, want ok", result["status"])
	}
	if receivedBody["scan_data"] == nil {
		t.Error("expected scan_data in request body")
	}
}

func TestSendHeartbeat(t *testing.T) {
	var receivedBody map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/heartbeat" {
			t.Errorf("path = %q, want /api/heartbeat", r.URL.Path)
		}
		decoder := json.NewDecoder(r.Body)
		decoder.Decode(&receivedBody)

		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]any{"ack": true})
	}))
	defer server.Close()

	client := NewClient(server.URL, "key")
	result, err := client.SendHeartbeat()
	if err != nil {
		t.Fatalf("SendHeartbeat() error: %v", err)
	}
	if result["ack"] != true {
		t.Errorf("ack = %v, want true", result["ack"])
	}
	if receivedBody["daemon_version"] == nil {
		t.Error("expected daemon_version in request body")
	}
}

func TestAPIError_On4xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		json.NewEncoder(w).Encode(map[string]any{"error": "forbidden"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "bad-key")
	_, err := client.ValidateKey()
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != 403 {
		t.Errorf("StatusCode = %d, want 403", apiErr.StatusCode)
	}
	if apiErr.Message != "forbidden" {
		t.Errorf("Message = %q, want %q", apiErr.Message, "forbidden")
	}
}

func TestAPIError_On500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]any{"error": "internal server error"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "key")
	_, err := client.RegisterHost()
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.StatusCode != 500 {
		t.Errorf("StatusCode = %d, want 500", apiErr.StatusCode)
	}
}

func TestAPIError_ErrorString(t *testing.T) {
	err := &APIError{StatusCode: 401, Message: "unauthorized"}
	s := err.Error()
	if s != "API error 401: unauthorized" {
		t.Errorf("Error() = %q, want %q", s, "API error 401: unauthorized")
	}
}
