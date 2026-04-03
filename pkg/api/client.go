package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/securient/ideviewer-oss/internal/version"
)

// Client communicates with the IDEViewer portal API.
type Client struct {
	PortalURL   string
	CustomerKey string
	HTTPClient  *http.Client
	hostname    string
	platform    string
}

// APIError represents an error response from the portal.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("API error %d: %s", e.StatusCode, e.Message)
}

// ScanCancelledError indicates the scan was cancelled by the user.
type ScanCancelledError struct {
	RequestID int
}

func (e *ScanCancelledError) Error() string {
	return fmt.Sprintf("scan request %d was cancelled", e.RequestID)
}

// NewClient creates a new API client.
func NewClient(portalURL, customerKey string) *Client {
	hostname, _ := os.Hostname()
	return &Client{
		PortalURL:   portalURL,
		CustomerKey: customerKey,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		hostname: hostname,
		platform: fmt.Sprintf("%s %s", runtime.GOOS, runtime.GOARCH),
	}
}

// doRequest executes an HTTP request with standard headers.
func (c *Client) doRequest(method, path string, body any) (map[string]any, error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	url := c.PortalURL + path
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("X-Customer-Key", c.CustomerKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "IDEViewer-Daemon/"+version.Version)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request to %s failed: %w", path, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var result map[string]any
	if len(respBody) > 0 {
		if err := json.Unmarshal(respBody, &result); err != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}
	}

	if resp.StatusCode >= 400 {
		msg := "unknown error"
		if e, ok := result["error"].(string); ok {
			msg = e
		}
		return nil, &APIError{StatusCode: resp.StatusCode, Message: msg}
	}

	return result, nil
}

// ValidateKey validates the customer key with the portal.
func (c *Client) ValidateKey() (map[string]any, error) {
	return c.doRequest("POST", "/api/validate-key", map[string]any{
		"hostname": c.hostname,
		"platform": c.platform,
	})
}

// RegisterHost registers this machine with the portal.
func (c *Client) RegisterHost() (map[string]any, error) {
	return c.doRequest("POST", "/api/register-host", map[string]any{
		"hostname": c.hostname,
		"platform": c.platform,
	})
}

// SubmitReport sends scan results to the portal.
func (c *Client) SubmitReport(scanData map[string]any) (map[string]any, error) {
	return c.doRequest("POST", "/api/report", map[string]any{
		"hostname":  c.hostname,
		"platform":  c.platform,
		"scan_data": scanData,
	})
}

// GetPendingScanRequests checks for on-demand scan requests.
func (c *Client) GetPendingScanRequests() ([]map[string]any, error) {
	result, err := c.doRequest("GET", "/api/scan-requests/pending", nil)
	if err != nil {
		return nil, err
	}

	requests, ok := result["requests"].([]any)
	if !ok {
		return nil, nil
	}

	var out []map[string]any
	for _, r := range requests {
		if m, ok := r.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out, nil
}

// UpdateScanRequest updates the progress of an on-demand scan.
func (c *Client) UpdateScanRequest(requestID int, params map[string]any) (map[string]any, error) {
	path := fmt.Sprintf("/api/scan-requests/%d/update", requestID)
	result, err := c.doRequest("POST", path, params)
	if err != nil {
		return nil, err
	}

	// Check if scan was cancelled
	if cancelled, ok := result["cancelled"].(bool); ok && cancelled {
		return nil, &ScanCancelledError{RequestID: requestID}
	}

	return result, nil
}

// SendHeartbeat sends a heartbeat to the portal.
func (c *Client) SendHeartbeat() (map[string]any, error) {
	return c.doRequest("POST", "/api/heartbeat", map[string]any{
		"hostname":       c.hostname,
		"platform":       c.platform,
		"daemon_version": version.Version,
	})
}

// SendTamperAlert reports a tamper/integrity alert.
func (c *Client) SendTamperAlert(alertType, details string) (map[string]any, error) {
	return c.doRequest("POST", "/api/alert", map[string]any{
		"hostname":   c.hostname,
		"platform":   c.platform,
		"alert_type": alertType,
		"details":    details,
	})
}

// DeregisterHost notifies the portal that this host is being uninstalled.
func (c *Client) DeregisterHost(reason string) (map[string]any, error) {
	return c.doRequest("POST", "/api/deregister-host", map[string]any{
		"hostname": c.hostname,
		"platform": c.platform,
		"reason":   reason,
	})
}

// SubmitRealtimeEvent sends a real-time change event to the portal.
func (c *Client) SubmitRealtimeEvent(eventData map[string]any) (map[string]any, error) {
	eventData["hostname"] = c.hostname
	eventData["platform"] = c.platform
	return c.doRequest("POST", "/api/realtime-event", eventData)
}

// SendHookBypass reports a git hook bypass event.
func (c *Client) SendHookBypass(data map[string]any) (map[string]any, error) {
	data["hostname"] = c.hostname
	data["platform"] = c.platform
	return c.doRequest("POST", "/api/hook-bypass", data)
}
