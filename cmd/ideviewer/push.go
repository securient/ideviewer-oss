package main

import (
	"fmt"

	"github.com/securient/ideviewer-oss/pkg/api"
	"github.com/securient/ideviewer-oss/pkg/dependencies"
	"github.com/securient/ideviewer-oss/pkg/scanner"
	"github.com/securient/ideviewer-oss/pkg/secrets"
)

// pushScanToPortal submits a scan the user ran by hand and, if the portal is
// waiting on an on-demand request for this host, closes that request out.
//
// The escape hatch for a daemon that never collects its work. Without it the
// portal's Trigger Scan sits at "Waiting for daemon to pick up request..."
// with no way forward except waiting for the pickup timeout.
//
// On overwriting results: it cannot. Scan reports are append-only rows on the
// portal — ingesting one adds history and re-derives the current-state child
// rows, and retention only nulls the raw payload of superseded reports. What a
// manual push *can* do is mislead, by making a hand-run scan look like routine
// daemon telemetry. So every push is tagged source=cli on the report, and the
// scan request it fulfils records who fulfilled it and how.
func pushScanToPortal(result *scanner.ScanResult, includeSecrets, includeDeps bool) {
	_, client, err := portalClient()
	if err != nil {
		colorRed.Printf("Portal error: %v\n", err)
		return
	}

	scanData := toMap(result)
	if includeSecrets {
		sc := secrets.NewScanner()
		if secResult, err := sc.Scan(); err == nil && secResult != nil {
			scanData["secrets"] = toMap(secResult)
		}
	}
	if includeDeps {
		dc := dependencies.NewScanner()
		if depResult, err := dc.Scan(); err == nil && depResult != nil {
			scanData["dependencies"] = toMap(depResult)
		}
	}

	// Claim a pending request before submitting, so the portal shows progress
	// while the upload is in flight rather than jumping from pending to done.
	requestID, claimed := claimPendingScanRequest(client)

	resp, err := client.SubmitReportFrom(scanData, api.SourceCLI)
	if err != nil {
		colorRed.Printf("Portal error: %v\n", err)
		if claimed {
			// Hand the request back rather than leaving it mid-flight; the
			// portal marks it failed and the button becomes usable again.
			_, _ = client.UpdateScanRequest(requestID, map[string]any{
				"status":        "failed",
				"log_message":   fmt.Sprintf("Manual CLI push failed: %v", err),
				"log_level":     "error",
				"error_message": err.Error(),
			})
		}
		return
	}

	if success, ok := resp["success"].(bool); !ok || !success {
		errMsg, _ := resp["error"].(string)
		colorRed.Printf("Portal rejected report: %s\n", errMsg)
		return
	}

	colorGreen.Println("Report pushed to portal (source: cli)")
	if stats, ok := resp["stats"].(map[string]any); ok && stats != nil {
		colorDim.Printf("  IDEs: %v, Extensions: %v, Secrets: %v, Packages: %v\n",
			stats["total_ides"], stats["total_extensions"],
			stats["secrets_found"], stats["packages_found"])
	}

	if !claimed {
		return
	}
	if _, err := client.UpdateScanRequest(requestID, map[string]any{
		"status":      "completed",
		"log_message": "Scan request fulfilled manually via 'ideviewer scan --push'",
		"log_level":   "warning",
	}); err != nil {
		colorYellow.Printf("Report was accepted, but scan request #%d could not be closed: %v\n", requestID, err)
		return
	}
	colorGreen.Printf("Closed pending scan request #%d\n", requestID)
}

// claimPendingScanRequest finds an outstanding on-demand request for this host
// and marks it in progress. Returns the request id and whether it was claimed.
//
// A failure to claim is never fatal: the point of --push is to work when the
// portal's request plane is not cooperating, so the report still goes up.
func claimPendingScanRequest(client *api.Client) (int, bool) {
	pending, err := client.GetPendingScanRequests()
	if err != nil {
		colorDim.Printf("Could not check for pending scan requests: %v\n", err)
		return 0, false
	}
	if len(pending) == 0 {
		return 0, false
	}

	// Newest first — the portal's host page polls the newest request, so
	// closing an older one would leave the page still showing "Pending".
	requestID := 0
	for _, req := range pending {
		idFloat, ok := req["id"].(float64)
		if !ok {
			continue
		}
		if id := int(idFloat); id > requestID {
			requestID = id
		}
	}
	if requestID == 0 {
		return 0, false
	}

	colorCyan.Printf("Found pending scan request #%d — fulfilling it from this CLI run\n", requestID)
	if _, err := client.UpdateScanRequest(requestID, map[string]any{
		"status": "scanning_ides",
		"log_message": "Fulfilled manually with 'ideviewer scan --push' on the host " +
			"(the daemon did not collect this request)",
		"log_level": "warning",
	}); err != nil {
		colorYellow.Printf("Could not claim scan request #%d: %v\n", requestID, err)
		return 0, false
	}
	return requestID, true
}
