package daemon

import (
	"fmt"
	"log"

	"github.com/securient/ideviewer-oss/pkg/api"
)

// checkOnDemandScans polls the portal for pending scan requests and executes
// each one sequentially.
func (d *Daemon) checkOnDemandScans() {
	if d.apiClient == nil {
		return
	}

	pending, err := d.apiClient.GetPendingScanRequests()
	if err != nil {
		log.Printf("Error checking on-demand scans: %v", err)
		return
	}

	for _, req := range pending {
		idFloat, ok := req["id"].(float64)
		if !ok {
			continue
		}
		requestID := int(idFloat)
		log.Printf("Processing on-demand scan request #%d", requestID)
		d.executeOnDemandScan(requestID)
	}
}

// executeOnDemandScan runs a full scan with progress updates reported back to
// the portal for the given request ID.
func (d *Daemon) executeOnDemandScan(requestID int) {
	update := func(params map[string]any) error {
		_, err := d.apiClient.UpdateScanRequest(requestID, params)
		return err
	}

	// progress sends a status update; if the scan was cancelled it panics
	// with cancelSentinel which is recovered by the outer defer.
	progress := func(params map[string]any) {
		err := update(params)
		if err != nil {
			if isCancelled(err) {
				panic(cancelSentinel{requestID: requestID})
			}
			log.Printf("Progress update failed for request #%d: %v", requestID, err)
		}
	}

	// Recover from cancel panics and unexpected panics.
	defer func() {
		if r := recover(); r != nil {
			if cs, ok := r.(cancelSentinel); ok {
				log.Printf("On-demand scan #%d was cancelled by user", cs.requestID)
				return
			}
			errMsg := fmt.Sprintf("%v", r)
			log.Printf("On-demand scan #%d panicked: %s", requestID, errMsg)
			_ = update(map[string]any{
				"status":        "failed",
				"log_message":   "Scan failed: " + errMsg,
				"log_level":     "error",
				"error_message": errMsg,
			})
		}
	}()

	// Step 1: Acknowledge.
	progress(map[string]any{
		"status":      "connecting",
		"log_message": "Daemon received scan request, establishing connection...",
	})
	progress(map[string]any{
		"log_message": "Connected to daemon on host",
		"log_level":   "success",
	})

	// Step 2: IDE scanning.
	progress(map[string]any{
		"status":      "scanning_ides",
		"log_message": "Starting IDE and extension scan...",
	})

	ideResult, err := d.scanner.Scan()
	if err != nil {
		_ = update(map[string]any{
			"status":        "failed",
			"log_message":   fmt.Sprintf("IDE scan failed: %v", err),
			"log_level":     "error",
			"error_message": err.Error(),
		})
		return
	}

	for _, ide := range ideResult.IDEs {
		extCount := len(ide.Extensions)
		dangerous := 0
		for _, ext := range ide.Extensions {
			for _, p := range ext.Permissions {
				if p.IsDangerous {
					dangerous++
					break
				}
			}
		}
		progress(map[string]any{
			"log_message": fmt.Sprintf("Found %s v%s -- %d extensions (%d flagged)",
				ide.Name, ide.Version, extCount, dangerous),
		})
	}

	totalExts := 0
	for _, ide := range ideResult.IDEs {
		totalExts += len(ide.Extensions)
	}
	progress(map[string]any{
		"log_message": fmt.Sprintf("IDE scan complete: %d IDEs, %d total extensions",
			len(ideResult.IDEs), totalExts),
		"log_level": "success",
	})

	// Step 3: Secrets scanning.
	progress(map[string]any{
		"status":      "scanning_secrets",
		"log_message": "Starting plaintext secrets scan...",
	})

	secretsResult, err := d.secrets.Scan()
	if err != nil {
		log.Printf("Secrets scan error during on-demand scan: %v", err)
	}

	if secretsResult != nil && len(secretsResult.Findings) > 0 {
		progress(map[string]any{
			"log_message": fmt.Sprintf("WARNING: Found %d plaintext secret(s)!",
				len(secretsResult.Findings)),
			"log_level": "warning",
		})
		for _, finding := range secretsResult.Findings {
			progress(map[string]any{
				"log_message": fmt.Sprintf("  %s in %s", finding.SecretType, finding.FilePath),
				"log_level":   "warning",
			})
		}
	} else {
		progress(map[string]any{
			"log_message": "No plaintext secrets detected",
			"log_level":   "success",
		})
	}

	// Step 4: Package scanning.
	progress(map[string]any{
		"status":      "scanning_packages",
		"log_message": "Starting package/dependency scan...",
	})

	depResult, err := d.dependencies.Scan()
	if err != nil {
		log.Printf("Dependency scan error during on-demand scan: %v", err)
	}

	if depResult != nil {
		for _, mgr := range depResult.PackageManagersFound {
			count := 0
			for _, p := range depResult.Packages {
				if p.PackageManager == mgr {
					count++
				}
			}
			progress(map[string]any{
				"log_message": fmt.Sprintf("Found %d %s packages", count, mgr),
			})
		}

		hooksCount := 0
		for _, p := range depResult.Packages {
			if len(p.LifecycleHooks) > 0 {
				hooksCount++
			}
		}
		if hooksCount > 0 {
			progress(map[string]any{
				"log_message": fmt.Sprintf("WARNING: %d npm package(s) "+
					"with lifecycle hooks (preinstall/postinstall)", hooksCount),
				"log_level": "warning",
			})
		}

		progress(map[string]any{
			"log_message": fmt.Sprintf("Package scan complete: %d packages across %d package managers",
				len(depResult.Packages), len(depResult.PackageManagersFound)),
			"log_level": "success",
		})
	}

	// Step 5: Submit results to portal.
	progress(map[string]any{
		"log_message": "Submitting scan results to portal...",
	})

	d.lastResult = ideResult
	d.sendToPortal(ideResult, secretsResult, depResult, nil)

	progress(map[string]any{
		"status":      "completed",
		"log_message": "On-demand scan completed successfully",
		"log_level":   "success",
	})

	log.Printf("On-demand scan #%d completed successfully", requestID)
}

// cancelSentinel is used to signal scan cancellation via panic/recover.
type cancelSentinel struct {
	requestID int
}

// isCancelled checks whether the error is a ScanCancelledError.
func isCancelled(err error) bool {
	_, ok := err.(*api.ScanCancelledError)
	return ok
}
