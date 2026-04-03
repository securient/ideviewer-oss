package daemon

import (
	"log"
	"time"

	"github.com/securient/ideviewer-oss/pkg/watcher"
)

// handleRealtimeEvents processes filesystem change events from the watcher.
// It runs a targeted rescan and reports to the portal via the realtime-event endpoint.
func (d *Daemon) handleRealtimeEvents(events []watcher.ChangeEvent) {
	// Run a targeted rescan (IDE + deps only, not secrets or AI tools)
	ideRes, ideErr := d.scanner.Scan()
	if ideErr != nil {
		log.Printf("Realtime IDE rescan error: %v", ideErr)
	}
	depRes, depErr := d.dependencies.Scan()
	if depErr != nil {
		log.Printf("Realtime dependency rescan error: %v", depErr)
	}

	if ideRes != nil {
		d.lastResult = ideRes
		totalExts := 0
		for _, ide := range ideRes.IDEs {
			totalExts += len(ide.Extensions)
		}
		log.Printf("Realtime rescan: %d IDEs, %d extensions", len(ideRes.IDEs), totalExts)
	}

	// Build event data for the realtime endpoint
	eventData := map[string]any{
		"event_type": "extension_change",
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"changes":    make([]map[string]any, 0, len(events)),
	}
	for _, e := range events {
		eventData["changes"] = append(eventData["changes"].([]map[string]any), map[string]any{
			"path":       e.Path,
			"event_type": e.EventType,
			"timestamp":  e.Timestamp.Format(time.RFC3339),
		})
	}

	// Include scan data
	if ideRes != nil {
		eventData["scan_data"] = structToMap(ideRes)
	}
	if depRes != nil {
		eventData["dependencies"] = structToMap(depRes)
	}

	// Submit to realtime endpoint
	if d.apiClient != nil {
		resp, err := d.apiClient.SubmitRealtimeEvent(eventData)
		if err != nil {
			log.Printf("Failed to submit realtime event: %v", err)
		} else {
			log.Printf("Realtime event submitted: %v", resp)
		}
	}
}
