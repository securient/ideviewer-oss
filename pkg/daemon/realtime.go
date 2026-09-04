package daemon

import (
	"log"
	"sort"
	"time"

	"github.com/securient/ideviewer-oss/pkg/watcher"
)

// handleRealtimeEvents processes filesystem change events from the watcher.
//
// The watcher tags every event with the category of directory it came from, so
// a change only triggers the rescan it actually invalidates: a new extension
// does not re-walk every project on the machine, and an edited lockfile does
// not re-enumerate MCP servers. Anything not rescanned here is still covered by
// the next periodic scan.
func (d *Daemon) handleRealtimeEvents(events []watcher.ChangeEvent) {
	if len(events) == 0 {
		return
	}

	cats := make(map[watcher.Category]bool, 3)
	for _, e := range events {
		cats[e.Category] = true
	}

	// Periodic and realtime scans share the scanner instances, which the scan
	// pipeline requires be used one at a time. If a periodic scan holds the
	// reservation it is walking the same filesystem we were about to walk, so
	// dropping this batch loses nothing.
	if !d.tryBeginScan() {
		log.Printf("Realtime: %d change(s) in %s skipped, a scan is already running",
			len(events), categoryList(cats))
		return
	}
	defer d.endScan()

	log.Printf("Realtime: %d change(s) detected in %s, rescanning", len(events), categoryList(cats))

	eventData := map[string]any{
		"event_type": "workstation_change",
		"categories": categoryList(cats),
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"changes":    make([]map[string]any, 0, len(events)),
	}
	for _, e := range events {
		eventData["changes"] = append(eventData["changes"].([]map[string]any), map[string]any{
			"path":       e.Path,
			"event_type": e.EventType,
			"category":   string(e.Category),
			"timestamp":  e.Timestamp.Format(time.RFC3339),
		})
	}

	// Extensions and plugins.
	if cats[watcher.CategoryExtensions] {
		ideRes, err := d.scanner.Scan()
		if err != nil {
			log.Printf("Realtime IDE rescan error: %v", err)
		}
		if ideRes != nil {
			d.setResult(ideRes)
			totalExts := 0
			for _, ide := range ideRes.IDEs {
				totalExts += len(ide.Extensions)
			}
			log.Printf("Realtime rescan: %d IDEs, %d extensions", len(ideRes.IDEs), totalExts)
			eventData["scan_data"] = structToMap(ideRes)
		}
	}

	// Dependency manifests and secrets share the project directories, so a
	// change in one is a reason to re-check both: an npm install rewrites the
	// lockfile, and a .env lands in the same tree.
	if cats[watcher.CategoryProjects] {
		depRes, err := d.dependencies.Scan()
		if err != nil {
			log.Printf("Realtime dependency rescan error: %v", err)
		}
		if depRes != nil {
			log.Printf("Realtime rescan: %d packages", len(depRes.Packages))
			eventData["dependencies"] = structToMap(depRes)
		}

		secRes, err := d.secrets.Scan()
		if err != nil {
			log.Printf("Realtime secrets rescan error: %v", err)
		}
		if secRes != nil {
			log.Printf("Realtime rescan: %d secret finding(s)", len(secRes.Findings))
			eventData["secrets"] = structToMap(secRes)
		}
	}

	// AI assistant configuration and MCP servers.
	if cats[watcher.CategoryAITools] {
		aiRes, err := d.aitools.Scan()
		if err != nil {
			log.Printf("Realtime AI tool rescan error: %v", err)
		}
		if aiRes != nil {
			log.Printf("Realtime rescan: %d AI tool(s)", len(aiRes.Tools))
			eventData["ai_tools"] = structToMap(aiRes)
		}
	}

	if d.apiClient == nil {
		return
	}

	var resp map[string]any
	err := d.withReauth(func() error {
		var callErr error
		resp, callErr = d.apiClient.SubmitRealtimeEvent(eventData)
		return callErr
	})
	if err != nil {
		log.Printf("Failed to submit realtime event: %v", err)
		return
	}
	log.Printf("Realtime event submitted: %v", resp)
}

// categoryList returns the categories present, sorted so log lines and the
// submitted payload are stable rather than varying with map iteration order.
func categoryList(cats map[watcher.Category]bool) []string {
	out := make([]string, 0, len(cats))
	for c := range cats {
		out = append(out, string(c))
	}
	sort.Strings(out)
	return out
}
