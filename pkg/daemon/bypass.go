package daemon

import (
	"encoding/json"
	"log"
	"os"
	"strings"

	"github.com/securient/ideviewer-oss/internal/platform"
)

// checkHookBypasses reads pending hook bypass events from the JSONL file
// written by the pre-commit hook, reports each to the portal, and removes
// the file after processing.
func (d *Daemon) checkHookBypasses() {
	if d.apiClient == nil {
		return
	}

	bypassFile := platform.BypassesPendingFile()

	data, err := os.ReadFile(bypassFile)
	if err != nil {
		return // file does not exist or unreadable -- nothing to do
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		return
	}

	log.Printf("Found %d hook bypass event(s) to report", len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var bypassData map[string]any
		if err := json.Unmarshal([]byte(line), &bypassData); err != nil {
			log.Printf("Invalid bypass event JSON: %.100s", line)
			continue
		}

		if _, err := d.apiClient.SendHookBypass(bypassData); err != nil {
			log.Printf("Failed to report hook bypass: %v", err)
			continue
		}

		commitHash, _ := bypassData["commit_hash"].(string)
		if len(commitHash) > 8 {
			commitHash = commitHash[:8]
		}
		log.Printf("Reported hook bypass: %s", commitHash)
	}

	// Remove the file after processing.
	if err := os.Remove(bypassFile); err != nil && !os.IsNotExist(err) {
		log.Printf("Failed to remove bypass file: %v", err)
	}
}
