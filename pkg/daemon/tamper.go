package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/securient/ideviewer-oss/internal/config"
	"github.com/securient/ideviewer-oss/internal/platform"
)

// tamperState holds the file checksums used for tamper detection.
var tamperState struct {
	mu             sync.Mutex
	criticalFiles  []string
	fileChecksums  map[string]string
}

// initTamperDetection builds the list of critical files and records their
// SHA-256 checksums so that subsequent calls to checkTamper can detect
// modifications or deletions.
func (d *Daemon) initTamperDetection() {
	tamperState.mu.Lock()
	defer tamperState.mu.Unlock()

	tamperState.criticalFiles = getCriticalFiles()
	tamperState.fileChecksums = computeFileChecksums(tamperState.criticalFiles)

	log.Printf("Tamper detection initialised: tracking %d critical file(s)", len(tamperState.criticalFiles))
}

// checkTamper compares the current state of critical files against the stored
// baselines and reports deletions or modifications to the portal.
func (d *Daemon) checkTamper() {
	tamperState.mu.Lock()
	defer tamperState.mu.Unlock()

	for _, path := range tamperState.criticalFiles {
		info, err := os.Stat(path)
		if err != nil || info == nil {
			// File was deleted.
			if _, tracked := tamperState.fileChecksums[path]; tracked {
				log.Printf("TAMPER: Critical file deleted: %s", path)
				d.sendTamperAlert("file_deleted",
					fmt.Sprintf("Critical daemon file was deleted: %s. "+
						"This may indicate an uninstall attempt.", path))
				delete(tamperState.fileChecksums, path)
			}
			continue
		}

		currentHash := hashFile(path)
		if currentHash == "" {
			continue
		}

		storedHash, tracked := tamperState.fileChecksums[path]
		if tracked && currentHash != storedHash {
			log.Printf("TAMPER: Critical file modified: %s", path)
			d.sendTamperAlert("file_modified",
				fmt.Sprintf("Critical daemon file was modified: %s. "+
					"Expected hash: %s..., current: %s...",
					path, storedHash[:16], currentHash[:16]))
			tamperState.fileChecksums[path] = currentHash
		} else if !tracked {
			// New file appeared; start tracking.
			tamperState.fileChecksums[path] = currentHash
		}
	}
}

// sendTamperAlert is a convenience wrapper around the API client.
func (d *Daemon) sendTamperAlert(alertType, details string) {
	if d.apiClient == nil {
		return
	}
	if _, err := d.apiClient.SendTamperAlert(alertType, details); err != nil {
		log.Printf("Failed to send tamper alert: %v", err)
	}
}

// getCriticalFiles returns the paths of files to monitor for tampering.
func getCriticalFiles() []string {
	var files []string

	addIfExists := func(p string) {
		if p == "" {
			return
		}
		if _, err := os.Stat(p); err == nil {
			files = append(files, p)
		}
	}

	// The installed binary.
	addIfExists(platform.BinaryInstallPath())

	// The daemon service file (launchd plist or systemd unit).
	addIfExists(platform.ServiceFilePath())

	// The config file.
	addIfExists(config.Path())

	// Uninstaller (macOS/Linux).
	if platform.IsMacOS() || platform.IsLinux() {
		addIfExists("/usr/local/bin/ideviewer-uninstall")
	}

	return files
}

// computeFileChecksums returns a map of path -> SHA-256 hex digest.
func computeFileChecksums(paths []string) map[string]string {
	checksums := make(map[string]string, len(paths))
	for _, p := range paths {
		h := hashFile(p)
		if h != "" {
			checksums[p] = h
		}
	}
	return checksums
}

// hashFile returns the SHA-256 hex digest of the file at path, or "" on error.
func hashFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
