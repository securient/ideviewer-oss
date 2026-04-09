package daemon

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
)

// scanHashes tracks the last hash of each scan type to detect changes.
type scanHashes struct {
	mu      sync.Mutex
	ide     string
	secrets string
	deps    string
	aitools string
}

// computeHash returns a SHA-256 hex digest of any JSON-serializable value.
func computeHash(v any) string {
	if v == nil {
		return ""
	}
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h)
}

// hasChanged checks if the hash for a given scan type has changed.
// Returns true if changed (and updates the stored hash).
func (s *scanHashes) hasChanged(scanType string, newHash string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	var current *string
	switch scanType {
	case "ide":
		current = &s.ide
	case "secrets":
		current = &s.secrets
	case "deps":
		current = &s.deps
	case "aitools":
		current = &s.aitools
	default:
		return true
	}

	if *current == newHash {
		return false
	}
	*current = newHash
	return true
}
