package daemon

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
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

// volatileKeys are fields that change on every scan no matter what is
// installed, so including them defeats the whole point of the comparison.
//
// Every scan result embeds the moment it was produced. Hashing it meant each
// cycle's digest differed from the last, hasChanged always returned true, and
// the "no changes detected, skipping portal report" branch in daemon.go was
// unreachable -- every host re-sent its entire inventory every interval
// forever. On a fleet that is the dominant source of portal write load, and it
// is why the portal could only ever show when a report arrived, never whether
// anything had actually changed.
var volatileKeys = map[string]bool{
	"timestamp": true,
}

// computeHash returns a SHA-256 hex digest of a scan result's *content*.
//
// The value is canonicalised first, in three ways, each of which was needed to
// make the comparison mean anything:
//
//   - volatile fields are dropped (see volatileKeys)
//   - re-marshalling through map[string]any makes encoding/json emit object
//     keys in sorted order
//   - arrays are sorted, because an inventory is a set and not a sequence
//
// The last one matters more than it looks. The dependency sub-scanners build
// their package slice by ranging over maps (npm.go, pip.go), and Go randomises
// map iteration order, so two scans of an unchanged machine returned the same
// packages in a different order -- and a different digest -- every time.
func computeHash(v any) string {
	if v == nil {
		return ""
	}
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}

	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		// Not an object we can normalise; hash the raw bytes rather than
		// silently reporting "unchanged", which would suppress real changes.
		h := sha256.Sum256(data)
		return fmt.Sprintf("%x", h)
	}

	canonical, err := json.Marshal(canonicalize(decoded))
	if err != nil {
		h := sha256.Sum256(data)
		return fmt.Sprintf("%x", h)
	}

	h := sha256.Sum256(canonical)
	return fmt.Sprintf("%x", h)
}

// canonicalize removes volatile keys and sorts arrays, at every depth -- so a
// timestamp added to a nested struct, or a new map-ordered slice, cannot
// quietly re-break the comparison.
func canonicalize(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if volatileKeys[k] {
				continue
			}
			out[k] = canonicalize(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = canonicalize(val)
		}
		// Sort by each element's encoded form: a total order that works for
		// mixed types, and stable because the elements are already canonical.
		sort.Slice(out, func(i, j int) bool {
			a, _ := json.Marshal(out[i])
			b, _ := json.Marshal(out[j])
			return string(a) < string(b)
		})
		return out
	default:
		return v
	}
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
