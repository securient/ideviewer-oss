// Package shiftleft moves protection earlier: it checks an extension against
// the threat-intelligence feed at INSTALL time, on the developer's machine,
// before the extension is ever loaded by an IDE.
//
// This is the warn tier (Phase 2 B4): it surfaces a warning and lets the
// developer decide. A blocking tier is gated on the signed feed-push over the
// Phase 1 B1 command channel (so the portal can't silently install a rule that
// bricks installs) — until then the feed is embedded in the binary and kept in
// sync with portal/app/threat_intel.json and rules/threat_intel.json.
package shiftleft

import (
	_ "embed"
	"encoding/json"
	"strings"
)

//go:embed threat_intel.json
var embeddedFeed []byte

// typosquatMaxDistance mirrors portal/app/threat_intel.py.
const typosquatMaxDistance = 2

type feed struct {
	Version             string   `json:"version"`
	MaliciousPublishers []string `json:"malicious_publishers"`
	BannedExtensionIDs  []string `json:"banned_extension_ids"`
	TyposquatTargets    []string `json:"typosquat_targets"`
}

// Warning is one reason an extension looks dangerous to install.
type Warning struct {
	IndicatorType string // banned_extension | malicious_publisher | typosquat
	Indicator     string
	Detail        string
	Severity      string // critical | high
}

var loadedFeed = mustLoad()

func mustLoad() feed {
	var f feed
	if err := json.Unmarshal(embeddedFeed, &f); err != nil {
		return feed{Version: "embedded-empty"}
	}
	return f
}

// FeedVersion returns the embedded threat feed's version.
func FeedVersion() string { return loadedFeed.Version }

func lower(ss []string) map[string]bool {
	out := make(map[string]bool, len(ss))
	for _, s := range ss {
		out[strings.ToLower(strings.TrimSpace(s))] = true
	}
	return out
}

// CheckExtension evaluates an extension id (optionally with an explicit
// publisher) against the embedded threat feed and returns any warnings. Mirrors
// portal/app/threat_intel.py:evaluate_extension so the daemon and portal agree.
func CheckExtension(extensionID, publisher, name string) []Warning {
	var warnings []Warning
	extID := strings.ToLower(strings.TrimSpace(extensionID))
	pub := strings.ToLower(strings.TrimSpace(publisher))
	if pub == "" && strings.Contains(extID, ".") {
		pub = strings.SplitN(extID, ".", 2)[0]
	}

	banned := lower(loadedFeed.BannedExtensionIDs)
	publishers := lower(loadedFeed.MaliciousPublishers)

	if extID != "" && banned[extID] {
		warnings = append(warnings, Warning{
			IndicatorType: "banned_extension", Indicator: extensionID,
			Detail: "Extension id is on the banned-extension threat list.", Severity: "critical",
		})
	}
	if pub != "" && publishers[pub] {
		warnings = append(warnings, Warning{
			IndicatorType: "malicious_publisher", Indicator: publisher,
			Detail: "Publisher '" + pub + "' is flagged as malicious.", Severity: "critical",
		})
	}
	if extID != "" && !banned[extID] {
		for _, target := range loadedFeed.TyposquatTargets {
			t := strings.ToLower(strings.TrimSpace(target))
			if t == extID {
				break // legitimate target itself — not a typosquat
			}
			if d := levenshtein(extID, t); d > 0 && d <= typosquatMaxDistance {
				warnings = append(warnings, Warning{
					IndicatorType: "typosquat", Indicator: extensionID,
					Detail:   "Closely resembles popular extension '" + t + "' — possible typosquat.",
					Severity: "high",
				})
				break
			}
		}
	}
	return warnings
}

// levenshtein is the classic edit distance (small strings).
func levenshtein(a, b string) int {
	if a == b {
		return 0
	}
	ra, rb := []rune(a), []rune(b)
	if len(ra) == 0 {
		return len(rb)
	}
	if len(rb) == 0 {
		return len(ra)
	}
	prev := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur := make([]int, len(rb)+1)
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(rb)]
}
