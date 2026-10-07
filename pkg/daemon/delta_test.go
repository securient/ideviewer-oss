package daemon

import "testing"

// The regression this guards: every scan result embeds the moment it was
// produced, so hashing the struct whole made each cycle's digest differ from
// the last. hasChanged always returned true, the "skipping portal report"
// branch was unreachable, and every host re-sent its full inventory every
// interval regardless of whether anything had changed.
func TestHashIgnoresScanTimestamp(t *testing.T) {
	type res struct {
		Timestamp string   `json:"timestamp"`
		Total     int      `json:"total"`
		Names     []string `json:"names"`
	}
	earlier := res{Timestamp: "2026-10-05T22:19:00Z", Total: 24, Names: []string{"a", "b"}}
	later := res{Timestamp: "2026-10-05T22:49:00Z", Total: 24, Names: []string{"a", "b"}}

	if computeHash(earlier) != computeHash(later) {
		t.Error("identical inventory scanned at different times must hash the same")
	}
}

func TestHashStillDetectsRealChanges(t *testing.T) {
	type pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	type res struct {
		Timestamp string `json:"timestamp"`
		Packages  []pkg  `json:"packages"`
	}
	base := res{Timestamp: "2026-10-05T22:19:00Z", Packages: []pkg{{"left-pad", "1.3.0"}}}

	cases := []struct {
		name string
		got  res
	}{
		{"added package", res{Timestamp: "2026-10-05T22:49:00Z", Packages: []pkg{{"left-pad", "1.3.0"}, {"evil", "6.6.6"}}}},
		{"removed package", res{Timestamp: "2026-10-05T22:49:00Z", Packages: nil}},
		{"version bump", res{Timestamp: "2026-10-05T22:49:00Z", Packages: []pkg{{"left-pad", "1.3.1"}}}},
		{"renamed package", res{Timestamp: "2026-10-05T22:49:00Z", Packages: []pkg{{"right-pad", "1.3.0"}}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if computeHash(base) == computeHash(c.got) {
				t.Errorf("%s must change the hash", c.name)
			}
		})
	}
}

// A timestamp added to a nested struct later must not quietly re-break the
// comparison, which is why the strip recurses rather than touching only the
// top level.
func TestHashIgnoresNestedTimestamps(t *testing.T) {
	type inner struct {
		Timestamp string `json:"timestamp"`
		Name      string `json:"name"`
	}
	type outer struct {
		Timestamp string  `json:"timestamp"`
		Items     []inner `json:"items"`
	}
	a := outer{Timestamp: "t1", Items: []inner{{Timestamp: "t1", Name: "ext"}}}
	b := outer{Timestamp: "t2", Items: []inner{{Timestamp: "t2", Name: "ext"}}}

	if computeHash(a) != computeHash(b) {
		t.Error("nested timestamps must be ignored too")
	}
}

func TestHashIsStableAcrossCalls(t *testing.T) {
	v := map[string]any{"b": 2, "a": 1, "c": []any{"x", "y"}}
	first := computeHash(v)
	for i := 0; i < 20; i++ {
		if computeHash(v) != first {
			t.Fatal("hash is not stable across calls; map ordering is leaking into the digest")
		}
	}
}

func TestHashHandlesNilAndEmpty(t *testing.T) {
	if computeHash(nil) != "" {
		t.Error("nil must hash to the empty string, which hasChanged treats as no result")
	}
	if computeHash(map[string]any{}) == "" {
		t.Error("an empty object is a real result and must produce a digest")
	}
}

// The end-to-end behaviour the fix exists for: a second scan that finds the
// same inventory must report no change, so the daemon skips the report.
func TestUnchangedSecondScanDoesNotReportChanged(t *testing.T) {
	type res struct {
		Timestamp string `json:"timestamp"`
		Total     int    `json:"total"`
	}
	s := &scanHashes{}

	first := computeHash(res{Timestamp: "2026-10-05T22:19:00Z", Total: 24})
	if !s.hasChanged("ide", first) {
		t.Fatal("the first scan of a run must count as a change")
	}

	second := computeHash(res{Timestamp: "2026-10-05T22:49:00Z", Total: 24})
	if s.hasChanged("ide", second) {
		t.Error("an unchanged second scan must not count as a change")
	}

	third := computeHash(res{Timestamp: "2026-10-05T23:19:00Z", Total: 25})
	if !s.hasChanged("ide", third) {
		t.Error("a genuine inventory change must still be detected")
	}
}

// The dependency sub-scanners build their package slice by ranging over maps,
// and Go randomises map iteration order. Two scans of an unchanged machine
// therefore returned the same packages in a different order every time, which
// defeated content hashing just as thoroughly as the timestamp did.
func TestHashIgnoresArrayOrder(t *testing.T) {
	type pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	type res struct {
		Managers []string `json:"package_managers_found"`
		Packages []pkg    `json:"packages"`
	}
	a := res{
		Managers: []string{"pip", "npm", "poetry"},
		Packages: []pkg{{"dompurify", "3.4.11"}, {"fuse.js", "7.0.0"}},
	}
	b := res{
		Managers: []string{"poetry", "pip", "npm"},
		Packages: []pkg{{"fuse.js", "7.0.0"}, {"dompurify", "3.4.11"}},
	}

	if computeHash(a) != computeHash(b) {
		t.Error("the same inventory in a different order must hash the same")
	}
}

// Order-insensitivity must not hide a membership change.
func TestHashDetectsChangeDespiteReordering(t *testing.T) {
	a := map[string]any{"packages": []any{"left-pad", "lodash"}}
	b := map[string]any{"packages": []any{"lodash", "evil"}}

	if computeHash(a) == computeHash(b) {
		t.Error("a swapped member is a real change even though the length matches")
	}
}
