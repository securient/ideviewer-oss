package shiftleft

import "testing"

func TestCheckExtension_BannedID(t *testing.T) {
	w := CheckExtension("ms-vscode.example-malware", "ms-vscode", "x")
	if len(w) == 0 || w[0].IndicatorType != "banned_extension" {
		t.Fatalf("expected banned_extension warning, got %+v", w)
	}
	if w[0].Severity != "critical" {
		t.Errorf("banned extension should be critical, got %q", w[0].Severity)
	}
}

func TestCheckExtension_MaliciousPublisher(t *testing.T) {
	w := CheckExtension("evilcorp.tool", "", "")
	found := false
	for _, x := range w {
		if x.IndicatorType == "malicious_publisher" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected malicious_publisher warning, got %+v", w)
	}
}

func TestCheckExtension_Typosquat(t *testing.T) {
	w := CheckExtension("ms-python.pythonn", "ms-python", "Python")
	if len(w) == 0 || w[0].IndicatorType != "typosquat" {
		t.Fatalf("expected typosquat warning, got %+v", w)
	}
}

func TestCheckExtension_LegitTargetClean(t *testing.T) {
	if w := CheckExtension("ms-python.python", "ms-python", "Python"); len(w) != 0 {
		t.Errorf("legit extension should be clean, got %+v", w)
	}
}

func TestCheckExtension_UnrelatedClean(t *testing.T) {
	if w := CheckExtension("acme.totally-unrelated", "acme", "x"); len(w) != 0 {
		t.Errorf("unrelated extension should be clean, got %+v", w)
	}
}

func TestFeedVersionEmbedded(t *testing.T) {
	if FeedVersion() == "" || FeedVersion() == "embedded-empty" {
		t.Errorf("embedded feed should have a real version, got %q", FeedVersion())
	}
}

func TestLevenshtein(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"abc", "abc", 0},
		{"abc", "abd", 1},
		{"abc", "ab", 1},
		{"", "abc", 3},
	}
	for _, c := range cases {
		if got := levenshtein(c.a, c.b); got != c.want {
			t.Errorf("levenshtein(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}
