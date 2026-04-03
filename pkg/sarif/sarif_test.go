package sarif

import (
	"encoding/json"
	"testing"

	"github.com/securient/ideviewer-oss/pkg/scanner"
	"github.com/securient/ideviewer-oss/pkg/secrets"
)

func TestSeverityToSARIFLevel(t *testing.T) {
	tests := []struct {
		severity string
		want     string
	}{
		{"critical", "error"},
		{"high", "error"},
		{"medium", "warning"},
		{"low", "note"},
		{"unknown", "note"},
		{"", "note"},
	}

	for _, tt := range tests {
		got := severityToSARIFLevel(tt.severity)
		if got != tt.want {
			t.Errorf("severityToSARIFLevel(%q) = %q, want %q", tt.severity, got, tt.want)
		}
	}
}

func TestFormatScanResult_ValidSARIF(t *testing.T) {
	scanResult := &scanner.ScanResult{
		Timestamp:       "2024-01-01T00:00:00Z",
		TotalIDEs:       1,
		TotalExtensions: 1,
		IDEs: []scanner.IDE{
			{
				Name: "VS Code",
				Extensions: []scanner.Extension{
					{
						ID:        "evil-ext",
						Name:      "Evil Extension",
						Publisher: "bad-publisher",
						Version:   "1.0.0",
						InstallPath: "/path/to/ext",
						Permissions: []scanner.Permission{
							{Name: "filesystem", Description: "Full filesystem access", IsDangerous: true},
						},
					},
				},
			},
		},
	}

	sarif := FormatScanResult(scanResult, "0.3.0")

	if sarif["$schema"] != sarifSchema {
		t.Errorf("$schema = %v, want %v", sarif["$schema"], sarifSchema)
	}
	if sarif["version"] != sarifVersion {
		t.Errorf("version = %v, want %v", sarif["version"], sarifVersion)
	}

	runs, ok := sarif["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatal("expected 1 run")
	}
	run := runs[0].(map[string]any)

	results, ok := run["results"].([]any)
	if !ok || len(results) != 1 {
		t.Fatal("expected 1 result")
	}

	result := results[0].(map[string]any)
	if result["level"] != "error" {
		t.Errorf("level = %v, want error", result["level"])
	}

	tool := run["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)
	rules := driver["rules"].([]any)
	if len(rules) != 1 {
		t.Errorf("rules length = %d, want 1", len(rules))
	}
}

func TestFormatScanResult_NoFindings(t *testing.T) {
	scanResult := &scanner.ScanResult{
		Timestamp: "2024-01-01T00:00:00Z",
		IDEs: []scanner.IDE{
			{
				Name: "VS Code",
				Extensions: []scanner.Extension{
					{
						ID:   "safe-ext",
						Name: "Safe Extension",
						Permissions: []scanner.Permission{
							{Name: "basic", IsDangerous: false},
						},
					},
				},
			},
		},
	}

	sarif := FormatScanResult(scanResult, "0.3.0")
	runs := sarif["runs"].([]any)
	run := runs[0].(map[string]any)
	results := run["results"].([]any)

	if len(results) != 0 {
		t.Errorf("results length = %d, want 0 (no dangerous permissions)", len(results))
	}
}

func TestFormatSecretsResult_ValidSARIF(t *testing.T) {
	secretsResult := &secrets.SecretsResult{
		Timestamp:     "2024-01-01T00:00:00Z",
		TotalFindings: 2,
		CriticalCount: 1,
		Findings: []secrets.SecretFinding{
			{
				FilePath:       "/path/to/.env",
				SecretType:     "ethereum_private_key",
				VariableName:   "ETH_PRIVATE_KEY",
				LineNumber:     3,
				Severity:       "critical",
				Description:    "Plaintext Ethereum private key detected.",
				Recommendation: "Use encrypted keystores.",
			},
			{
				FilePath:     "/path/to/.env",
				SecretType:   "aws_access_key",
				VariableName: "AWS_ACCESS_KEY_ID",
				LineNumber:   5,
				Severity:     "high",
				Description:  "AWS Access Key ID detected.",
			},
		},
	}

	sarif := FormatSecretsResult(secretsResult, "0.3.0")

	runs := sarif["runs"].([]any)
	run := runs[0].(map[string]any)
	results := run["results"].([]any)

	if len(results) != 2 {
		t.Fatalf("results length = %d, want 2", len(results))
	}

	// First result should be critical -> error level.
	r0 := results[0].(map[string]any)
	if r0["level"] != "error" {
		t.Errorf("result[0] level = %v, want error", r0["level"])
	}

	// Second result should be high -> error level.
	r1 := results[1].(map[string]any)
	if r1["level"] != "error" {
		t.Errorf("result[1] level = %v, want error", r1["level"])
	}

	// Check that locations have line numbers.
	locs := r0["locations"].([]any)
	if len(locs) != 1 {
		t.Fatalf("locations length = %d, want 1", len(locs))
	}
	loc := locs[0].(map[string]any)
	physLoc := loc["physicalLocation"].(map[string]any)
	region := physLoc["region"].(map[string]any)
	if region["startLine"] != 3 {
		t.Errorf("startLine = %v, want 3", region["startLine"])
	}
}

func TestToJSON_ProducesValidJSON(t *testing.T) {
	sarifMap := map[string]any{
		"$schema": sarifSchema,
		"version": sarifVersion,
		"runs":    []any{},
	}

	data, err := ToJSON(sarifMap)
	if err != nil {
		t.Fatalf("ToJSON() error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("produced invalid JSON: %v", err)
	}

	if parsed["$schema"] != sarifSchema {
		t.Errorf("$schema = %v, want %v", parsed["$schema"], sarifSchema)
	}
}

func TestFormatSecretsResult_Empty(t *testing.T) {
	result := &secrets.SecretsResult{
		Timestamp: "2024-01-01T00:00:00Z",
	}

	sarif := FormatSecretsResult(result, "0.3.0")
	runs := sarif["runs"].([]any)
	run := runs[0].(map[string]any)
	results := run["results"].([]any)

	if len(results) != 0 {
		t.Errorf("results length = %d, want 0", len(results))
	}
}
