package secrets

import "time"

// SecretFinding represents a single detected secret.
type SecretFinding struct {
	FilePath       string `json:"file_path"`
	SecretType     string `json:"secret_type"`
	VariableName   string `json:"variable_name,omitempty"`
	LineNumber     int    `json:"line_number,omitempty"`
	Severity       string `json:"severity"`
	Description    string `json:"description"`
	Recommendation string `json:"recommendation"`
	RedactedValue  string `json:"redacted_value"`
	Source         string `json:"source"` // "filesystem" or "git_history"
	CommitHash     string `json:"commit_hash,omitempty"`
	CommitAuthor   string `json:"commit_author,omitempty"`
	CommitDate     string `json:"commit_date,omitempty"`
	RepoPath       string `json:"repo_path,omitempty"`
}

// SecretsResult holds the complete result of a secrets scan.
type SecretsResult struct {
	Timestamp     string          `json:"timestamp"`
	Findings      []SecretFinding `json:"findings"`
	TotalFindings int             `json:"total_findings"`
	CriticalCount int             `json:"critical_count"`
	ScannedPaths  []string        `json:"scanned_paths"`
	Errors        []string        `json:"errors"`
}

// NewSecretsResult creates a SecretsResult with computed totals.
func NewSecretsResult(findings []SecretFinding, scannedPaths []string, errors []string) *SecretsResult {
	critical := 0
	for _, f := range findings {
		if f.Severity == "critical" {
			critical++
		}
	}
	return &SecretsResult{
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Findings:      findings,
		TotalFindings: len(findings),
		CriticalCount: critical,
		ScannedPaths:  scannedPaths,
		Errors:        errors,
	}
}
