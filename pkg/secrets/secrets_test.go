package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckEthPrivateKey_HexWithout0x(t *testing.T) {
	hexKey := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	finding := checkEthPrivateKey("test.env", "ETH_PRIVATE_KEY", hexKey, 1)
	if finding == nil {
		t.Fatal("expected finding, got nil")
	}
	if finding.SecretType != "ethereum_private_key" {
		t.Errorf("SecretType = %q, want %q", finding.SecretType, "ethereum_private_key")
	}
	if finding.Severity != "critical" {
		t.Errorf("Severity = %q, want %q", finding.Severity, "critical")
	}
}

func TestCheckEthPrivateKey_HexWith0xPrefix(t *testing.T) {
	hexKey := "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	finding := checkEthPrivateKey("test.env", "PRIVATE_KEY", hexKey, 1)
	if finding == nil {
		t.Fatal("expected finding, got nil")
	}
	if finding.SecretType != "ethereum_private_key" {
		t.Errorf("SecretType = %q, want %q", finding.SecretType, "ethereum_private_key")
	}
}

func TestCheckEthPrivateKey_NoMatchWrongName(t *testing.T) {
	hexKey := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	finding := checkEthPrivateKey("test.env", "DATABASE_URL", hexKey, 1)
	if finding != nil {
		t.Error("expected nil finding for non-matching variable name")
	}
}

func TestCheckEthPrivateKey_NoMatchWrongValue(t *testing.T) {
	finding := checkEthPrivateKey("test.env", "ETH_PRIVATE_KEY", "not-a-hex-key", 1)
	if finding != nil {
		t.Error("expected nil finding for non-hex value")
	}
}

func TestCheckAWSAccessKey(t *testing.T) {
	finding := checkAWSCredentials("test.env", "AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE", 1)
	if finding == nil {
		t.Fatal("expected finding, got nil")
	}
	if finding.SecretType != "aws_access_key" {
		t.Errorf("SecretType = %q, want %q", finding.SecretType, "aws_access_key")
	}
	if finding.Severity != "high" {
		t.Errorf("Severity = %q, want %q", finding.Severity, "high")
	}
}

func TestCheckAWSSecretKey(t *testing.T) {
	// 40-char base64-compatible string
	secretKey := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	finding := checkAWSCredentials("test.env", "AWS_SECRET_ACCESS_KEY", secretKey, 1)
	if finding == nil {
		t.Fatal("expected finding, got nil")
	}
	if finding.SecretType != "aws_secret_key" {
		t.Errorf("SecretType = %q, want %q", finding.SecretType, "aws_secret_key")
	}
	if finding.Severity != "critical" {
		t.Errorf("Severity = %q, want %q", finding.Severity, "critical")
	}
}

func TestCheckAWSAccessKey_NoMatch(t *testing.T) {
	finding := checkAWSCredentials("test.env", "AWS_ACCESS_KEY_ID", "not-a-valid-key", 1)
	if finding != nil {
		t.Error("expected nil finding for invalid AWS key")
	}
}

func TestCheckMnemonic_12Words(t *testing.T) {
	mnemonic := "abandon ability able about above absent absorb abstract absurd abuse access accident"
	finding := checkMnemonic("test.env", "MNEMONIC", mnemonic, 1)
	if finding == nil {
		t.Fatal("expected finding, got nil")
	}
	if finding.SecretType != "mnemonic_seed_phrase" {
		t.Errorf("SecretType = %q, want %q", finding.SecretType, "mnemonic_seed_phrase")
	}
	if finding.Severity != "critical" {
		t.Errorf("Severity = %q, want %q", finding.Severity, "critical")
	}
}

func TestCheckMnemonic_24Words(t *testing.T) {
	words := make([]string, 24)
	for i := range words {
		words[i] = "abandon"
	}
	mnemonic := strings.Join(words, " ")
	finding := checkMnemonic("test.env", "SEED_PHRASE", mnemonic, 1)
	if finding == nil {
		t.Fatal("expected finding, got nil")
	}
	if finding.SecretType != "mnemonic_seed_phrase" {
		t.Errorf("SecretType = %q, want %q", finding.SecretType, "mnemonic_seed_phrase")
	}
}

func TestCheckMnemonic_WrongWordCount(t *testing.T) {
	mnemonic := "abandon ability able about above"
	finding := checkMnemonic("test.env", "MNEMONIC", mnemonic, 1)
	if finding != nil {
		t.Error("expected nil finding for wrong word count")
	}
}

func TestCheckMnemonic_WrongKeyName(t *testing.T) {
	mnemonic := "abandon ability able about above absent absorb abstract absurd abuse access accident"
	finding := checkMnemonic("test.env", "DATABASE_URL", mnemonic, 1)
	if finding != nil {
		t.Error("expected nil finding for non-mnemonic key name")
	}
}

func TestRedactValue(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"ab", "**"},
		{"abcde", "ab***"},
		{"abcdefghijk", "abcd***hijk"},
		{"abcdefghijklmnop", "abcd********mnop"},
	}

	for _, tt := range tests {
		got := redactValue(tt.input)
		if got != tt.want {
			t.Errorf("redactValue(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNewSecretsResult_ComputesTotals(t *testing.T) {
	findings := []SecretFinding{
		{SecretType: "ethereum_private_key", Severity: "critical"},
		{SecretType: "aws_access_key", Severity: "high"},
		{SecretType: "aws_secret_key", Severity: "critical"},
	}

	result := NewSecretsResult(findings, []string{"/path/1"}, nil)

	if result.TotalFindings != 3 {
		t.Errorf("TotalFindings = %d, want 3", result.TotalFindings)
	}
	if result.CriticalCount != 2 {
		t.Errorf("CriticalCount = %d, want 2", result.CriticalCount)
	}
	if len(result.ScannedPaths) != 1 {
		t.Errorf("ScannedPaths length = %d, want 1", len(result.ScannedPaths))
	}
	if result.Timestamp == "" {
		t.Error("Timestamp should not be empty")
	}
}

func TestNewSecretsResult_Empty(t *testing.T) {
	result := NewSecretsResult(nil, nil, []string{"err1"})
	if result.TotalFindings != 0 {
		t.Errorf("TotalFindings = %d, want 0", result.TotalFindings)
	}
	if result.CriticalCount != 0 {
		t.Errorf("CriticalCount = %d, want 0", result.CriticalCount)
	}
	if len(result.Errors) != 1 {
		t.Errorf("Errors length = %d, want 1", len(result.Errors))
	}
}

func TestScanEnvFile(t *testing.T) {
	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, ".env")

	content := `# Comment line
DATABASE_URL=postgres://localhost/db
ETH_PRIVATE_KEY=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
EMPTY_VAR=
`
	if err := os.WriteFile(envFile, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	s := &Scanner{MaxDepth: 5, ScanHidden: false, HomeDir: tmpDir}
	result := &SecretsResult{}
	s.scanEnvFile(envFile, result)

	if len(result.Findings) != 2 {
		t.Fatalf("Findings length = %d, want 2 (eth key + aws key)", len(result.Findings))
	}

	foundTypes := make(map[string]bool)
	for _, f := range result.Findings {
		foundTypes[f.SecretType] = true
		if f.LineNumber == 0 {
			t.Errorf("LineNumber should be > 0 for finding type %s", f.SecretType)
		}
	}
	if !foundTypes["ethereum_private_key"] {
		t.Error("expected to find ethereum_private_key")
	}
	if !foundTypes["aws_access_key"] {
		t.Error("expected to find aws_access_key")
	}

	if len(result.ScannedPaths) != 1 {
		t.Errorf("ScannedPaths length = %d, want 1", len(result.ScannedPaths))
	}
}

func TestParseEnvLine(t *testing.T) {
	tests := []struct {
		line    string
		wantKey string
		wantVal string
	}{
		{`KEY=value`, "KEY", "value"},
		{`KEY="quoted value"`, "KEY", "quoted value"},
		{`KEY='single quoted'`, "KEY", "single quoted"},
		{`KEY=`, "KEY", ""},
		{`no-equals`, "", ""},
	}

	for _, tt := range tests {
		key, val := parseEnvLine(tt.line)
		if key != tt.wantKey || val != tt.wantVal {
			t.Errorf("parseEnvLine(%q) = (%q, %q), want (%q, %q)", tt.line, key, val, tt.wantKey, tt.wantVal)
		}
	}
}
