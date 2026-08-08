package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testHex64 = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

// TestVarNameMatching_ConventionInsensitive is the regression test for the
// underscore-sensitive Contains match: only the SCREAMING_SNAKE spelling of a
// pattern ever matched, so camelCase/PascalCase/kebab-case variables were
// silently skipped no matter how obviously secret their values were.
func TestVarNameMatching_ConventionInsensitive(t *testing.T) {
	names := []string{
		"PRIVATE_KEY", // canonical
		"privateKey",  // camelCase
		"PrivateKey",  // PascalCase
		"private-key", // kebab-case
		"privatekey",  // flat
		"private.key", // dotted
		"WALLET_PRIVATE_KEY",
		"walletPrivateKey",
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			finding := checkEthPrivateKey("test.env", name, testHex64, 1)
			if finding == nil {
				t.Fatalf("checkEthPrivateKey(%q) = nil, want a finding", name)
			}
			if finding.SecretType != "ethereum_private_key" {
				t.Errorf("SecretType = %q, want ethereum_private_key", finding.SecretType)
			}
			if finding.VariableName != name {
				t.Errorf("VariableName = %q, want %q (original spelling must survive)", finding.VariableName, name)
			}
		})
	}
}

func TestVarNameMatching_StillRejectsUnrelatedNames(t *testing.T) {
	for _, name := range []string{"DATABASE_URL", "LOG_LEVEL", "targetScope", "MAX_RETRIES"} {
		if f := checkEthPrivateKey("test.env", name, testHex64, 1); f != nil {
			t.Errorf("checkEthPrivateKey(%q) = %v, want nil", name, f.SecretType)
		}
	}
}

func TestNormalizeVarName(t *testing.T) {
	tests := []struct{ in, want string }{
		{"PRIVATE_KEY", "PRIVATEKEY"},
		{"privateKey", "PRIVATEKEY"},
		{"private-key", "PRIVATEKEY"},
		{"private.key", "PRIVATEKEY"},
		{"AWS_SECRET_ACCESS_KEY", "AWSSECRETACCESSKEY"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := normalizeVarName(tt.in); got != tt.want {
			t.Errorf("normalizeVarName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestAWSAccessKey_NameIndependent covers the second half of the name bug: AWS
// detection gated on the literal substring "AWS", so the ordinary AccessKeyID
// and ACCESS_KEY_ID spellings could never match regardless of value.
func TestAWSAccessKey_NameIndependent(t *testing.T) {
	// Split so the literal never appears contiguously in source: these are
	// synthetic fixtures, but GitHub push protection and secret scanners match
	// on raw file content and cannot tell them from live credentials.
	const validAccessKey = "AKIA" + "IOSFODNN7ZQR4TWA"

	for _, name := range []string{"AWS_ACCESS_KEY_ID", "AccessKeyID", "ACCESS_KEY_ID", "accessKeyId"} {
		t.Run(name, func(t *testing.T) {
			finding := checkAWSCredentials("test.env", name, validAccessKey, 1)
			if finding == nil {
				t.Fatalf("checkAWSCredentials(%q) = nil, want aws_access_key", name)
			}
			if finding.SecretType != "aws_access_key" {
				t.Errorf("SecretType = %q, want aws_access_key", finding.SecretType)
			}
		})
	}
}

func TestAWSSecretKey_AcceptsCommonSpellings(t *testing.T) {
	const validSecret = "wJalrXUtnFEMI/K7MDENG" + "/bPxRfiCYzWQR4TWAbc" // gitleaks:allow — synthetic fixture

	if len(validSecret) != 40 {
		t.Fatalf("test fixture must be exactly 40 chars, got %d", len(validSecret))
	}

	for _, name := range []string{"AWS_SECRET_ACCESS_KEY", "SecretAccessKey", "SECRET_ACCESS_KEY"} {
		t.Run(name, func(t *testing.T) {
			finding := checkAWSCredentials("test.env", name, validSecret, 1)
			if finding == nil {
				t.Fatalf("checkAWSCredentials(%q) = nil, want aws_secret_key", name)
			}
			if finding.SecretType != "aws_secret_key" {
				t.Errorf("SecretType = %q, want aws_secret_key", finding.SecretType)
			}
		})
	}
}

// TestAWSSecretKey_StillNeedsCredentialName guards the false-positive floor:
// the 40-char regex is loose, so an unrelated variable must not trip it.
func TestAWSSecretKey_StillNeedsCredentialName(t *testing.T) {
	const fortyChars = "wJalrXUtnFEMI/K7MDENG" + "/bPxRfiCYzWQR4TWAbc"
	if f := checkAWSCredentials("test.env", "BUILD_FINGERPRINT", fortyChars, 1); f != nil {
		t.Errorf("expected nil for non-credential name, got %s", f.SecretType)
	}
}

func TestCheckAPIToken_VendorFormats(t *testing.T) {
	tests := []struct {
		name     string
		varName  string
		value    string
		wantType string
		wantSev  string
	}{
		{"anthropic", "ANTHROPIC_API_KEY", "sk-ant-api03-" + strings.Repeat("a1B2c3D4", 11), "anthropic_api_key", "critical"},
		{"openai", "OPENAI_API_KEY", "sk-" + strings.Repeat("aB3d", 12), "openai_api_key", "critical"},
		{"openai project", "OPENAI_API_KEY", "sk-proj-" + strings.Repeat("aB3d", 12), "openai_api_key", "critical"},
		{"github classic", "GITHUB_TOKEN", "ghp_" + strings.Repeat("aB3d", 9), "github_token", "critical"},
		{"github fine grained", "GITHUB_TOKEN", "github_pat_" + strings.Repeat("aB3d1", 12), "github_fine_grained_token", "critical"},
		{"gitlab", "GITLAB_TOKEN", "glpat-" + strings.Repeat("aB3d", 6), "gitlab_token", "critical"},
		{"slack", "SLACK_BOT_TOKEN", "xoxb-" + "123456789012-123456789012-aBcDeFgHiJkLmNoP", "slack_token", "high"},
		{"stripe live", "STRIPE_KEY", "sk_live_" + strings.Repeat("aB3d", 8), "stripe_live_key", "critical"},
		{"google", "GOOGLE_API_KEY", "AIza" + strings.Repeat("aB3d1", 7), "google_api_key", "high"},
		{"npm", "NPM_TOKEN", "npm_" + strings.Repeat("aB3d", 9), "npm_token", "high"},
		{"telegram", "TELEGRAM_BOT_TOKEN", "123456789:" + strings.Repeat("aB3d1", 7), "telegram_bot_token", "high"},
		{"jwt", "SESSION_JWT", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r", "jwt", "high"}, // gitleaks:allow — synthetic fixture
		{"pem", "SSH_KEY", "-----BEGIN RSA PRIVATE KEY-----", "private_key_pem", "critical"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := checkAPIToken("test.env", tt.varName, tt.value, 1)
			if finding == nil {
				t.Fatalf("checkAPIToken(%q) = nil, want %s", tt.varName, tt.wantType)
			}
			if finding.SecretType != tt.wantType {
				t.Errorf("SecretType = %q, want %q", finding.SecretType, tt.wantType)
			}
			if finding.Severity != tt.wantSev {
				t.Errorf("Severity = %q, want %q", finding.Severity, tt.wantSev)
			}
			if strings.Contains(finding.RedactedValue, tt.value[:8]) {
				t.Errorf("RedactedValue %q leaks plaintext", finding.RedactedValue)
			}
		})
	}
}

// TestCheckAPIToken_AnthropicBeatsOpenAI pins the ordering dependency: sk-ant-
// also satisfies the broader sk- pattern, so it must be tried first.
func TestCheckAPIToken_AnthropicBeatsOpenAI(t *testing.T) {
	value := "sk-ant-api03-" + strings.Repeat("a1B2c3D4", 11)
	finding := checkAPIToken("test.env", "KEY", value, 1)
	if finding == nil {
		t.Fatal("expected a finding")
	}
	if finding.SecretType != "anthropic_api_key" {
		t.Errorf("SecretType = %q, want anthropic_api_key (pattern order regression)", finding.SecretType)
	}
}

func TestCheckAPIToken_GenericNameAndEntropy(t *testing.T) {
	// No recognised vendor prefix, but a credential-shaped name and a
	// high-entropy 32-char value — the SHODAN_API_KEY / BURP_API_KEY shape.
	finding := checkAPIToken("test.env", "SHODAN_API_KEY", "kQ7bZ2mX9pL4vR8tN3wY6cH1jF5gD0sA", 1) // gitleaks:allow — synthetic fixture
	if finding == nil {
		t.Fatal("expected api_credential finding")
	}
	if finding.SecretType != "api_credential" {
		t.Errorf("SecretType = %q, want api_credential", finding.SecretType)
	}
}

func TestCheckAPIToken_NoFalsePositives(t *testing.T) {
	tests := []struct {
		name    string
		varName string
		value   string
	}{
		{"non-credential name", "LOG_LEVEL", "kQ7bZ2mX9pL4vR8tN3wY6cH1jF5gD0sA"},
		{"model identifier", "ANTHROPIC_MODEL", "claude-opus-4-20250514"},
		{"api url not key", "BURP_API_URL", "https://burp.internal:1337"},
		{"too short", "API_KEY", "abc123"},
		{"low entropy", "API_KEY", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{"placeholder", "API_KEY", "your-api-key-here-replace-me-now"},
		{"example marker", "API_KEY", "sk-EXAMPLEEXAMPLEEXAMPLEEXAMPLE12"},
		{"templated", "API_KEY", "${SECRETS_MANAGER_API_KEY_VALUE}"},
		{"prose with spaces", "SECRET", "this is a description not a secret value"},
		{"boolean", "REQUIRE_HUMAN_APPROVAL", "true"},
		{"empty", "API_KEY", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if f := checkAPIToken("test.env", tt.varName, tt.value, 1); f != nil {
				t.Errorf("checkAPIToken(%q, %q) = %s, want nil", tt.varName, tt.value, f.SecretType)
			}
		})
	}
}

func TestShannonEntropy(t *testing.T) {
	if e := shannonEntropy(""); e != 0 {
		t.Errorf("entropy of empty string = %v, want 0", e)
	}
	repeated := shannonEntropy(strings.Repeat("a", 32))
	if repeated != 0 {
		t.Errorf("entropy of repeated char = %v, want 0", repeated)
	}
	random := shannonEntropy("kQ7bZ2mX9pL4vR8tN3wY6cH1jF5gD0sA")
	if random < minGenericTokenEntropy {
		t.Errorf("entropy of random token = %v, want >= %v", random, minGenericTokenEntropy)
	}
	if random <= repeated {
		t.Error("random value should have higher entropy than repeated value")
	}
}

// TestScanEnvFile_DetectsTokens is the end-to-end check against a file shaped
// like the ones that scanned clean before this change.
func TestScanEnvFile_DetectsTokens(t *testing.T) {
	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, ".env")

	content := "# Comment\n" +
		"LOG_LEVEL=info\n" +
		"ANTHROPIC_API_KEY=sk-ant-api03-" + strings.Repeat("a1B2c3D4", 11) + "\n" +
		"GITHUB_TOKEN=ghp_" + strings.Repeat("aB3d", 9) + "\n" +
		"SHODAN_API_KEY=kQ7bZ2mX9pL4vR8tN3wY6cH1jF5gD0sA\n" + // gitleaks:allow — synthetic fixture
		"privateKey=" + testHex64 + "\n" +
		"DATABASE_URL=postgres://localhost/db\n"

	if err := os.WriteFile(envFile, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	s := &Scanner{MaxDepth: 5, HomeDir: tmpDir}
	result := &SecretsResult{}
	s.scanEnvFile(envFile, result)

	byType := make(map[string]bool)
	for _, f := range result.Findings {
		byType[f.SecretType] = true
		if f.LineNumber == 0 {
			t.Errorf("finding %s has no line number", f.SecretType)
		}
	}

	for _, want := range []string{"anthropic_api_key", "github_token", "api_credential", "ethereum_private_key"} {
		if !byType[want] {
			t.Errorf("expected a %s finding, got %v", want, byType)
		}
	}
	if len(result.Findings) != 4 {
		t.Errorf("Findings = %d, want 4 (LOG_LEVEL and DATABASE_URL must not match)", len(result.Findings))
	}
}

// TestCheckAPIToken_URLsAreNotCredentials covers the 1Password collision:
// ONEPASSWORD normalizes to a string containing PASSWORD, so endpoint URLs
// stored under such names must not be reported as secrets.
func TestCheckAPIToken_URLsAreNotCredentials(t *testing.T) {
	urls := []struct{ varName, value string }{
		{"ONEPASSWORD_EVENTS_URL", "https://events.1password.com/api"},
		{"ONEPASSWORD_SCIM_URL", "https://scim.1password.com/v2/Users"},
		{"API_KEY_ENDPOINT", "https://vault.internal.corp/v1/secret"},
	}
	for _, u := range urls {
		t.Run(u.varName, func(t *testing.T) {
			if f := checkAPIToken("test.env", u.varName, u.value, 1); f != nil {
				t.Errorf("checkAPIToken(%q) = %s, want nil for a plain URL", u.varName, f.SecretType)
			}
		})
	}
}

// TestCheckAPIToken_URLWithInlineCredentials is the other side of that guard —
// a URL embedding user:pass really is a leaked credential.
func TestCheckAPIToken_URLWithInlineCredentials(t *testing.T) {
	value := "https://admin:kQ7bZ2mX9pL4vR8t@db.internal.corp/prod"
	f := checkAPIToken("test.env", "DATABASE_PASSWORD", value, 1)
	if f == nil {
		t.Fatal("expected a finding for a URL with inline credentials")
	}
	if f.SecretType != "api_credential" {
		t.Errorf("SecretType = %q, want api_credential", f.SecretType)
	}
}

func TestLooksLikeURL(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"https://events.1password.com/api", true},
		{"http://localhost:8080/health", true},
		{"https://admin:secret@host/path", false}, // inline credentials
		{"kQ7bZ2mX9pL4vR8tN3wY6cH1jF5gD0sA", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := looksLikeURL(tt.value); got != tt.want {
			t.Errorf("looksLikeURL(%q) = %v, want %v", tt.value, got, tt.want)
		}
	}
}
