package secrets

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode"
)

// normalizeVarName upper-cases a variable name and strips the separators that
// distinguish naming conventions, so a single pattern matches PRIVATE_KEY,
// privateKey, PrivateKey, private-key and privatekey alike.
//
// Matching used to be a plain Contains against the upper-cased name, which is
// underscore-sensitive: strings.ToUpper("privateKey") is "PRIVATEKEY", and that
// does not contain the literal "PRIVATE_KEY". Every camelCase, PascalCase and
// kebab-case variable silently missed. checkMnemonic only escaped this because
// its keywords happen to contain no separators.
func normalizeVarName(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		if r == '_' || r == '-' || r == '.' || r == ' ' {
			continue
		}
		b.WriteRune(unicode.ToUpper(r))
	}
	return b.String()
}

// varNameMatches reports whether a variable name contains any of the patterns,
// comparing both sides in normalized form.
func varNameMatches(name string, patterns []string) bool {
	norm := normalizeVarName(name)
	for _, p := range patterns {
		if strings.Contains(norm, normalizeVarName(p)) {
			return true
		}
	}
	return false
}

// shannonEntropy returns the per-character Shannon entropy of s in bits. Used
// to separate real credential material from short, structured config values.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var e float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}

// privateKeyVarNames are variable names commonly used for private keys.
var privateKeyVarNames = []string{
	"PRIVATE_KEY",
	"PRIV_KEY",
	"ETH_PRIVATE_KEY",
	"ETHEREUM_PRIVATE_KEY",
	"WALLET_PRIVATE_KEY",
	"DEPLOYER_PRIVATE_KEY",
	"DEPLOYER_KEY",
	"OWNER_PRIVATE_KEY",
	"SIGNER_PRIVATE_KEY",
	"MNEMONIC",
	"SEED_PHRASE",
	"SECRET_KEY",
	"WALLET_KEY",
	"ACCOUNT_KEY",
}

// mnemonicKeywords are keywords in variable names that suggest a mnemonic.
var mnemonicKeywords = []string{"MNEMONIC", "SEED", "PHRASE", "WORDS"}

// Compiled regex patterns.
var (
	ethHex64Re     = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	awsAccessKeyRe = regexp.MustCompile(`^(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}$`)
	awsSecretKeyRe = regexp.MustCompile(`^[a-zA-Z0-9+/]{40}$`)
)

// redactValue produces a non-reversible placeholder for a detected secret.
//
// It deliberately reveals NO plaintext characters — only a fixed mask and a
// coarse length class. The previous implementation exposed the first and last
// four characters plus the exact length, which leaks recoverable material for
// structured / fixed-prefix secrets (e.g. AWS access keys) and aids
// brute-force/correlation. The portal only needs enough to display and
// de-duplicate a finding, never the value itself.
func redactValue(value string) string {
	n := len(value)
	if n == 0 {
		return ""
	}
	var class string
	switch {
	case n < 16:
		class = "short"
	case n < 40:
		class = "medium"
	case n < 80:
		class = "long"
	default:
		class = "very long"
	}
	return "[redacted · " + class + "]"
}

// checkEthPrivateKey checks if a key/value pair looks like an Ethereum private key.
func checkEthPrivateKey(filePath, key, value string, lineNum int) *SecretFinding {
	isKeyNameMatch := varNameMatches(key, privateKeyVarNames)

	// Check if value looks like a private key (64 hex chars).
	valueClean := strings.TrimPrefix(strings.TrimPrefix(value, "0x"), "0X")
	isHex64 := ethHex64Re.MatchString(valueClean)

	// Only flag if BOTH the name and value match to reduce false positives.
	if isKeyNameMatch && isHex64 {
		return &SecretFinding{
			FilePath:       filePath,
			SecretType:     "ethereum_private_key",
			VariableName:   key,
			LineNumber:     lineNum,
			Severity:       "critical",
			Description:    "Plaintext Ethereum/EVM private key detected. This key can be used to sign transactions and drain funds from the associated wallet.",
			Recommendation: "Use encrypted keystores (e.g., Foundry's 'cast wallet import') or hardware wallets for production deployments. Never store private keys in plaintext.",
			RedactedValue:  redactValue(value),
			Source:         "filesystem",
		}
	}
	return nil
}

// checkMnemonic checks if a key/value pair looks like a mnemonic/seed phrase.
func checkMnemonic(filePath, key, value string, lineNum int) *SecretFinding {
	if !varNameMatches(key, mnemonicKeywords) {
		return nil
	}

	words := strings.Fields(value)
	if len(words) != 12 && len(words) != 24 {
		return nil
	}
	for _, w := range words {
		for _, c := range w {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
				return nil
			}
		}
	}

	// Never echo any of the actual words — that alone can be enough to
	// recover or confirm a seed phrase. Report the word count only.
	return &SecretFinding{
		FilePath:       filePath,
		SecretType:     "mnemonic_seed_phrase",
		VariableName:   key,
		LineNumber:     lineNum,
		Severity:       "critical",
		Description:    "Plaintext mnemonic/seed phrase detected. This can be used to derive all wallet keys and drain all associated funds.",
		Recommendation: "Use encrypted keystores or hardware wallets. Never store seed phrases in plaintext files.",
		RedactedValue:  fmt.Sprintf("[redacted · %d-word seed phrase]", len(words)),
		Source:         "filesystem",
	}
}

// awsSecretVarNames are the variable names that gate AWS secret-key detection.
// The secret-key regex alone (40 base64-ish chars) is far too loose to flag on
// its own, so the name still has to look the part — but it no longer has to
// contain the literal "AWS", which the very common SecretAccessKey /
// SECRET_ACCESS_KEY spellings do not.
var awsSecretVarNames = []string{
	"AWS_SECRET",
	"SECRET_ACCESS_KEY",
}

// checkAWSCredentials checks for AWS credentials.
func checkAWSCredentials(filePath, key, value string, lineNum int) *SecretFinding {
	// The access-key ID format (a fixed AKIA/ASIA/AROA-style prefix plus 16
	// upper-case alphanumerics) is distinctive enough to match on value alone.
	// Requiring "AWS" in the name meant AccessKeyID and ACCESS_KEY_ID — both
	// ordinary spellings — could never be detected no matter the value.
	if awsAccessKeyRe.MatchString(value) {
		return &SecretFinding{
			FilePath:       filePath,
			SecretType:     "aws_access_key",
			VariableName:   key,
			LineNumber:     lineNum,
			Severity:       "high",
			Description:    "AWS Access Key ID detected in plaintext.",
			Recommendation: "Use AWS IAM roles, environment variables from secure vaults, or AWS SSO instead of hardcoded credentials.",
			RedactedValue:  redactValue(value),
			Source:         "filesystem",
		}
	}

	if varNameMatches(key, awsSecretVarNames) {
		if len(value) == 40 && awsSecretKeyRe.MatchString(value) {
			return &SecretFinding{
				FilePath:       filePath,
				SecretType:     "aws_secret_key",
				VariableName:   key,
				LineNumber:     lineNum,
				Severity:       "critical",
				Description:    "AWS Secret Access Key detected in plaintext.",
				Recommendation: "Use AWS IAM roles, environment variables from secure vaults, or AWS SSO instead of hardcoded credentials.",
				RedactedValue:  redactValue(value),
				Source:         "filesystem",
			}
		}
	}

	return nil
}

// tokenPattern describes a credential format distinctive enough to identify
// from its value alone, independent of the variable name it is stored under.
type tokenPattern struct {
	secretType  string
	re          *regexp.Regexp
	severity    string
	description string
}

// tokenPatterns are matched in order, so more specific prefixes must come
// before the generic ones they share a stem with (sk-ant- before sk-).
var tokenPatterns = []tokenPattern{
	{
		secretType:  "anthropic_api_key",
		re:          regexp.MustCompile(`^sk-ant-[A-Za-z0-9_-]{20,}$`),
		severity:    "critical",
		description: "Anthropic API key detected in plaintext.",
	},
	{
		secretType:  "openai_api_key",
		re:          regexp.MustCompile(`^sk-(?:proj-)?[A-Za-z0-9_-]{20,}$`),
		severity:    "critical",
		description: "OpenAI API key detected in plaintext.",
	},
	{
		secretType:  "github_token",
		re:          regexp.MustCompile(`^gh[pousr]_[A-Za-z0-9]{36,}$`),
		severity:    "critical",
		description: "GitHub access token detected in plaintext.",
	},
	{
		secretType:  "github_fine_grained_token",
		re:          regexp.MustCompile(`^github_pat_[A-Za-z0-9_]{50,}$`),
		severity:    "critical",
		description: "GitHub fine-grained personal access token detected in plaintext.",
	},
	{
		secretType:  "gitlab_token",
		re:          regexp.MustCompile(`^glpat-[A-Za-z0-9_-]{20,}$`),
		severity:    "critical",
		description: "GitLab personal access token detected in plaintext.",
	},
	{
		secretType:  "slack_token",
		re:          regexp.MustCompile(`^xox[abporss]-[A-Za-z0-9-]{10,}$`),
		severity:    "high",
		description: "Slack API token detected in plaintext.",
	},
	{
		secretType:  "stripe_live_key",
		re:          regexp.MustCompile(`^[sr]k_live_[A-Za-z0-9]{20,}$`),
		severity:    "critical",
		description: "Stripe live secret key detected in plaintext.",
	},
	{
		secretType:  "google_api_key",
		re:          regexp.MustCompile(`^AIza[A-Za-z0-9_-]{35}$`),
		severity:    "high",
		description: "Google API key detected in plaintext.",
	},
	{
		secretType:  "sendgrid_api_key",
		re:          regexp.MustCompile(`^SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}$`),
		severity:    "high",
		description: "SendGrid API key detected in plaintext.",
	},
	{
		secretType:  "npm_token",
		re:          regexp.MustCompile(`^npm_[A-Za-z0-9]{36}$`),
		severity:    "high",
		description: "npm access token detected in plaintext.",
	},
	{
		secretType:  "telegram_bot_token",
		re:          regexp.MustCompile(`^\d{8,10}:[A-Za-z0-9_-]{35}$`),
		severity:    "high",
		description: "Telegram bot token detected in plaintext.",
	},
	{
		secretType:  "jwt",
		re:          regexp.MustCompile(`^eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$`),
		severity:    "high",
		description: "JSON Web Token detected in plaintext.",
	},
	{
		secretType:  "private_key_pem",
		re:          regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY`),
		severity:    "critical",
		description: "PEM-encoded private key detected in plaintext.",
	},
}

// genericCredentialVarNames flag a variable as credential-bearing when no
// known token format matches. These require a length and entropy floor too,
// since the name alone says nothing about whether the value is real.
var genericCredentialVarNames = []string{
	"API_KEY",
	"APIKEY",
	"ACCESS_TOKEN",
	"AUTH_TOKEN",
	"TOKEN",
	"CLIENT_SECRET",
	"SECRET",
	"PASSWORD",
	"PASSWD",
	"CREDENTIAL",
	"PRIVATE_KEY",
	"ACCESS_KEY",
}

// placeholderMarkers appear in documentation stand-ins rather than live
// credentials. Applied only to token detection — the AWS and Ethereum checks
// gate on strict value formats and have their own long-standing behaviour.
var placeholderMarkers = []string{
	"EXAMPLE", "CHANGEME", "CHANGE_ME", "YOUR_", "YOURKEY", "PLACEHOLDER",
	"DUMMY", "REPLACE", "INSERT", "XXXX", "TODO", "FIXME", "REDACTED",
	"<", ">", "${", "{{",
}

const (
	// minGenericTokenLen is the shortest value the name-based path will flag.
	// Deliberately conservative: below this, config values and real secrets are
	// hard to tell apart and the false-positive rate climbs fast. A short
	// password (PASSWORD=hunter2) is a known, accepted miss.
	minGenericTokenLen = 20
	// minGenericTokenEntropy in bits/char. Random alphanumeric credentials sit
	// near 4.5-5.0; repeated or templated filler sits well below.
	minGenericTokenEntropy = 3.5
)

// looksLikeURL reports whether a value is a plain HTTP(S) endpoint.
//
// Normalizing away separators makes vendor names collide with credential
// keywords: 1Password becomes ONEPASSWORD, which contains PASSWORD, so
// ONEPASSWORD_EVENTS_URL and ONEPASSWORD_SCIM_URL both looked credential-shaped
// and their perfectly ordinary https:// values cleared the length and entropy
// floors. A URL carrying inline credentials (scheme://user:pass@host) is still
// a secret and is deliberately not excluded.
func looksLikeURL(value string) bool {
	lower := strings.ToLower(value)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return false
	}
	authority, _, _ := strings.Cut(value[strings.Index(value, "://")+3:], "/")
	if userinfo, _, found := strings.Cut(authority, "@"); found && strings.Contains(userinfo, ":") {
		return false
	}
	return true
}

// looksLikePlaceholder reports whether a value is an obvious stand-in.
func looksLikePlaceholder(value string) bool {
	upper := strings.ToUpper(value)
	for _, m := range placeholderMarkers {
		if strings.Contains(upper, m) {
			return true
		}
	}
	return false
}

// checkAPIToken detects API keys and access tokens: first by matching known
// vendor formats against the value, then by falling back to a credential-shaped
// variable name combined with length and entropy floors.
//
// This closes the gap that let ANTHROPIC_API_KEY, GITHUB_TOKEN and friends sit
// in a scanned .env while the scan reported zero findings — nothing in the
// package looked for tokens at all, only Ethereum keys, mnemonics and AWS.
func checkAPIToken(filePath, key, value string, lineNum int) *SecretFinding {
	if value == "" || looksLikePlaceholder(value) {
		return nil
	}

	for _, p := range tokenPatterns {
		if p.re.MatchString(value) {
			return &SecretFinding{
				FilePath:       filePath,
				SecretType:     p.secretType,
				VariableName:   key,
				LineNumber:     lineNum,
				Severity:       p.severity,
				Description:    p.description,
				Recommendation: "Revoke and rotate this credential, then load it from a secrets manager or environment injected at runtime rather than a file on disk.",
				RedactedValue:  redactValue(value),
				Source:         "filesystem",
			}
		}
	}

	// Name-based fallback for vendor formats we don't enumerate.
	if !varNameMatches(key, genericCredentialVarNames) {
		return nil
	}
	if looksLikeURL(value) {
		return nil
	}
	if len(value) < minGenericTokenLen || shannonEntropy(value) < minGenericTokenEntropy {
		return nil
	}
	// Values with whitespace are prose or command lines, not credentials.
	if strings.ContainsAny(value, " \t") {
		return nil
	}

	return &SecretFinding{
		FilePath:       filePath,
		SecretType:     "api_credential",
		VariableName:   key,
		LineNumber:     lineNum,
		Severity:       "high",
		Description:    "High-entropy value stored in a credential-named variable; likely a plaintext API key, token or password.",
		Recommendation: "Revoke and rotate this credential, then load it from a secrets manager or environment injected at runtime rather than a file on disk.",
		RedactedValue:  redactValue(value),
		Source:         "filesystem",
	}
}
