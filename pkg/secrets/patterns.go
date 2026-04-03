package secrets

import (
	"regexp"
	"strings"
)

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

// redactValue redacts a secret value, showing only first 4 and last 4 characters.
func redactValue(value string) string {
	if value == "" {
		return ""
	}
	n := len(value)
	if n <= 10 {
		if n <= 2 {
			return strings.Repeat("*", n)
		}
		return value[:2] + strings.Repeat("*", n-2)
	}
	return value[:4] + strings.Repeat("*", n-8) + value[n-4:]
}

// checkEthPrivateKey checks if a key/value pair looks like an Ethereum private key.
func checkEthPrivateKey(filePath, key, value string, lineNum int) *SecretFinding {
	keyUpper := strings.ToUpper(key)
	isKeyNameMatch := false
	for _, pattern := range privateKeyVarNames {
		if strings.Contains(keyUpper, pattern) {
			isKeyNameMatch = true
			break
		}
	}

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
	keyUpper := strings.ToUpper(key)
	hasMnemonicKeyword := false
	for _, kw := range mnemonicKeywords {
		if strings.Contains(keyUpper, kw) {
			hasMnemonicKeyword = true
			break
		}
	}
	if !hasMnemonicKeyword {
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

	first2 := words[0] + " " + words[1]
	last := words[len(words)-1]
	return &SecretFinding{
		FilePath:       filePath,
		SecretType:     "mnemonic_seed_phrase",
		VariableName:   key,
		LineNumber:     lineNum,
		Severity:       "critical",
		Description:    "Plaintext mnemonic/seed phrase detected. This can be used to derive all wallet keys and drain all associated funds.",
		Recommendation: "Use encrypted keystores or hardware wallets. Never store seed phrases in plaintext files.",
		RedactedValue:  redactValue(first2) + " ... " + redactValue(last),
		Source:         "filesystem",
	}
}

// checkAWSCredentials checks for AWS credentials.
func checkAWSCredentials(filePath, key, value string, lineNum int) *SecretFinding {
	keyUpper := strings.ToUpper(key)

	if strings.Contains(keyUpper, "AWS") && strings.Contains(keyUpper, "ACCESS") {
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
	}

	if strings.Contains(keyUpper, "AWS") && strings.Contains(keyUpper, "SECRET") {
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
