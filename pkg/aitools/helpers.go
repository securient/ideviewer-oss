package aitools

import (
	"context"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// Secret detection patterns.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`sk-ant-[a-zA-Z0-9_-]{20,}`),         // Anthropic API key
	regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`),                // OpenAI API key
	regexp.MustCompile(`xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+`),   // Slack bot token
	regexp.MustCompile(`xapp-[0-9]+-[a-zA-Z0-9]+-[0-9]+-[a-zA-Z0-9]+`), // Slack app token
	regexp.MustCompile(`[0-9]+:[a-zA-Z0-9_-]{35}`),           // Telegram bot token
	regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),                // GitHub personal access token
	regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`),                // GitHub OAuth token
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),                   // AWS access key
}

// looksLikeSecret checks if a string value appears to be a secret/token.
func looksLikeSecret(value string) bool {
	if len(value) < 8 {
		return false
	}
	for _, pat := range secretPatterns {
		if pat.MatchString(value) {
			return true
		}
	}
	// Generic: long alphanumeric strings that look like tokens
	if len(value) >= 20 && !strings.Contains(value, " ") && !strings.Contains(value, "/") {
		alphaNum := 0
		for _, c := range value {
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
				alphaNum++
			}
		}
		ratio := float64(alphaNum) / float64(len(value))
		if ratio > 0.8 {
			return true
		}
	}
	return false
}

// classifySecret determines the type of a secret based on its key name and value.
func classifySecret(keyName, value string) string {
	keyLower := strings.ToLower(keyName)
	valueLower := strings.ToLower(value)

	switch {
	case strings.Contains(keyLower, "anthropic") || strings.HasPrefix(value, "sk-ant-"):
		return "anthropic_api_key"
	case strings.Contains(keyLower, "openai") || (strings.HasPrefix(value, "sk-") && !strings.HasPrefix(value, "sk-ant-")):
		return "openai_api_key"
	case strings.Contains(keyLower, "slack") && strings.Contains(keyLower, "bot"):
		return "slack_bot_token"
	case strings.Contains(keyLower, "slack"):
		return "slack_token"
	case strings.Contains(keyLower, "telegram"):
		return "telegram_bot_token"
	case strings.Contains(keyLower, "github") || strings.HasPrefix(value, "ghp_") || strings.HasPrefix(value, "gho_"):
		return "github_token"
	case strings.HasPrefix(value, "AKIA"):
		return "aws_access_key"
	case strings.Contains(keyLower, "token") || strings.Contains(valueLower, "token"):
		return "token"
	case strings.Contains(keyLower, "key") || strings.Contains(keyLower, "secret"):
		return "api_key"
	default:
		return "credential"
	}
}

// scanForSecrets scans raw config data for secret patterns.
func scanForSecrets(data []byte, source string, tool *AITool) {
	content := string(data)
	for _, pat := range secretPatterns {
		matches := pat.FindAllString(content, -1)
		for _, match := range matches {
			// Skip if already reported
			redacted := redactSecret(match)
			alreadyFound := false
			for _, existing := range tool.Secrets {
				if existing.RedactedValue == redacted {
					alreadyFound = true
					break
				}
			}
			if alreadyFound {
				continue
			}
			tool.Secrets = append(tool.Secrets, RedactedSecret{
				Source:        source,
				VariableName:  "(embedded in config)",
				RedactedValue: redacted,
				SecretType:    classifySecret("", match),
			})
		}
	}
}

// isProcessRunning checks if any of the given process names are running.
func isProcessRunning(names ...string) bool {
	if runtime.GOOS == "windows" {
		return isProcessRunningWindows(names...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, name := range names {
		cmd := exec.CommandContext(ctx, "pgrep", "-x", name)
		if err := cmd.Run(); err == nil {
			return true
		}
	}
	return false
}

// isProcessRunningWindows uses tasklist to check for running processes on Windows.
func isProcessRunningWindows(names ...string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "tasklist", "/FO", "CSV", "/NH").Output()
	if err != nil {
		return false
	}
	output := strings.ToLower(string(out))
	for _, name := range names {
		// tasklist shows "process.exe" — check with and without .exe
		lower := strings.ToLower(name)
		if strings.Contains(output, "\""+lower+"\"") || strings.Contains(output, "\""+lower+".exe\"") {
			return true
		}
	}
	return false
}
