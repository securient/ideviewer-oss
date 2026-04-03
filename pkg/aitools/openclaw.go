package aitools

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// detectOpenClaw detects OpenClaw (formerly Clawdbot) AI agent framework.
func detectOpenClaw(ports []OpenPort) (*AITool, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil
	}

	isRunning := isProcessRunning("openclaw", "clawdbot")

	// Search for config dirs
	configDirs := []string{
		filepath.Join(home, ".openclaw"),
		filepath.Join(home, ".config", "openclaw"),
		filepath.Join(home, ".clawdbot"),
		filepath.Join(home, ".config", "clawdbot"),
	}

	var foundConfigDir string
	for _, dir := range configDirs {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			foundConfigDir = dir
			break
		}
	}

	if foundConfigDir == "" && !isRunning {
		return nil, nil
	}

	tool := &AITool{
		Name:      "OpenClaw",
		IsRunning: isRunning,
	}

	if foundConfigDir != "" {
		tool.ConfigPath = foundConfigDir
		scanOpenClawConfigs(foundConfigDir, tool)
	}

	// Filter ports
	for _, p := range ports {
		pLower := strings.ToLower(p.Process)
		if strings.Contains(pLower, "openclaw") || strings.Contains(pLower, "clawdbot") {
			tool.OpenPorts = append(tool.OpenPorts, p)
		}
	}

	return tool, nil
}

func scanOpenClawConfigs(dir string, tool *AITool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") && !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}

		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		source := "openclaw:" + name

		// Try to parse as JSON for structured extraction
		if strings.HasSuffix(name, ".json") {
			parseOpenClawJSON(data, source, tool)
		}

		// Scan all config files for secrets regardless of format
		scanForSecrets(data, source, tool)
	}
}

// openClawConfig represents common OpenClaw configuration structure.
type openClawConfig struct {
	LLM          *openClawLLM         `json:"llm"`
	Integrations *openClawIntegration `json:"integrations"`
	Slack        *openClawSlack       `json:"slack"`
	Telegram     *openClawTelegram    `json:"telegram"`
	AutoExecute  *bool                `json:"auto_execute"`
	Autonomous   *bool                `json:"autonomous"`
	FileAccess   *openClawFileAccess  `json:"file_access"`
	APIEndpoint  string               `json:"api_endpoint"`
}

type openClawLLM struct {
	Provider string `json:"provider"` // "anthropic", "openai"
	Model    string `json:"model"`
	APIKey   string `json:"api_key"`
}

type openClawIntegration struct {
	Slack    *openClawSlack    `json:"slack"`
	Telegram *openClawTelegram `json:"telegram"`
}

type openClawSlack struct {
	BotToken string `json:"bot_token"`
	AppToken string `json:"app_token"`
	Channel  string `json:"channel"`
}

type openClawTelegram struct {
	BotToken string `json:"bot_token"`
	ChatID   string `json:"chat_id"`
}

type openClawFileAccess struct {
	ReadPaths  []string `json:"read_paths"`
	WritePaths []string `json:"write_paths"`
}

func parseOpenClawJSON(data []byte, source string, tool *AITool) {
	var config openClawConfig
	if json.Unmarshal(data, &config) != nil {
		return
	}

	// Extract LLM configuration as an integration
	if config.LLM != nil {
		comp := AIComponent{
			Name:      "LLM: " + config.LLM.Provider,
			Type:      "integration",
			Transport: "api",
			Command:   config.LLM.Provider + "/" + config.LLM.Model,
			Source:    source,
			Permissions: AIPermissions{
				NetworkAccess: true,
			},
		}
		if config.LLM.APIKey != "" {
			comp.EnvVars = append(comp.EnvVars, "api_key")
			tool.Secrets = append(tool.Secrets, RedactedSecret{
				Source:        source,
				VariableName:  "llm.api_key",
				RedactedValue: redactSecret(config.LLM.APIKey),
				SecretType:    "api_key",
			})
		}
		calculateRisk(&comp)
		tool.Components = append(tool.Components, comp)
	}

	// Extract Slack integration
	slack := config.Slack
	if slack == nil && config.Integrations != nil {
		slack = config.Integrations.Slack
	}
	if slack != nil {
		comp := AIComponent{
			Name:      "Slack Integration",
			Type:      "integration",
			Transport: "websocket",
			Source:    source,
			Permissions: AIPermissions{
				NetworkAccess: true,
			},
		}
		if slack.BotToken != "" {
			tool.Secrets = append(tool.Secrets, RedactedSecret{
				Source:        source,
				VariableName:  "slack.bot_token",
				RedactedValue: redactSecret(slack.BotToken),
				SecretType:    "bot_token",
			})
		}
		if slack.AppToken != "" {
			tool.Secrets = append(tool.Secrets, RedactedSecret{
				Source:        source,
				VariableName:  "slack.app_token",
				RedactedValue: redactSecret(slack.AppToken),
				SecretType:    "app_token",
			})
		}
		calculateRisk(&comp)
		tool.Components = append(tool.Components, comp)
	}

	// Extract Telegram integration
	telegram := config.Telegram
	if telegram == nil && config.Integrations != nil {
		telegram = config.Integrations.Telegram
	}
	if telegram != nil {
		comp := AIComponent{
			Name:      "Telegram Integration",
			Type:      "integration",
			Transport: "api",
			Source:    source,
			Permissions: AIPermissions{
				NetworkAccess: true,
			},
		}
		if telegram.BotToken != "" {
			tool.Secrets = append(tool.Secrets, RedactedSecret{
				Source:        source,
				VariableName:  "telegram.bot_token",
				RedactedValue: redactSecret(telegram.BotToken),
				SecretType:    "bot_token",
			})
		}
		calculateRisk(&comp)
		tool.Components = append(tool.Components, comp)
	}

	// Check for autonomous execution flags
	if (config.AutoExecute != nil && *config.AutoExecute) || (config.Autonomous != nil && *config.Autonomous) {
		comp := AIComponent{
			Name:   "Autonomous Execution",
			Type:   "permission",
			Source: source,
			Permissions: AIPermissions{
				BashCommands: []string{"*"},
			},
		}
		calculateRisk(&comp)
		// Override: autonomous execution is always high risk
		if comp.Risk != "critical" {
			comp.Risk = "high"
			comp.RiskReason = "Autonomous execution enabled — agent can act without human approval"
		}
		tool.Components = append(tool.Components, comp)
	}

	// Check for unconstrained file system access
	if config.FileAccess != nil {
		hasWildcardRead := false
		hasWildcardWrite := false
		for _, p := range config.FileAccess.ReadPaths {
			if p == "*" || p == "/" || p == "~" || p == "/**" {
				hasWildcardRead = true
			}
		}
		for _, p := range config.FileAccess.WritePaths {
			if p == "*" || p == "/" || p == "~" || p == "/**" {
				hasWildcardWrite = true
			}
		}
		if hasWildcardRead || hasWildcardWrite {
			comp := AIComponent{
				Name:   "Unconstrained Filesystem Access",
				Type:   "permission",
				Source: source,
				Permissions: AIPermissions{
					FileSystemRead:  config.FileAccess.ReadPaths,
					FileSystemWrite: config.FileAccess.WritePaths,
				},
			}
			comp.Risk = "critical"
			comp.RiskReason = "Unrestricted shell execution or wildcard access"
			tool.Components = append(tool.Components, comp)
		}
	}

	// Check for insecure transport (HTTP vs HTTPS for API endpoints)
	if config.APIEndpoint != "" && strings.HasPrefix(config.APIEndpoint, "http://") {
		comp := AIComponent{
			Name:   "Insecure API Endpoint",
			Type:   "integration",
			Source: source,
			Permissions: AIPermissions{
				NetworkAccess: true,
			},
		}
		comp.Risk = "high"
		comp.RiskReason = "API endpoint uses unencrypted HTTP transport"
		tool.Components = append(tool.Components, comp)
	}
}
