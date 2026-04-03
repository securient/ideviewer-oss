package aitools

import (
	"strings"
	"sync"
	"time"
)

// Scanner detects AI development tools, their configurations, and permissions.
type Scanner struct{}

// NewScanner creates a new AI tools scanner.
func NewScanner() *Scanner {
	return &Scanner{}
}

// AIToolResult holds results from scanning for AI tools.
type AIToolResult struct {
	Timestamp string   `json:"timestamp"`
	Tools     []AITool `json:"ai_tools"`
	Errors    []string `json:"errors,omitempty"`
}

// AITool represents a detected AI development tool.
type AITool struct {
	Name       string           `json:"name"`
	Version    string           `json:"version,omitempty"`
	IsRunning  bool             `json:"is_running"`
	ConfigPath string           `json:"config_path,omitempty"`
	Components []AIComponent    `json:"components,omitempty"`
	OpenPorts  []OpenPort       `json:"open_ports,omitempty"`
	Secrets    []RedactedSecret `json:"secrets,omitempty"`
}

// AIComponent is a unified entry for MCP servers, skills, plugins, integrations, and permissions.
type AIComponent struct {
	Name        string        `json:"name"`
	Type        string        `json:"type"`                   // "mcp-server", "cloud-mcp", "skill", "integration", "permission"
	Transport   string        `json:"transport,omitempty"`    // "stdio", "sse", "http", "plugin", "cloud", "api", "websocket"
	Command     string        `json:"command,omitempty"`
	Args        []string      `json:"args,omitempty"`
	EnvVars     []string      `json:"env_vars,omitempty"`
	Permissions AIPermissions `json:"permissions"`
	Risk        string        `json:"risk"`                   // "critical", "high", "medium", "low", "info"
	RiskReason  string        `json:"risk_reason,omitempty"`
	Source      string        `json:"source,omitempty"`       // where this was found (e.g., "settings.json", "project:ideviewer")
}

// AIPermissions tracks what an AI component can access.
type AIPermissions struct {
	FileSystemRead  []string `json:"fs_read,omitempty"`
	FileSystemWrite []string `json:"fs_write,omitempty"`
	NetworkAccess   bool     `json:"network_access"`
	EnvAccess       []string `json:"env_access,omitempty"`
	BashCommands    []string `json:"bash_commands,omitempty"`
	MCPTools        []string `json:"mcp_tools,omitempty"`
}

// calculateRisk sets the Risk and RiskReason fields on an AIComponent.
func calculateRisk(c *AIComponent) {
	switch {
	case containsWildcard(c):
		c.Risk = "critical"
		c.RiskReason = "Unrestricted shell execution or wildcard access"
	case hasPlaintextSecrets(c):
		c.Risk = "critical"
		c.RiskReason = "Plaintext credentials in configuration"
	case c.Type == "integration" && c.Permissions.NetworkAccess:
		c.Risk = "high"
		c.RiskReason = "External service integration with network access"
	case c.Type == "cloud-mcp":
		c.Risk = "medium"
		c.RiskReason = "Cloud MCP with access to sensitive data"
	case c.Type == "mcp-server" && c.Permissions.NetworkAccess && len(c.Permissions.FileSystemRead) > 0:
		c.Risk = "medium"
		c.RiskReason = "MCP server with both filesystem and network access"
	case c.Type == "skill" && c.Permissions.NetworkAccess:
		c.Risk = "low"
		c.RiskReason = "Skill with network access"
	case c.Type == "permission" && len(c.Permissions.BashCommands) > 0:
		c.Risk = "medium"
		c.RiskReason = "Shell command execution permissions granted"
	default:
		c.Risk = "info"
	}
}

// containsWildcard checks if any bash command permission uses wildcard access.
func containsWildcard(c *AIComponent) bool {
	for _, cmd := range c.Permissions.BashCommands {
		if cmd == "*" || strings.HasSuffix(cmd, ":*") || cmd == "Bash(*)" {
			return true
		}
	}
	return false
}

// hasPlaintextSecrets checks if env vars look like they contain secrets.
func hasPlaintextSecrets(c *AIComponent) bool {
	for _, envVar := range c.EnvVars {
		lower := strings.ToLower(envVar)
		if strings.Contains(lower, "key") || strings.Contains(lower, "secret") ||
			strings.Contains(lower, "token") || strings.Contains(lower, "password") {
			// The env var name itself suggests a secret; the value was in config
			return false // We only have names, not values — can't confirm plaintext
		}
	}
	return false
}

// OpenPort represents a listening port from an AI-related process.
type OpenPort struct {
	Port    int    `json:"port"`
	Process string `json:"process"`
	Proto   string `json:"proto"`
}

// RedactedSecret represents a secret found in an AI tool config with its value redacted.
type RedactedSecret struct {
	Source        string `json:"source"`
	VariableName  string `json:"variable_name"`
	RedactedValue string `json:"redacted_value"`
	SecretType    string `json:"secret_type"`
}

// Scan detects all supported AI tools and their configurations.
func (s *Scanner) Scan() (*AIToolResult, error) {
	var (
		mu     sync.Mutex
		tools  []AITool
		errors []string
	)

	// Collect open ports once (shared across all tools)
	ports := scanOpenPorts()

	type detector struct {
		name string
		fn   func([]OpenPort) (*AITool, error)
	}
	detectors := []detector{
		{"Claude Code", detectClaude},
		{"Cursor", detectCursor},
		{"OpenClaw", detectOpenClaw},
	}

	var wg sync.WaitGroup
	wg.Add(len(detectors))

	for _, d := range detectors {
		go func(det detector) {
			defer wg.Done()
			tool, err := det.fn(ports)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errors = append(errors, det.name+": "+err.Error())
				return
			}
			if tool != nil {
				tools = append(tools, *tool)
			}
		}(d)
	}

	wg.Wait()

	return &AIToolResult{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Tools:     tools,
		Errors:    errors,
	}, nil
}

// redactSecret redacts a secret value, showing first 4 + **** + last 4 chars.
func redactSecret(value string) string {
	if len(value) <= 12 {
		return "****"
	}
	return value[:4] + "****" + value[len(value)-4:]
}
