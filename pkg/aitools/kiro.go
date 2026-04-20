package aitools

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// detectKiro detects Kiro IDE installation and MCP configuration.
func detectKiro(ports []OpenPort) (*AITool, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil
	}

	kiroDir := filepath.Join(home, ".kiro")
	mcpPath := filepath.Join(kiroDir, "settings", "mcp.json")

	isRunning := isProcessRunning("Kiro", "kiro")

	// Check if Kiro has config
	_, mcpExists := os.Stat(mcpPath)
	_, dirExists := os.Stat(kiroDir)

	if dirExists != nil && !isRunning && mcpExists != nil {
		return nil, nil
	}

	tool := &AITool{
		Name:      "Kiro",
		IsRunning: isRunning,
	}

	// Parse mcp.json
	if data, err := os.ReadFile(mcpPath); err == nil {
		tool.ConfigPath = mcpPath
		parseKiroMCPConfig(data, "mcp.json", tool)
	}

	// Parse VS Code-like settings for MCP config
	var settingsPaths []string
	switch runtime.GOOS {
	case "darwin":
		settingsPaths = []string{
			filepath.Join(home, "Library", "Application Support", "Kiro", "User", "settings.json"),
		}
	case "linux":
		settingsPaths = []string{
			filepath.Join(home, ".config", "Kiro", "User", "settings.json"),
		}
	case "windows":
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			settingsPaths = []string{
				filepath.Join(appdata, "Kiro", "User", "settings.json"),
			}
		}
	}

	for _, sp := range settingsPaths {
		if data, err := os.ReadFile(sp); err == nil {
			parseKiroVSCodeSettings(data, sp, tool)
		}
	}

	// Filter ports for kiro-related processes
	for _, p := range ports {
		pLower := strings.ToLower(p.Process)
		if strings.Contains(pLower, "kiro") {
			tool.OpenPorts = append(tool.OpenPorts, p)
		}
	}

	return tool, nil
}

// kiroMCPConfig represents Kiro's mcp.json structure.
type kiroMCPConfig struct {
	MCPServers map[string]kiroMCPServer `json:"mcpServers"`
}

type kiroMCPServer struct {
	// Local (stdio) servers
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	// Remote (SSE/streamable HTTP) servers
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	// Common fields
	Disabled      *bool    `json:"disabled"`
	AutoApprove   []string `json:"autoApprove"`
	DisabledTools []string `json:"disabledTools"`
}

func parseKiroMCPConfig(data []byte, source string, tool *AITool) {
	var config kiroMCPConfig
	if json.Unmarshal(data, &config) != nil {
		return
	}

	for name, srv := range config.MCPServers {
		comp := AIComponent{
			Name:   name,
			Type:   "mcp-server",
			Source: "kiro:" + source,
		}

		if srv.URL != "" {
			// Remote server (SSE or streamable HTTP)
			comp.Command = srv.URL
			comp.Transport = "sse"
			comp.Permissions.NetworkAccess = true
			if strings.HasPrefix(srv.URL, "http://") {
				comp.Risk = "high"
				comp.RiskReason = "Unencrypted HTTP transport for MCP server"
			}
		} else {
			// Local stdio server
			comp.Command = srv.Command
			comp.Args = srv.Args
			comp.Transport = "stdio"
		}

		for k, v := range srv.Env {
			comp.EnvVars = append(comp.EnvVars, k)
			comp.Permissions.EnvAccess = append(comp.Permissions.EnvAccess, k)
			if looksLikeSecret(v) {
				tool.Secrets = append(tool.Secrets, RedactedSecret{
					Source:        "kiro:" + source,
					VariableName:  k,
					RedactedValue: redactSecret(v),
					SecretType:    classifySecret(k, v),
				})
			}
		}

		// Check headers for secrets (remote servers)
		for k, v := range srv.Headers {
			if looksLikeSecret(v) {
				tool.Secrets = append(tool.Secrets, RedactedSecret{
					Source:        "kiro:" + source,
					VariableName:  "header:" + k,
					RedactedValue: redactSecret(v),
					SecretType:    classifySecret(k, v),
				})
			}
		}

		// Flag auto-approved tools as higher risk
		if len(srv.AutoApprove) > 0 {
			comp.Permissions.MCPTools = append(comp.Permissions.MCPTools, srv.AutoApprove...)
		}

		// Infer permissions from command/args
		if srv.Command != "" {
			allArgs := append([]string{srv.Command}, srv.Args...)
			joined := strings.Join(allArgs, " ")
			if strings.Contains(joined, "filesystem") || strings.Contains(joined, "fs-") {
				comp.Permissions.FileSystemRead = append(comp.Permissions.FileSystemRead, "(inferred)")
				comp.Permissions.FileSystemWrite = append(comp.Permissions.FileSystemWrite, "(inferred)")
			}
			if strings.Contains(joined, "fetch") || strings.Contains(joined, "http") ||
				strings.Contains(joined, "api") || strings.Contains(joined, "web") {
				comp.Permissions.NetworkAccess = true
			}
		}

		// Only calculate risk if not already set by HTTP detection
		if comp.Risk == "" {
			calculateRisk(&comp)
		}
		tool.Components = append(tool.Components, comp)
	}

	scanForSecrets(data, "kiro:"+source, tool)
}

func parseKiroVSCodeSettings(data []byte, source string, tool *AITool) {
	var settings map[string]json.RawMessage
	if json.Unmarshal(data, &settings) != nil {
		return
	}

	// Try "mcp.servers" key
	if raw, ok := settings["mcp.servers"]; ok {
		parseKiroMCPServersRaw(raw, "kiro:settings:mcp.servers", tool)
	}

	// Try "mcpServers" key
	if raw, ok := settings["mcpServers"]; ok {
		parseKiroMCPServersRaw(raw, "kiro:settings:mcpServers", tool)
	}

	// Try "mcp" key with nested "servers" or "mcpServers"
	if raw, ok := settings["mcp"]; ok {
		var mcpBlock map[string]json.RawMessage
		if json.Unmarshal(raw, &mcpBlock) == nil {
			if serversRaw, ok := mcpBlock["servers"]; ok {
				parseKiroMCPServersRaw(serversRaw, "kiro:settings:mcp.servers", tool)
			}
			if serversRaw, ok := mcpBlock["mcpServers"]; ok {
				parseKiroMCPServersRaw(serversRaw, "kiro:settings:mcp.mcpServers", tool)
			}
		}
	}
}

func parseKiroMCPServersRaw(raw json.RawMessage, source string, tool *AITool) {
	var servers map[string]kiroMCPServer
	if json.Unmarshal(raw, &servers) != nil {
		return
	}

	for name, srv := range servers {
		comp := AIComponent{
			Name:   name,
			Type:   "mcp-server",
			Source: source,
		}

		if srv.URL != "" {
			comp.Command = srv.URL
			comp.Transport = "sse"
			comp.Permissions.NetworkAccess = true
			if strings.HasPrefix(srv.URL, "http://") {
				comp.Risk = "high"
				comp.RiskReason = "Unencrypted HTTP transport for MCP server"
			}
		} else {
			comp.Command = srv.Command
			comp.Args = srv.Args
			comp.Transport = "stdio"
		}

		for k, v := range srv.Env {
			comp.EnvVars = append(comp.EnvVars, k)
			comp.Permissions.EnvAccess = append(comp.Permissions.EnvAccess, k)
			if looksLikeSecret(v) {
				tool.Secrets = append(tool.Secrets, RedactedSecret{
					Source:        source,
					VariableName:  k,
					RedactedValue: redactSecret(v),
					SecretType:    classifySecret(k, v),
				})
			}
		}

		if len(srv.AutoApprove) > 0 {
			comp.Permissions.MCPTools = append(comp.Permissions.MCPTools, srv.AutoApprove...)
		}

		if comp.Risk == "" {
			calculateRisk(&comp)
		}
		tool.Components = append(tool.Components, comp)
	}
}
