package aitools

import (
	"encoding/json"
	"strings"
)

// MCPServerConfig represents an MCP server entry in a VS Code-derived IDE's config.
type MCPServerConfig struct {
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

// MCPConfig wraps the top-level mcpServers key.
type MCPConfig struct {
	MCPServers map[string]MCPServerConfig `json:"mcpServers"`
}

// parseMCPServers converts a map of MCP server configs into AIComponents on the given tool.
func parseMCPServers(servers map[string]MCPServerConfig, source string, tool *AITool) {
	for name, srv := range servers {
		comp := AIComponent{
			Name:   name,
			Type:   "mcp-server",
			Source: source,
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
					Source:        source,
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
					Source:        source,
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
}

// parseMCPConfigFile parses a top-level mcp.json file (with mcpServers key),
// calls parseMCPServers, then scans the raw data for embedded secrets.
func parseMCPConfigFile(data []byte, source string, tool *AITool) {
	var config MCPConfig
	if json.Unmarshal(data, &config) != nil {
		return
	}

	parseMCPServers(config.MCPServers, source, tool)
	scanForSecrets(data, source, tool)
}

// parseMCPFromVSCodeSettings handles VS Code settings.json parsing with the three key
// variants (mcp.servers, mcpServers, mcp->servers nested). For each discovered block,
// it calls parseMCPServers and scanForSecrets on the raw data.
func parseMCPFromVSCodeSettings(data []byte, source string, tool *AITool) {
	var settings map[string]json.RawMessage
	if json.Unmarshal(data, &settings) != nil {
		return
	}

	// Try "mcp.servers" key
	if raw, ok := settings["mcp.servers"]; ok {
		parseMCPServersRaw(raw, source+":mcp.servers", tool)
	}

	// Try "mcpServers" key
	if raw, ok := settings["mcpServers"]; ok {
		parseMCPServersRaw(raw, source+":mcpServers", tool)
	}

	// Try "mcp" key with nested "servers" or "mcpServers"
	if raw, ok := settings["mcp"]; ok {
		var mcpBlock map[string]json.RawMessage
		if json.Unmarshal(raw, &mcpBlock) == nil {
			if serversRaw, ok := mcpBlock["servers"]; ok {
				parseMCPServersRaw(serversRaw, source+":mcp.servers", tool)
			}
			if serversRaw, ok := mcpBlock["mcpServers"]; ok {
				parseMCPServersRaw(serversRaw, source+":mcp.mcpServers", tool)
			}
		}
	}

	// Scan full settings data for embedded secrets
	scanForSecrets(data, source, tool)
}

// parseMCPServersRaw unmarshals a json.RawMessage into a server map and processes it.
func parseMCPServersRaw(raw json.RawMessage, source string, tool *AITool) {
	var servers map[string]MCPServerConfig
	if json.Unmarshal(raw, &servers) != nil {
		return
	}

	parseMCPServers(servers, source, tool)
}
