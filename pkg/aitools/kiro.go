package aitools

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func detectKiro(ports []OpenPort) (*AITool, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil
	}
	kiroDir := filepath.Join(home, ".kiro")
	mcpPath := filepath.Join(kiroDir, "settings", "mcp.json")
	isRunning := isProcessRunning("Kiro", "kiro")
	_, mcpExists := os.Stat(mcpPath)
	_, dirExists := os.Stat(kiroDir)
	if dirExists != nil && !isRunning && mcpExists != nil {
		return nil, nil
	}
	tool := &AITool{Name: "Kiro", IsRunning: isRunning}
	if data, err := os.ReadFile(mcpPath); err == nil {
		tool.ConfigPath = mcpPath
		parseKiroMCPConfig(data, "mcp.json", tool)
	}
	var settingsPaths []string
	switch runtime.GOOS {
	case "darwin":
		settingsPaths = []string{filepath.Join(home, "Library", "Application Support", "Kiro", "User", "settings.json")}
	case "linux":
		settingsPaths = []string{filepath.Join(home, ".config", "Kiro", "User", "settings.json")}
	case "windows":
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			settingsPaths = []string{filepath.Join(appdata, "Kiro", "User", "settings.json")}
		}
	}
	for _, sp := range settingsPaths {
		if data, err := os.ReadFile(sp); err == nil {
			parseKiroVSCodeSettings(data, sp, tool)
		}
	}
	for _, p := range ports {
		if strings.Contains(strings.ToLower(p.Process), "kiro") {
			tool.OpenPorts = append(tool.OpenPorts, p)
		}
	}
	return tool, nil
}

type kiroMCPServer struct {
	Command     string            `json:"command"`
	Args        []string          `json:"args"`
	Env         map[string]string `json:"env"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
	AutoApprove []string          `json:"autoApprove"`
}

type kiroMCPConfig struct {
	MCPServers map[string]kiroMCPServer `json:"mcpServers"`
}

func parseKiroMCPConfig(data []byte, source string, tool *AITool) {
	var config kiroMCPConfig
	if json.Unmarshal(data, &config) != nil {
		return
	}
	for name, srv := range config.MCPServers {
		comp := AIComponent{Name: name, Type: "mcp-server", Source: "kiro:" + source}
		if srv.URL != "" {
			comp.Transport = inferKiroRemoteTransport(srv.URL)
			comp.Permissions.NetworkAccess = true
			if strings.HasPrefix(srv.URL, "http://") {
				comp.Risk = "high"
				comp.RiskReason = "Remote MCP server using unencrypted HTTP transport"
			}
			for k, v := range srv.Headers {
				comp.EnvVars = append(comp.EnvVars, k)
				if looksLikeSecret(v) {
					tool.Secrets = append(tool.Secrets, RedactedSecret{Source: "kiro:" + source, VariableName: k, RedactedValue: redactSecret(v), SecretType: classifySecret(k, v)})
				}
			}
		} else {
			comp.Transport = "stdio"
			comp.Command = srv.Command
			comp.Args = srv.Args
			for k, v := range srv.Env {
				comp.EnvVars = append(comp.EnvVars, k)
				comp.Permissions.EnvAccess = append(comp.Permissions.EnvAccess, k)
				if looksLikeSecret(v) {
					tool.Secrets = append(tool.Secrets, RedactedSecret{Source: "kiro:" + source, VariableName: k, RedactedValue: redactSecret(v), SecretType: classifySecret(k, v)})
				}
			}
			joined := strings.Join(append([]string{srv.Command}, srv.Args...), " ")
			if strings.Contains(joined, "filesystem") || strings.Contains(joined, "fs-") {
				comp.Permissions.FileSystemRead = append(comp.Permissions.FileSystemRead, "(inferred)")
				comp.Permissions.FileSystemWrite = append(comp.Permissions.FileSystemWrite, "(inferred)")
			}
			if strings.Contains(joined, "fetch") || strings.Contains(joined, "http") || strings.Contains(joined, "api") || strings.Contains(joined, "web") {
				comp.Permissions.NetworkAccess = true
			}
		}
		if len(srv.AutoApprove) > 0 {
			comp.Permissions.MCPTools = srv.AutoApprove
			if comp.Risk != "high" && comp.Risk != "critical" {
				comp.Risk = "high"
				comp.RiskReason = "MCP server has auto-approved tools: " + strings.Join(srv.AutoApprove, ", ")
			}
		}
		if comp.Risk == "" {
			calculateRisk(&comp)
		}
		tool.Components = append(tool.Components, comp)
	}
	scanForSecrets(data, "kiro:"+source, tool)
}

func inferKiroRemoteTransport(url string) string {
	lower := strings.ToLower(url)
	if strings.HasSuffix(lower, "/sse") || strings.Contains(lower, "/sse?") {
		return "sse"
	}
	return "http"
}

func parseKiroVSCodeSettings(data []byte, source string, tool *AITool) {
	var settings map[string]json.RawMessage
	if json.Unmarshal(data, &settings) != nil {
		return
	}
	if raw, ok := settings["mcp.servers"]; ok {
		parseKiroServersRaw(raw, "kiro:settings:mcp.servers", tool)
	}
	if raw, ok := settings["mcpServers"]; ok {
		parseKiroServersRaw(raw, "kiro:settings:mcpServers", tool)
	}
	if raw, ok := settings["mcp"]; ok {
		var mcpBlock map[string]json.RawMessage
		if json.Unmarshal(raw, &mcpBlock) == nil {
			if serversRaw, ok := mcpBlock["servers"]; ok {
				parseKiroServersRaw(serversRaw, "kiro:settings:mcp.servers", tool)
			}
			if serversRaw, ok := mcpBlock["mcpServers"]; ok {
				parseKiroServersRaw(serversRaw, "kiro:settings:mcp.mcpServers", tool)
			}
		}
	}
}

func parseKiroServersRaw(raw json.RawMessage, source string, tool *AITool) {
	var servers map[string]kiroMCPServer
	if json.Unmarshal(raw, &servers) != nil {
		return
	}
	for name, srv := range servers {
		comp := AIComponent{Name: name, Type: "mcp-server", Command: srv.Command, Args: srv.Args, Transport: "stdio", Source: source}
		for k, v := range srv.Env {
			comp.EnvVars = append(comp.EnvVars, k)
			comp.Permissions.EnvAccess = append(comp.Permissions.EnvAccess, k)
			if looksLikeSecret(v) {
				tool.Secrets = append(tool.Secrets, RedactedSecret{Source: source, VariableName: k, RedactedValue: redactSecret(v), SecretType: classifySecret(k, v)})
			}
		}
		calculateRisk(&comp)
		tool.Components = append(tool.Components, comp)
	}
}
