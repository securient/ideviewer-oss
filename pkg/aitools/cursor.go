package aitools

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// detectCursor detects Cursor IDE installation and MCP configuration.
func detectCursor(ports []OpenPort) (*AITool, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil
	}

	cursorDir := filepath.Join(home, ".cursor")
	mcpPath := filepath.Join(cursorDir, "mcp.json")

	isRunning := isProcessRunning("Cursor", "cursor")

	// Check if Cursor has config
	_, mcpExists := os.Stat(mcpPath)
	_, dirExists := os.Stat(cursorDir)

	if dirExists != nil && !isRunning && mcpExists != nil {
		return nil, nil
	}

	tool := &AITool{
		Name:      "Cursor",
		IsRunning: isRunning,
	}

	// Parse mcp.json
	if data, err := os.ReadFile(mcpPath); err == nil {
		tool.ConfigPath = mcpPath
		parseCursorMCPConfig(data, "mcp.json", tool)
	}

	// Parse VS Code-like settings for MCP config
	var settingsPaths []string
	switch runtime.GOOS {
	case "darwin":
		settingsPaths = []string{
			filepath.Join(home, "Library", "Application Support", "Cursor", "User", "settings.json"),
		}
	case "linux":
		settingsPaths = []string{
			filepath.Join(home, ".config", "Cursor", "User", "settings.json"),
		}
	case "windows":
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			settingsPaths = []string{
				filepath.Join(appdata, "Cursor", "User", "settings.json"),
			}
		}
	}

	for _, sp := range settingsPaths {
		if data, err := os.ReadFile(sp); err == nil {
			parseCursorVSCodeSettings(data, sp, tool)
		}
	}

	// Filter ports for cursor-related processes
	for _, p := range ports {
		pLower := strings.ToLower(p.Process)
		if strings.Contains(pLower, "cursor") {
			tool.OpenPorts = append(tool.OpenPorts, p)
		}
	}

	return tool, nil
}

// cursorMCPConfig represents Cursor's mcp.json structure.
type cursorMCPConfig struct {
	AIComponents map[string]cursorAIComponent `json:"mcpServers"`
}

type cursorAIComponent struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
}

func parseCursorMCPConfig(data []byte, source string, tool *AITool) {
	var config cursorMCPConfig
	if json.Unmarshal(data, &config) != nil {
		return
	}

	for name, srv := range config.AIComponents {
		comp := AIComponent{
			Name:      name,
			Type:      "mcp-server",
			Command:   srv.Command,
			Args:      srv.Args,
			Transport: "stdio",
			Source:    "cursor:" + source,
		}

		for k, v := range srv.Env {
			comp.EnvVars = append(comp.EnvVars, k)
			comp.Permissions.EnvAccess = append(comp.Permissions.EnvAccess, k)
			if looksLikeSecret(v) {
				tool.Secrets = append(tool.Secrets, RedactedSecret{
					Source:        "cursor:" + source,
					VariableName:  k,
					RedactedValue: redactSecret(v),
					SecretType:    classifySecret(k, v),
				})
			}
		}

		// Infer permissions from command/args
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

		calculateRisk(&comp)
		tool.Components = append(tool.Components, comp)
	}

	scanForSecrets(data, "cursor:"+source, tool)
}

func parseCursorVSCodeSettings(data []byte, source string, tool *AITool) {
	// Cursor can have MCP servers under multiple keys in VS Code settings:
	// "mcp.servers", "mcpServers", or nested under "mcp" -> "servers"
	var settings map[string]json.RawMessage
	if json.Unmarshal(data, &settings) != nil {
		return
	}

	// Try "mcp.servers" key
	if raw, ok := settings["mcp.servers"]; ok {
		parseCursorAIComponentsRaw(raw, "cursor:settings:mcp.servers", tool)
	}

	// Try "mcpServers" key
	if raw, ok := settings["mcpServers"]; ok {
		parseCursorAIComponentsRaw(raw, "cursor:settings:mcpServers", tool)
	}

	// Try "mcp" key with nested "servers" or "mcpServers"
	if raw, ok := settings["mcp"]; ok {
		var mcpBlock map[string]json.RawMessage
		if json.Unmarshal(raw, &mcpBlock) == nil {
			if serversRaw, ok := mcpBlock["servers"]; ok {
				parseCursorAIComponentsRaw(serversRaw, "cursor:settings:mcp.servers", tool)
			}
			if serversRaw, ok := mcpBlock["mcpServers"]; ok {
				parseCursorAIComponentsRaw(serversRaw, "cursor:settings:mcp.mcpServers", tool)
			}
		}
	}
}

func parseCursorAIComponentsRaw(raw json.RawMessage, source string, tool *AITool) {
	var servers map[string]cursorAIComponent
	if json.Unmarshal(raw, &servers) != nil {
		return
	}

	for name, srv := range servers {
		comp := AIComponent{
			Name:      name,
			Type:      "mcp-server",
			Command:   srv.Command,
			Args:      srv.Args,
			Transport: "stdio",
			Source:    source,
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
		calculateRisk(&comp)
		tool.Components = append(tool.Components, comp)
	}
}
