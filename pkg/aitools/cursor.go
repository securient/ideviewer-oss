package aitools

import (
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
		parseMCPConfigFile(data, "cursor:mcp.json", tool)
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
			parseMCPFromVSCodeSettings(data, "cursor:settings", tool)
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
