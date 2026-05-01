package aitools

import (
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
		parseMCPConfigFile(data, "kiro:mcp.json", tool)
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
			parseMCPFromVSCodeSettings(data, "kiro:settings", tool)
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
