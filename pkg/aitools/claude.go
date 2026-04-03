package aitools

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// projectSearchDirs are subdirectories of home to search for project-level configs.
var projectSearchDirs = []string{
	"Documents",
	"Projects",
	"Development",
	"dev",
	"projects",
	"code",
	"src",
	"work",
	"workspace",
	"repos",
	"git",
	"github",
	"go/src",
}

// detectClaude detects Claude Code installation and configuration.
func detectClaude(ports []OpenPort) (*AITool, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil
	}

	claudeDir := filepath.Join(home, ".claude")
	settingsPath := filepath.Join(claudeDir, "settings.json")

	// Check if Claude Code is installed (config dir or binary exists)
	_, dirExists := os.Stat(claudeDir)
	isRunning := isProcessRunning("claude")
	version := getClaudeVersion()

	if dirExists != nil && !isRunning && version == "" {
		return nil, nil // Not installed
	}

	tool := &AITool{
		Name:      "Claude Code",
		Version:   version,
		IsRunning: isRunning,
	}

	// Parse global settings
	if data, err := os.ReadFile(settingsPath); err == nil {
		tool.ConfigPath = settingsPath
		parseClaudeSettings(data, "global", tool)
	}

	// Parse per-project settings from ~/.claude/projects/
	projectsDir := filepath.Join(claudeDir, "projects")
	if entries, err := os.ReadDir(projectsDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			projSettings := filepath.Join(projectsDir, entry.Name(), "settings.json")
			if data, err := os.ReadFile(projSettings); err == nil {
				parseClaudeSettings(data, "project:"+entry.Name(), tool)
			}
		}
	}

	// Parse project-level .claude/settings.local.json files
	parseProjectLocalSettings(home, tool)

	// Parse MCP auth cache for cloud MCP servers
	parseMCPAuthCache(home, tool)

	// Filter ports for claude-related processes
	for _, p := range ports {
		pLower := strings.ToLower(p.Process)
		if strings.Contains(pLower, "claude") {
			tool.OpenPorts = append(tool.OpenPorts, p)
		}
	}

	return tool, nil
}

func getClaudeVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "claude", "--version").CombinedOutput()
	if err != nil {
		return ""
	}
	v := strings.TrimSpace(string(out))
	if idx := strings.IndexByte(v, '\n'); idx >= 0 {
		v = v[:idx]
	}
	return v
}

// claudeSettings represents the structure of Claude Code's settings.json.
type claudeSettings struct {
	AIComponents             map[string]claudeAIComponent `json:"mcpServers"`
	EnabledPlugins         map[string]bool            `json:"enabledPlugins"`
	ExtraKnownMarketplaces map[string]json.RawMessage `json:"extraKnownMarketplaces"`
	Permissions            *claudePermissions         `json:"permissions"`
}

type claudeAIComponent struct {
	Command   string            `json:"command"`
	Args      []string          `json:"args"`
	Env       map[string]string `json:"env"`
	Transport string            `json:"type"` // "stdio", "sse", etc.
}

type claudePermissions struct {
	Allow []string `json:"allow"`
	Deny  []string `json:"deny"`
}

func parseClaudeSettings(data []byte, source string, tool *AITool) {
	var settings claudeSettings
	if json.Unmarshal(data, &settings) != nil {
		return
	}

	// Extract MCP servers
	for name, srv := range settings.AIComponents {
		comp := AIComponent{
			Name:      name,
			Type:      "mcp-server",
			Command:   srv.Command,
			Args:      srv.Args,
			Transport: srv.Transport,
			Source:    source,
		}
		if comp.Transport == "" {
			comp.Transport = "stdio"
		}

		// Extract env var names only (never values)
		for k, v := range srv.Env {
			comp.EnvVars = append(comp.EnvVars, k)
			// Check if value looks like a secret
			if looksLikeSecret(v) {
				tool.Secrets = append(tool.Secrets, RedactedSecret{
					Source:        source,
					VariableName:  k,
					RedactedValue: redactSecret(v),
					SecretType:    classifySecret(k, v),
				})
			}
		}

		// Infer permissions from command
		comp.Permissions = inferAIPermissions(srv)
		calculateRisk(&comp)
		tool.Components = append(tool.Components, comp)
	}

	// Extract enabled plugins as skill entries
	for pluginName, enabled := range settings.EnabledPlugins {
		if !enabled {
			continue
		}
		comp := AIComponent{
			Name:      pluginName,
			Type:      "skill",
			Transport: "plugin",
			Source:    source,
			Permissions: AIPermissions{
				// Plugins have broad access by default
				NetworkAccess: true,
			},
		}
		calculateRisk(&comp)
		tool.Components = append(tool.Components, comp)
	}

	// Extract permissions from Claude Code's allow/deny lists
	if settings.Permissions != nil {
		extractClaudePermissions(settings.Permissions, source, tool)
	}

	// Scan the raw data for any secret patterns
	scanForSecrets(data, source, tool)
}

func extractClaudePermissions(perms *claudePermissions, source string, tool *AITool) {
	// Claude Code permissions look like: "Read(path)", "Write(path)", "Bash(command:*)"
	// and "mcp__servername__toolname"
	readPattern := regexp.MustCompile(`Read\(([^)]+)\)`)
	writePattern := regexp.MustCompile(`Write\(([^)]+)\)`)
	bashPattern := regexp.MustCompile(`Bash\(([^)]+)\)`)
	mcpPattern := regexp.MustCompile(`^mcp__([^_]+(?:_[^_]+)*)__(.+)$`)

	var bashCommands []string
	var readPaths []string
	var writePaths []string
	var mcpTools []string

	for _, p := range perms.Allow {
		if matches := readPattern.FindStringSubmatch(p); len(matches) > 1 {
			readPaths = append(readPaths, matches[1])
		}
		if matches := writePattern.FindStringSubmatch(p); len(matches) > 1 {
			writePaths = append(writePaths, matches[1])
		}
		if matches := bashPattern.FindStringSubmatch(p); len(matches) > 1 {
			bashCommands = append(bashCommands, matches[1])
		}
		if matches := mcpPattern.FindStringSubmatch(p); len(matches) > 2 {
			mcpTools = append(mcpTools, matches[1]+"::"+matches[2])
		}
	}

	// Group Bash commands into one "permission" component named "Shell Access"
	if len(bashCommands) > 0 {
		comp := AIComponent{
			Name:   "Shell Access",
			Type:   "permission",
			Source: source,
			Permissions: AIPermissions{
				NetworkAccess: true,
				BashCommands:  bashCommands,
			},
		}
		calculateRisk(&comp)
		tool.Components = append(tool.Components, comp)
	}

	// Group Read paths into one "permission" component named "Filesystem Read"
	if len(readPaths) > 0 {
		comp := AIComponent{
			Name:   "Filesystem Read",
			Type:   "permission",
			Source: source,
			Permissions: AIPermissions{
				FileSystemRead: readPaths,
			},
		}
		calculateRisk(&comp)
		tool.Components = append(tool.Components, comp)
	}

	// Group Write paths into one "permission" component named "Filesystem Write"
	if len(writePaths) > 0 {
		comp := AIComponent{
			Name:   "Filesystem Write",
			Type:   "permission",
			Source: source,
			Permissions: AIPermissions{
				FileSystemWrite: writePaths,
			},
		}
		calculateRisk(&comp)
		tool.Components = append(tool.Components, comp)
	}

	// Group mcp__ entries into one "permission" component named "MCP Tool Access"
	if len(mcpTools) > 0 {
		comp := AIComponent{
			Name:   "MCP Tool Access",
			Type:   "permission",
			Source: source,
			Permissions: AIPermissions{
				MCPTools: mcpTools,
			},
		}
		calculateRisk(&comp)
		tool.Components = append(tool.Components, comp)
	}
}

// parseProjectLocalSettings searches common project directories for
// .claude/settings.local.json files and extracts their permissions.
func parseProjectLocalSettings(home string, tool *AITool) {
	for _, subdir := range projectSearchDirs {
		baseDir := filepath.Join(home, subdir)
		info, err := os.Stat(baseDir)
		if err != nil || !info.IsDir() {
			continue
		}
		entries, err := os.ReadDir(baseDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			localSettingsPath := filepath.Join(baseDir, entry.Name(), ".claude", "settings.local.json")
			data, err := os.ReadFile(localSettingsPath)
			if err != nil {
				continue
			}
			projectName := filepath.Join(subdir, entry.Name())
			parseClaudeSettings(data, "project-local:"+projectName, tool)
		}
	}
}

// parseMCPAuthCache parses ~/.claude/mcp-needs-auth-cache.json to discover
// cloud MCP servers that are configured in Claude Code.
func parseMCPAuthCache(home string, tool *AITool) {
	cachePath := filepath.Join(home, ".claude", "mcp-needs-auth-cache.json")
	data, err := os.ReadFile(cachePath)
	if err != nil {
		return
	}

	var cache map[string]json.RawMessage
	if json.Unmarshal(data, &cache) != nil {
		return
	}

	for serverName := range cache {
		// Check if we already have this server
		found := false
		for _, existing := range tool.Components {
			if existing.Name == serverName {
				found = true
				break
			}
		}
		if found {
			continue
		}

		comp := AIComponent{
			Name:      serverName,
			Type:      "cloud-mcp",
			Transport: "cloud",
			Source:    "mcp-needs-auth-cache.json",
			Permissions: AIPermissions{
				NetworkAccess: true,
			},
		}
		calculateRisk(&comp)
		tool.Components = append(tool.Components, comp)
	}
}

func inferAIPermissions(srv claudeAIComponent) AIPermissions {
	perms := AIPermissions{}

	// Infer from command and args
	allArgs := append([]string{srv.Command}, srv.Args...)
	joined := strings.Join(allArgs, " ")

	if strings.Contains(joined, "filesystem") || strings.Contains(joined, "fs-") {
		perms.FileSystemRead = append(perms.FileSystemRead, "(inferred from command)")
		perms.FileSystemWrite = append(perms.FileSystemWrite, "(inferred from command)")
	}
	if strings.Contains(joined, "fetch") || strings.Contains(joined, "http") ||
		strings.Contains(joined, "api") || strings.Contains(joined, "web") {
		perms.NetworkAccess = true
	}

	// Env vars imply env access
	for k := range srv.Env {
		perms.EnvAccess = append(perms.EnvAccess, k)
	}

	return perms
}
