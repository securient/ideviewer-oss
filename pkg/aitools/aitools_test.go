package aitools

import (
	"encoding/json"
	"testing"
)

func TestParseMCPServers_LocalStdio(t *testing.T) {
	servers := map[string]MCPServerConfig{
		"test-stdio": {
			Command: "npx",
			Args:    []string{"-y", "my-server"},
			Env: map[string]string{
				"NODE_ENV": "production",
				"DEBUG":    "true",
			},
		},
	}

	tool := &AITool{}
	parseMCPServers(servers, "test-source", tool)

	if len(tool.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(tool.Components))
	}

	comp := tool.Components[0]
	if comp.Name != "test-stdio" {
		t.Errorf("Name = %q, want %q", comp.Name, "test-stdio")
	}
	if comp.Type != "mcp-server" {
		t.Errorf("Type = %q, want %q", comp.Type, "mcp-server")
	}
	if comp.Transport != "stdio" {
		t.Errorf("Transport = %q, want %q", comp.Transport, "stdio")
	}
	if comp.Command != "npx" {
		t.Errorf("Command = %q, want %q", comp.Command, "npx")
	}
	if len(comp.Args) != 2 || comp.Args[0] != "-y" || comp.Args[1] != "my-server" {
		t.Errorf("Args = %v, want [-y my-server]", comp.Args)
	}

	// Env vars should be recorded (order may vary)
	envSet := make(map[string]bool)
	for _, e := range comp.EnvVars {
		envSet[e] = true
	}
	if !envSet["NODE_ENV"] || !envSet["DEBUG"] {
		t.Errorf("EnvVars = %v, want NODE_ENV and DEBUG", comp.EnvVars)
	}

	accessSet := make(map[string]bool)
	for _, e := range comp.Permissions.EnvAccess {
		accessSet[e] = true
	}
	if !accessSet["NODE_ENV"] || !accessSet["DEBUG"] {
		t.Errorf("Permissions.EnvAccess = %v, want NODE_ENV and DEBUG", comp.Permissions.EnvAccess)
	}
}

func TestParseMCPServers_RemoteSSE(t *testing.T) {
	servers := map[string]MCPServerConfig{
		"remote-sse": {
			URL: "https://mcp.example.com/sse",
		},
	}

	tool := &AITool{}
	parseMCPServers(servers, "test-source", tool)

	if len(tool.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(tool.Components))
	}

	comp := tool.Components[0]
	if comp.Transport != "sse" {
		t.Errorf("Transport = %q, want %q", comp.Transport, "sse")
	}
	if comp.Command != "https://mcp.example.com/sse" {
		t.Errorf("Command = %q, want URL", comp.Command)
	}
	if !comp.Permissions.NetworkAccess {
		t.Error("expected NetworkAccess = true for remote SSE server")
	}
}

func TestParseMCPServers_RemoteHTTPInsecure(t *testing.T) {
	servers := map[string]MCPServerConfig{
		"insecure-http": {
			URL: "http://mcp.example.com/sse",
		},
	}

	tool := &AITool{}
	parseMCPServers(servers, "test-source", tool)

	if len(tool.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(tool.Components))
	}

	comp := tool.Components[0]
	if comp.Risk != "high" {
		t.Errorf("Risk = %q, want %q", comp.Risk, "high")
	}
	if comp.RiskReason == "" {
		t.Error("expected RiskReason to be set for insecure HTTP")
	}
	if comp.RiskReason != "Unencrypted HTTP transport for MCP server" {
		t.Errorf("RiskReason = %q, want mention of unencrypted HTTP", comp.RiskReason)
	}
}

func TestParseMCPServers_SecretsInEnv(t *testing.T) {
	servers := map[string]MCPServerConfig{
		"secret-server": {
			Command: "node",
			Args:    []string{"server.js"},
			Env: map[string]string{
				"API_KEY": "sk-ant-abcdefghijklmnopqrstuvwxyz123456",
			},
		},
	}

	tool := &AITool{}
	parseMCPServers(servers, "test-source", tool)

	if len(tool.Secrets) == 0 {
		t.Fatal("expected at least 1 secret, got 0")
	}

	found := false
	for _, s := range tool.Secrets {
		if s.VariableName == "API_KEY" {
			found = true
			if s.RedactedValue == "sk-ant-abcdefghijklmnopqrstuvwxyz123456" {
				t.Error("secret value should be redacted, got full value")
			}
			if s.RedactedValue == "" {
				t.Error("redacted value should not be empty")
			}
			if s.SecretType != "anthropic_api_key" {
				t.Errorf("SecretType = %q, want %q", s.SecretType, "anthropic_api_key")
			}
			break
		}
	}
	if !found {
		t.Error("expected a secret with VariableName=API_KEY")
	}
}

func TestParseMCPServers_SecretsInHeaders(t *testing.T) {
	servers := map[string]MCPServerConfig{
		"header-secret": {
			URL: "https://mcp.example.com/sse",
			Headers: map[string]string{
				"Authorization": "sk-ant-abcdefghijklmnopqrstuvwxyz123456",
			},
		},
	}

	tool := &AITool{}
	parseMCPServers(servers, "test-source", tool)

	if len(tool.Secrets) == 0 {
		t.Fatal("expected at least 1 secret from headers, got 0")
	}

	found := false
	for _, s := range tool.Secrets {
		if s.VariableName == "header:Authorization" {
			found = true
			if s.RedactedValue == "sk-ant-abcdefghijklmnopqrstuvwxyz123456" {
				t.Error("secret value should be redacted")
			}
			break
		}
	}
	if !found {
		t.Errorf("expected secret with VariableName='header:Authorization', got %v", tool.Secrets)
	}
}

func TestParseMCPServers_AutoApprove(t *testing.T) {
	servers := map[string]MCPServerConfig{
		"auto-approve-server": {
			Command:     "node",
			Args:        []string{"server.js"},
			AutoApprove: []string{"read", "write"},
		},
	}

	tool := &AITool{}
	parseMCPServers(servers, "test-source", tool)

	if len(tool.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(tool.Components))
	}

	comp := tool.Components[0]
	if len(comp.Permissions.MCPTools) != 2 {
		t.Fatalf("MCPTools = %v, want [read write]", comp.Permissions.MCPTools)
	}

	toolSet := make(map[string]bool)
	for _, mt := range comp.Permissions.MCPTools {
		toolSet[mt] = true
	}
	if !toolSet["read"] || !toolSet["write"] {
		t.Errorf("MCPTools = %v, want read and write", comp.Permissions.MCPTools)
	}

	// After parseMCPServers, calculateRisk should have been called.
	if comp.Risk != "high" {
		t.Errorf("Risk = %q, want %q for auto-approved MCP tools", comp.Risk, "high")
	}
	if comp.RiskReason == "" {
		t.Error("expected RiskReason to mention auto-approved")
	}
}

func TestParseMCPServers_PermissionInference(t *testing.T) {
	t.Run("filesystem inference", func(t *testing.T) {
		servers := map[string]MCPServerConfig{
			"fs-server": {
				Command: "npx",
				Args:    []string{"-y", "@modelcontextprotocol/server-filesystem", "/tmp"},
			},
		}

		tool := &AITool{}
		parseMCPServers(servers, "test-source", tool)

		if len(tool.Components) != 1 {
			t.Fatalf("expected 1 component, got %d", len(tool.Components))
		}

		comp := tool.Components[0]
		if len(comp.Permissions.FileSystemRead) == 0 {
			t.Error("expected FileSystemRead to be populated with (inferred)")
		}
		if len(comp.Permissions.FileSystemWrite) == 0 {
			t.Error("expected FileSystemWrite to be populated with (inferred)")
		}
		if len(comp.Permissions.FileSystemRead) > 0 && comp.Permissions.FileSystemRead[0] != "(inferred)" {
			t.Errorf("FileSystemRead[0] = %q, want %q", comp.Permissions.FileSystemRead[0], "(inferred)")
		}
	})

	t.Run("network inference from fetch", func(t *testing.T) {
		servers := map[string]MCPServerConfig{
			"fetch-server": {
				Command: "npx",
				Args:    []string{"-y", "@modelcontextprotocol/server-fetch"},
			},
		}

		tool := &AITool{}
		parseMCPServers(servers, "test-source", tool)

		if len(tool.Components) != 1 {
			t.Fatalf("expected 1 component, got %d", len(tool.Components))
		}

		comp := tool.Components[0]
		if !comp.Permissions.NetworkAccess {
			t.Error("expected NetworkAccess = true for fetch-containing command")
		}
	})
}

func TestParseMCPConfigFile(t *testing.T) {
	configJSON := `{"mcpServers": {"test-server": {"command": "node", "args": ["server.js"]}}}`

	tool := &AITool{}
	parseMCPConfigFile([]byte(configJSON), "mcp.json", tool)

	if len(tool.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(tool.Components))
	}

	comp := tool.Components[0]
	if comp.Name != "test-server" {
		t.Errorf("Name = %q, want %q", comp.Name, "test-server")
	}
	if comp.Command != "node" {
		t.Errorf("Command = %q, want %q", comp.Command, "node")
	}
	if len(comp.Args) != 1 || comp.Args[0] != "server.js" {
		t.Errorf("Args = %v, want [server.js]", comp.Args)
	}
	if comp.Type != "mcp-server" {
		t.Errorf("Type = %q, want %q", comp.Type, "mcp-server")
	}
	if comp.Source != "mcp.json" {
		t.Errorf("Source = %q, want %q", comp.Source, "mcp.json")
	}
}

func TestParseMCPFromVSCodeSettings_AllKeyVariants(t *testing.T) {
	tests := []struct {
		name       string
		settings   string
		wantServer string
	}{
		{
			name:       "mcp.servers key",
			settings:   `{"mcp.servers": {"srv1": {"command": "a"}}}`,
			wantServer: "srv1",
		},
		{
			name:       "mcpServers key",
			settings:   `{"mcpServers": {"srv2": {"command": "b"}}}`,
			wantServer: "srv2",
		},
		{
			name:       "mcp.servers nested",
			settings:   `{"mcp": {"servers": {"srv3": {"command": "c"}}}}`,
			wantServer: "srv3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tool := &AITool{}
			parseMCPFromVSCodeSettings([]byte(tt.settings), "settings.json", tool)

			found := false
			for _, comp := range tool.Components {
				if comp.Name == tt.wantServer {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected to find component %q, components: %v", tt.wantServer, tool.Components)
			}
		})
	}
}

func TestParseMCPFromVSCodeSettings_ScansForSecrets(t *testing.T) {
	// Embed a raw API key in a settings value to confirm scanForSecrets is called.
	settings := `{
		"mcp.servers": {
			"test": {
				"command": "node",
				"args": ["server.js"]
			}
		},
		"someOtherSetting": "prefix sk-ant-abcdefghijklmnopqrstuvwxyz123456 suffix"
	}`

	tool := &AITool{}
	parseMCPFromVSCodeSettings([]byte(settings), "settings.json", tool)

	if len(tool.Secrets) == 0 {
		t.Fatal("expected scanForSecrets to find the embedded API key")
	}

	found := false
	for _, s := range tool.Secrets {
		if s.SecretType == "anthropic_api_key" {
			found = true
			if s.VariableName != "(embedded in config)" {
				t.Errorf("VariableName = %q, want %q", s.VariableName, "(embedded in config)")
			}
			break
		}
	}
	if !found {
		t.Errorf("expected an anthropic_api_key secret, got %v", tool.Secrets)
	}
}

func TestCalculateRisk(t *testing.T) {
	tests := []struct {
		name       string
		comp       AIComponent
		wantRisk   string
		wantReason string
	}{
		{
			name: "wildcard bash is critical",
			comp: AIComponent{
				Type:        "mcp-server",
				Permissions: AIPermissions{BashCommands: []string{"*"}},
			},
			wantRisk: "critical",
		},
		{
			name: "bash suffix wildcard is critical",
			comp: AIComponent{
				Type:        "mcp-server",
				Permissions: AIPermissions{BashCommands: []string{"Bash(*)"}},
			},
			wantRisk: "critical",
		},
		{
			name: "integration with network is high",
			comp: AIComponent{
				Type:        "integration",
				Permissions: AIPermissions{NetworkAccess: true},
			},
			wantRisk: "high",
		},
		{
			name: "mcp-server with auto-approved tools is high",
			comp: AIComponent{
				Type:        "mcp-server",
				Permissions: AIPermissions{MCPTools: []string{"read", "write"}},
			},
			wantRisk: "high",
		},
		{
			name: "cloud-mcp is medium",
			comp: AIComponent{
				Type: "cloud-mcp",
			},
			wantRisk: "medium",
		},
		{
			name: "mcp-server with network and filesystem is medium",
			comp: AIComponent{
				Type: "mcp-server",
				Permissions: AIPermissions{
					NetworkAccess:  true,
					FileSystemRead: []string{"/tmp"},
				},
			},
			wantRisk: "medium",
		},
		{
			name: "permission with bash commands is medium",
			comp: AIComponent{
				Type:        "permission",
				Permissions: AIPermissions{BashCommands: []string{"ls", "cat"}},
			},
			wantRisk: "medium",
		},
		{
			name: "skill with network is low",
			comp: AIComponent{
				Type:        "skill",
				Permissions: AIPermissions{NetworkAccess: true},
			},
			wantRisk: "low",
		},
		{
			name: "default is info",
			comp: AIComponent{
				Type: "mcp-server",
			},
			wantRisk: "info",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comp := tt.comp
			calculateRisk(&comp)
			if comp.Risk != tt.wantRisk {
				t.Errorf("Risk = %q, want %q (reason: %q)", comp.Risk, tt.wantRisk, comp.RiskReason)
			}
			if tt.wantReason != "" && comp.RiskReason != tt.wantReason {
				t.Errorf("RiskReason = %q, want %q", comp.RiskReason, tt.wantReason)
			}
		})
	}
}

func TestLooksLikeSecret(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{
			name:  "Anthropic API key",
			value: "sk-ant-abc123def456ghi789jkl012",
			want:  true,
		},
		{
			name:  "GitHub personal access token",
			value: "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
			want:  true,
		},
		{
			name:  "too short",
			value: "short",
			want:  false,
		},
		{
			name:  "normal value with spaces",
			value: "just a normal value",
			want:  false,
		},
		{
			name:  "AWS access key",
			value: "AKIAIOSFODNN7EXAMPLE",
			want:  true,
		},
		{
			name:  "OpenAI API key",
			value: "sk-abcdefghijklmnopqrstuvwxyz",
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := looksLikeSecret(tt.value)
			if got != tt.want {
				t.Errorf("looksLikeSecret(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestClassifySecret(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		value    string
		wantType string
	}{
		{
			name:     "Anthropic API key by key name",
			key:      "ANTHROPIC_API_KEY",
			value:    "sk-ant-abcdefghijklmnopqrstuvwxyz123456",
			wantType: "anthropic_api_key",
		},
		{
			name:     "Anthropic API key by value prefix",
			key:      "SOME_KEY",
			value:    "sk-ant-abcdefghijklmnopqrstuvwxyz123456",
			wantType: "anthropic_api_key",
		},
		{
			name:     "GitHub token by key name",
			key:      "GITHUB_TOKEN",
			value:    "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
			wantType: "github_token",
		},
		{
			name:     "GitHub token by value prefix",
			key:      "MY_TOKEN",
			value:    "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
			wantType: "github_token",
		},
		{
			name:     "AWS access key",
			key:      "AWS_ACCESS_KEY_ID",
			value:    "AKIAIOSFODNN7EXAMPLE",
			wantType: "aws_access_key",
		},
		{
			name:     "generic token by key name",
			key:      "SOME_TOKEN",
			value:    "",
			wantType: "token",
		},
		{
			name:     "OpenAI API key",
			key:      "OPENAI_API_KEY",
			value:    "sk-abcdefghijklmnopqrstuvwxyz",
			wantType: "openai_api_key",
		},
		{
			name:     "generic api_key by key name",
			key:      "MY_SECRET",
			value:    "somevalue",
			wantType: "api_key",
		},
		{
			name:     "unknown credential",
			key:      "RANDOM_THING",
			value:    "somevalue",
			wantType: "credential",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifySecret(tt.key, tt.value)
			if got != tt.wantType {
				t.Errorf("classifySecret(%q, %q) = %q, want %q", tt.key, tt.value, got, tt.wantType)
			}
		})
	}
}

func TestRedactSecret(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "short value fully redacted",
			value: "abc123",
			want:  "****",
		},
		{
			name:  "exactly 12 chars fully redacted",
			value: "123456789012",
			want:  "****",
		},
		{
			name:  "longer value shows first 4 and last 4",
			value: "sk-ant-abcdefghijklmnop",
			want:  "sk-a****mnop",
		},
		{
			name:  "13 chars shows prefix and suffix",
			value: "1234567890123",
			want:  "1234****0123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redactSecret(tt.value)
			if got != tt.want {
				t.Errorf("redactSecret(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestScanForSecrets(t *testing.T) {
	data := []byte(`{
		"config": "some value with sk-ant-abcdefghijklmnopqrstuvwxyz123456 embedded",
		"other": "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
	}`)

	tool := &AITool{}
	scanForSecrets(data, "test.json", tool)

	if len(tool.Secrets) < 2 {
		t.Fatalf("expected at least 2 secrets, got %d", len(tool.Secrets))
	}

	typeSet := make(map[string]bool)
	for _, s := range tool.Secrets {
		typeSet[s.SecretType] = true
		if s.Source != "test.json" {
			t.Errorf("Source = %q, want %q", s.Source, "test.json")
		}
		if s.VariableName != "(embedded in config)" {
			t.Errorf("VariableName = %q, want %q", s.VariableName, "(embedded in config)")
		}
	}

	if !typeSet["anthropic_api_key"] {
		t.Error("expected to find anthropic_api_key secret type")
	}
	if !typeSet["github_token"] {
		t.Error("expected to find github_token secret type")
	}
}

func TestScanForSecrets_NoDuplicates(t *testing.T) {
	// Pre-populate a secret with matching redacted value
	secret := "sk-ant-abcdefghijklmnopqrstuvwxyz123456"
	tool := &AITool{
		Secrets: []RedactedSecret{
			{
				Source:        "env",
				VariableName:  "API_KEY",
				RedactedValue: redactSecret(secret),
				SecretType:    "anthropic_api_key",
			},
		},
	}

	data := []byte(`{"key": "` + secret + `"}`)
	scanForSecrets(data, "test.json", tool)

	// Should not add a duplicate
	if len(tool.Secrets) != 1 {
		t.Errorf("expected 1 secret (no duplicate), got %d", len(tool.Secrets))
	}
}

func TestParseMCPConfigFile_InvalidJSON(t *testing.T) {
	tool := &AITool{}
	parseMCPConfigFile([]byte("not valid json"), "bad.json", tool)

	if len(tool.Components) != 0 {
		t.Errorf("expected 0 components for invalid JSON, got %d", len(tool.Components))
	}
}

func TestParseMCPFromVSCodeSettings_InvalidJSON(t *testing.T) {
	tool := &AITool{}
	parseMCPFromVSCodeSettings([]byte("not valid json"), "settings.json", tool)

	if len(tool.Components) != 0 {
		t.Errorf("expected 0 components for invalid JSON, got %d", len(tool.Components))
	}
}

func TestParseMCPServersRaw_ValidJSON(t *testing.T) {
	raw := json.RawMessage(`{"my-server": {"command": "node", "args": ["index.js"]}}`)

	tool := &AITool{}
	parseMCPServersRaw(raw, "test-source", tool)

	if len(tool.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(tool.Components))
	}
	if tool.Components[0].Name != "my-server" {
		t.Errorf("Name = %q, want %q", tool.Components[0].Name, "my-server")
	}
}

func TestParseMCPServersRaw_InvalidJSON(t *testing.T) {
	raw := json.RawMessage(`not valid`)

	tool := &AITool{}
	parseMCPServersRaw(raw, "test-source", tool)

	if len(tool.Components) != 0 {
		t.Errorf("expected 0 components for invalid JSON, got %d", len(tool.Components))
	}
}

func TestContainsWildcard(t *testing.T) {
	tests := []struct {
		name     string
		commands []string
		want     bool
	}{
		{"star wildcard", []string{"*"}, true},
		{"suffix wildcard", []string{"bash:*"}, true},
		{"Bash star", []string{"Bash(*)"}, true},
		{"no wildcard", []string{"ls", "cat"}, false},
		{"empty", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comp := &AIComponent{
				Permissions: AIPermissions{BashCommands: tt.commands},
			}
			got := containsWildcard(comp)
			if got != tt.want {
				t.Errorf("containsWildcard(%v) = %v, want %v", tt.commands, got, tt.want)
			}
		})
	}
}

func TestNewScanner(t *testing.T) {
	scanner := NewScanner()
	if scanner == nil {
		t.Error("NewScanner() returned nil")
	}
}
