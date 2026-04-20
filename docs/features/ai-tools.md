---
title: AI Tools & MCP Detection
nav_order: 4
parent: Features
---

# AI Tools & MCP Detection

IDEViewer detects AI coding assistants and their configurations, identifying insecure settings that could expose sensitive data or grant excessive permissions.

## Why AI Tools Are a Security Risk

AI coding assistants often:

- Connect to external MCP servers that access email, calendars, and internal systems
- Execute shell commands with broad or wildcard permissions
- Store API keys in plaintext config files
- Enable autonomous execution without human approval
- Use unencrypted HTTP transport for sensitive data

Traditional security tools do not monitor these configurations. IDEViewer does.

## Detected Tools

| Tool | What's Detected |
|------|----------------|
| **Claude Code** | Enabled skills/plugins, cloud MCP servers (Gmail, Calendar, etc.), per-project permissions (Bash, Read, Write, MCP tools), API keys (redacted) |
| **Cursor** | MCP server configs from `mcp.json` and VS Code settings, environment variables, permissions |
| **Kiro** | MCP server configs from `~/.kiro/settings/mcp.json`, remote MCP servers (SSE/HTTP), environment variables, auto-approve permissions |
| **OpenClaw** | LLM providers, Slack/Telegram integrations, bot tokens (redacted), autonomous execution flags, insecure transport |

## Component Types

Each detected AI component is classified by type:

| Type | Description |
|------|-------------|
| `skill` | A capability or plugin enabled in the AI tool |
| `mcp-server` | A locally configured Model Context Protocol server |
| `cloud-mcp` | A cloud-hosted MCP server (e.g., Gmail, Google Calendar) |
| `integration` | An external service integration (Slack, Telegram) |
| `permission` | A granted permission (Bash access, file read/write) |

## Risk Scoring

Each component is assigned a risk score based on its security implications:

| Risk Level | Criteria | Examples |
|------------|----------|----------|
| **Critical** | Direct path to data exfiltration or system compromise | Wildcard bash access (`Bash(*)`), plaintext API keys in config |
| **High** | Significant security exposure | Autonomous execution enabled, external integrations (Slack/Telegram), insecure HTTP transport |
| **Medium** | Elevated access that warrants monitoring | Cloud MCP with data access (Gmail, Calendar), shell command permissions |
| **Low** | Standard capabilities with limited risk | Skills with network access, read-only file permissions |
| **Info** | Informational, no direct security concern | Tool version, basic configuration metadata |

## Detection Details

### Claude Code

IDEViewer reads Claude Code's configuration files to detect:

- **Plugins/skills** -- Enabled capabilities and their permission scope
- **Cloud MCP servers** -- Connected cloud services (Gmail, Google Calendar, etc.) and their granted scopes
- **Project permissions** -- Per-project tool permissions:
  - `Bash(*)` -- Wildcard shell access (Critical)
  - `Read`, `Write` -- File system access permissions
  - `mcp__*` -- MCP tool permissions granted to the AI
- **API keys** -- Detects presence of API keys (values are redacted, never transmitted)

### Cursor

IDEViewer reads MCP configuration from:

- `~/.cursor/mcp.json` -- Primary MCP config file
- VS Code settings (`settings.json`) -- MCP servers configured as VS Code settings
- Environment variables referenced in MCP configs

### Kiro

IDEViewer reads MCP configuration from:

- `~/.kiro/settings/mcp.json` -- Primary MCP config file (global)
- `.kiro/settings/mcp.json` -- Workspace-level MCP config
- VS Code settings (`settings.json`) -- MCP servers configured as VS Code settings
- Environment variables referenced in MCP configs

Kiro supports both local (stdio) and remote (SSE/HTTP) MCP servers. IDEViewer detects both types and flags remote servers using unencrypted HTTP as high risk. Auto-approved MCP tools are also flagged as they execute without user confirmation.

### OpenClaw

IDEViewer scans OpenClaw configuration for:

- **LLM providers** -- Configured AI model providers and their API endpoints
- **Integrations** -- Slack bots, Telegram bots, and their tokens (redacted)
- **Autonomous execution** -- Whether the agent can execute actions without human approval
- **Transport security** -- Flags HTTP (unencrypted) connections as High risk
- **Bot tokens** -- Detects Slack/Telegram bot tokens (values redacted)

## Port Scanning

IDEViewer scans for running AI tool processes and their listening ports, identifying active MCP servers and AI agents on the machine.

## Secret Detection in AI Configs

API keys and tokens found in AI tool configuration files are flagged but **never transmitted**. Only the presence, type, and location are reported.

## Privacy

{: .important }
IDEViewer **never reads AI conversation content**. It only analyzes configuration metadata, permission sets, and connection details. No prompts, responses, or conversation history are accessed.
