---
title: IDE & Extension Scanning
nav_order: 1
parent: Features
---

# IDE & Extension Scanning

IDEViewer detects installed IDEs and analyzes their extensions for dangerous permissions that could indicate supply chain risks.

## Supported IDEs

| IDE | Extensions Path | Platform |
|-----|----------------|----------|
| VS Code | `~/.vscode/extensions` | All |
| Cursor | `~/.cursor/extensions` | All |
| VSCodium | `~/.vscode-oss/extensions` | All |
| Kiro | `~/.kiro/extensions` | All |
| JetBrains (IntelliJ, PyCharm, WebStorm, GoLand, CLion, Rider, PhpStorm, RubyMine, DataGrip) | `~/.config/JetBrains/*/plugins` | All |
| Sublime Text | `~/Library/Application Support/Sublime Text/Packages` | macOS |
| Vim / Neovim | `~/.vim`, `~/.config/nvim` | All |
| Xcode | `/Applications/Xcode.app` | macOS |

## CLI Usage

```bash
# Scan all IDEs
ideviewer scan

# Output as JSON
ideviewer scan --json

# Output as SARIF (for CI/CD)
ideviewer scan --output-sarif > results.sarif

# Save to file
ideviewer scan --json -o results.json

# List only dangerous extensions
ideviewer dangerous
```

## Extension Permission Risk Model

Each extension's permissions are analyzed and assigned a risk level:

| Level | Criteria | Examples |
|-------|----------|----------|
| **Critical** | Full system compromise potential | Wildcard activation (`*`), filesystem + shell access combined |
| **High** | Elevated permissions beyond typical use | Authentication providers, terminal access, URI handlers |
| **Medium** | Potentially concerning capabilities | Startup execution (`onStartupFinished`), debugger access |
| **Low** | Standard, expected permissions | Commands, keybindings, themes, snippets |

## How Permissions Are Extracted

For VS Code-family editors, IDEViewer reads each extension's `package.json` and analyzes:

- **`activationEvents`** -- When the extension activates (e.g., `*` means always active, `onStartupFinished` means at startup)
- **`capabilities`** -- Declared capabilities like `untrustedWorkspaces`, `virtualWorkspaces`
- **`contributes`** -- What the extension registers: commands, views, terminal profiles, authentication providers, URI handlers, debuggers

Each permission is classified as dangerous or normal based on its security implications. Extensions with dangerous permissions are flagged in both the CLI output and the portal.

## Portal View

In the portal, click any extension to see its detail view:

- Marketplace metadata (publisher, install count, description)
- Full permission list with risk assessments
- Which hosts have this extension installed
- Extension version across hosts

![Extension Details](../images/Extension%20Details%20and%20Installed%20on.png)
