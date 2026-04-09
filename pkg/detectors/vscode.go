package detectors

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/securient/ideviewer-oss/pkg/scanner"
)

// Dangerous activation-event permissions (matches Python exactly).
var dangerousPermissions = map[string]string{
	"onFileSystem":            "Full file system access",
	"onStartupFinished":       "Runs on startup",
	"onUri":                   "Can register URI handlers",
	"onAuthenticationRequest": "Authentication access",
	"onDebug":                 "Debugger access",
	"onTerminalProfile":       "Terminal access",
	"*":                       "Wildcard activation (runs for everything)",
}

var dangerousCapabilities = map[string]string{
	"untrustedWorkspaces.supported": "Can run in untrusted workspaces",
	"virtualWorkspaces.supported":   "Virtual workspace access",
}

type vscodeVariant struct {
	ideType         scanner.IDEType
	name            string
	executables     map[string][]string
	extensionsPaths map[string][]string
	configPaths     map[string][]string
	processNames    []string
}

var vscodeVariants = []vscodeVariant{
	{
		ideType: scanner.IDETypeVSCode,
		name:    "Visual Studio Code",
		executables: map[string][]string{
			"darwin": {
				"/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code",
				"/usr/local/bin/code",
			},
			"linux": {
				"/usr/bin/code",
				"/usr/share/code/bin/code",
				"/snap/bin/code",
			},
			"windows": {
				`%LOCALAPPDATA%\Programs\Microsoft VS Code\Code.exe`,
				`%ProgramFiles%\Microsoft VS Code\Code.exe`,
			},
		},
		extensionsPaths: map[string][]string{
			"darwin":  {"~/.vscode/extensions"},
			"linux":   {"~/.vscode/extensions"},
			"windows": {`%USERPROFILE%\.vscode\extensions`},
		},
		configPaths: map[string][]string{
			"darwin":  {"~/Library/Application Support/Code"},
			"linux":   {"~/.config/Code"},
			"windows": {`%APPDATA%\Code`},
		},
		processNames: []string{"Code", "code", "Code.exe"},
	},
	{
		ideType: scanner.IDETypeCursor,
		name:    "Cursor",
		executables: map[string][]string{
			"darwin": {
				"/Applications/Cursor.app/Contents/Resources/app/bin/cursor",
				"/usr/local/bin/cursor",
			},
			"linux": {
				"/usr/bin/cursor",
				"/opt/Cursor/cursor",
				"~/.local/bin/cursor",
			},
			"windows": {
				`%LOCALAPPDATA%\Programs\Cursor\Cursor.exe`,
				`%LOCALAPPDATA%\cursor\Cursor.exe`,
			},
		},
		extensionsPaths: map[string][]string{
			"darwin":  {"~/.cursor/extensions"},
			"linux":   {"~/.cursor/extensions"},
			"windows": {`%USERPROFILE%\.cursor\extensions`},
		},
		configPaths: map[string][]string{
			"darwin":  {"~/Library/Application Support/Cursor"},
			"linux":   {"~/.config/Cursor"},
			"windows": {`%APPDATA%\Cursor`},
		},
		processNames: []string{"Cursor", "cursor", "Cursor.exe"},
	},
	{
		ideType: scanner.IDETypeVSCodium,
		name:    "VSCodium",
		executables: map[string][]string{
			"darwin": {
				"/Applications/VSCodium.app/Contents/Resources/app/bin/codium",
				"/usr/local/bin/codium",
			},
			"linux": {
				"/usr/bin/codium",
				"/snap/bin/codium",
			},
			"windows": {
				`%LOCALAPPDATA%\Programs\VSCodium\VSCodium.exe`,
				`%ProgramFiles%\VSCodium\VSCodium.exe`,
			},
		},
		extensionsPaths: map[string][]string{
			"darwin":  {"~/.vscode-oss/extensions"},
			"linux":   {"~/.vscode-oss/extensions"},
			"windows": {`%USERPROFILE%\.vscode-oss\extensions`},
		},
		configPaths: map[string][]string{
			"darwin":  {"~/Library/Application Support/VSCodium"},
			"linux":   {"~/.config/VSCodium"},
			"windows": {`%APPDATA%\VSCodium`},
		},
		processNames: []string{"VSCodium", "codium", "VSCodium.exe"},
	},
}

// VSCodeDetector detects VS Code, Cursor, and VSCodium.
type VSCodeDetector struct{}

func (d *VSCodeDetector) Name() string { return "vscode" }

func (d *VSCodeDetector) Detect() ([]scanner.IDE, error) {
	var ides []scanner.IDE
	plat := PlatformKey()
	for _, v := range vscodeVariants {
		ide, ok := detectVariant(v, plat)
		if ok {
			ide.Extensions = parseVSCodeExtensions(ide.ExtensionsPath, v.ideType)
			ides = append(ides, ide)
		}
	}
	return ides, nil
}

func detectVariant(v vscodeVariant, plat string) (scanner.IDE, bool) {
	var installPath, extensionsPath, configPath string

	for _, p := range v.executables[plat] {
		ep := ExpandPath(p)
		if info, err := os.Stat(ep); err == nil && !info.IsDir() {
			installPath = ep
			break
		}
	}
	for _, p := range v.extensionsPaths[plat] {
		ep := ExpandPath(p)
		if info, err := os.Stat(ep); err == nil && info.IsDir() {
			extensionsPath = ep
			break
		}
	}
	if installPath == "" && extensionsPath == "" {
		return scanner.IDE{}, false
	}
	for _, p := range v.configPaths[plat] {
		ep := ExpandPath(p)
		if info, err := os.Stat(ep); err == nil && info.IsDir() {
			configPath = ep
			break
		}
	}

	var version string
	if installPath != "" {
		version = GetVersion(installPath)
	}

	return scanner.IDE{
		IDEType:        v.ideType,
		Name:           v.name,
		Version:        version,
		InstallPath:    installPath,
		ConfigPath:     configPath,
		ExtensionsPath: extensionsPath,
		IsRunning:      IsProcessRunning(v.processNames...),
	}, true
}

// parseVSCodeExtensions scans the extensions directory for package.json files.
func parseVSCodeExtensions(extensionsDir string, ideType scanner.IDEType) []scanner.Extension {
	if extensionsDir == "" {
		return nil
	}
	entries, err := os.ReadDir(extensionsDir)
	if err != nil {
		return nil
	}
	var exts []scanner.Extension
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		ext, ok := parseVSCodeExtension(filepath.Join(extensionsDir, entry.Name()), ideType)
		if ok {
			exts = append(exts, ext)
		}
	}
	return exts
}

type vscodePkgJSON struct {
	Name                 string            `json:"name"`
	DisplayName          string            `json:"displayName"`
	Version              string            `json:"version"`
	Publisher            string            `json:"publisher"`
	Description          string            `json:"description"`
	Homepage             string            `json:"homepage"`
	License              string            `json:"license"`
	Repository           json.RawMessage   `json:"repository"`
	Author               json.RawMessage   `json:"author"`
	ActivationEvents     []string          `json:"activationEvents"`
	Capabilities         map[string]any    `json:"capabilities"`
	Contributes          map[string]any    `json:"contributes"`
	ExtensionDeps        []string          `json:"extensionDependencies"`
}

func parseVSCodeExtension(dir string, ideType scanner.IDEType) (scanner.Extension, bool) {
	pkgPath := filepath.Join(dir, "package.json")
	data, err := os.ReadFile(pkgPath)
	if err != nil {
		return scanner.Extension{}, false
	}
	// Compute content hash for change detection
	contentHash := fmt.Sprintf("%x", sha256.Sum256(data))

	var pkg vscodePkgJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return scanner.Extension{}, false
	}

	folderName := filepath.Base(dir)
	extID := pkg.Name
	if extID == "" {
		extID = folderName
	}
	if pkg.Publisher != "" {
		extID = pkg.Publisher + "." + extID
	}

	// Repository can be string or object
	repo := parseRepository(pkg.Repository)

	// Author / maintainer
	maintainer := parseAuthor(pkg.Author)

	// Marketplace URL
	var marketplaceURL string
	switch ideType {
	case scanner.IDETypeVSCode:
		marketplaceURL = "https://marketplace.visualstudio.com/items?itemName=" + extID
	case scanner.IDETypeVSCodium:
		marketplaceURL = fmt.Sprintf("https://open-vsx.org/extension/%s/%s", pkg.Publisher, pkg.Name)
	}

	// Last updated from file mtime
	var lastUpdated *time.Time
	if info, err := os.Stat(pkgPath); err == nil {
		t := info.ModTime()
		lastUpdated = &t
	}

	isBuiltin := strings.Contains(strings.ToLower(dir), "ms-vscode") &&
		strings.Contains(strings.ToLower(dir), "builtin")

	displayName := pkg.DisplayName
	if displayName == "" {
		displayName = pkg.Name
		if displayName == "" {
			displayName = folderName
		}
	}

	permissions := extractVSCodePermissions(pkg)
	contributes := summarizeContributes(pkg.Contributes)

	return scanner.Extension{
		ID:               extID,
		Name:             displayName,
		Version:          pkg.Version,
		Publisher:        pkg.Publisher,
		Maintainer:       maintainer,
		Description:      pkg.Description,
		Homepage:         pkg.Homepage,
		Repository:       repo,
		License:          pkg.License,
		InstallPath:      dir,
		Permissions:      permissions,
		Contributes:      contributes,
		Dependencies:     pkg.ExtensionDeps,
		Enabled:          true,
		Builtin:          isBuiltin,
		LastUpdated:      lastUpdated,
		MarketplaceURL:   marketplaceURL,
		ActivationEvents: pkg.ActivationEvents,
		Capabilities:     pkg.Capabilities,
		ContentHash:      contentHash,
	}, true
}

func extractVSCodePermissions(pkg vscodePkgJSON) []scanner.Permission {
	var perms []scanner.Permission
	seen := make(map[string]bool)

	// Activation events
	for _, event := range pkg.ActivationEvents {
		eventType := event
		if idx := strings.IndexByte(event, ':'); idx >= 0 {
			eventType = event[:idx]
		}
		if desc, ok := dangerousPermissions[eventType]; ok && !seen[eventType] {
			seen[eventType] = true
			perms = append(perms, scanner.Permission{Name: eventType, Description: desc, IsDangerous: true})
		} else if event == "*" && !seen["*"] {
			seen["*"] = true
			perms = append(perms, scanner.Permission{Name: "*", Description: dangerousPermissions["*"], IsDangerous: true})
		}
	}

	// Capabilities
	capStr := fmt.Sprintf("%v", pkg.Capabilities)
	for capName, capDesc := range dangerousCapabilities {
		if strings.Contains(capStr, capName) && !seen[capName] {
			seen[capName] = true
			perms = append(perms, scanner.Permission{Name: capName, Description: capDesc, IsDangerous: true})
		}
	}

	// Contributes
	if pkg.Contributes != nil {
		if _, ok := pkg.Contributes["authentication"]; ok && !seen["authentication"] {
			seen["authentication"] = true
			perms = append(perms, scanner.Permission{Name: "authentication", Description: "Provides authentication providers", IsDangerous: true})
		}
		if _, ok := pkg.Contributes["terminal"]; ok && !seen["terminal"] {
			seen["terminal"] = true
			perms = append(perms, scanner.Permission{Name: "terminal", Description: "Terminal integration", IsDangerous: true})
		}
		if _, ok := pkg.Contributes["debuggers"]; ok && !seen["debuggers"] {
			seen["debuggers"] = true
			perms = append(perms, scanner.Permission{Name: "debuggers", Description: "Debugger integration", IsDangerous: false})
		}
		if _, ok := pkg.Contributes["taskDefinitions"]; ok && !seen["taskDefinitions"] {
			seen["taskDefinitions"] = true
			perms = append(perms, scanner.Permission{Name: "taskDefinitions", Description: "Can define tasks (may execute commands)", IsDangerous: true})
		}
		if cmds, ok := pkg.Contributes["commands"]; ok && !seen["commands"] {
			seen["commands"] = true
			count := 0
			if arr, ok := cmds.([]any); ok {
				count = len(arr)
			}
			perms = append(perms, scanner.Permission{Name: "commands", Description: fmt.Sprintf("Registers %d commands", count), IsDangerous: false})
		}
	}

	return perms
}

func summarizeContributes(contributes map[string]any) map[string]any {
	if contributes == nil {
		return nil
	}
	summary := make(map[string]any, len(contributes))
	for k, v := range contributes {
		switch val := v.(type) {
		case []any:
			summary[k] = len(val)
		case map[string]any:
			summary[k] = len(val)
		default:
			summary[k] = 1
		}
	}
	return summary
}

func parseRepository(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var obj struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(raw, &obj) == nil {
		return obj.URL
	}
	return ""
}

func parseAuthor(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var obj struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(raw, &obj) == nil {
		return obj.Name
	}
	return ""
}
