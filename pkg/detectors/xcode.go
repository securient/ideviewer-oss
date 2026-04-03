//go:build darwin

package detectors

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"howett.net/plist"

	"github.com/securient/ideviewer-oss/pkg/scanner"
)

// XcodeDetector detects Xcode on macOS.
type XcodeDetector struct{}

func (d *XcodeDetector) Name() string { return "xcode" }

func (d *XcodeDetector) Detect() ([]scanner.IDE, error) {
	xcodePath := findXcode()
	if xcodePath == "" {
		return nil, nil
	}

	version := xcodeVersion(xcodePath)
	home := HomeDir()

	pluginsPath := filepath.Join(home, "Library", "Developer", "Xcode", "Plug-ins")
	var extensionsPath string
	if PathExists(pluginsPath) {
		extensionsPath = pluginsPath
	}

	ide := scanner.IDE{
		IDEType:        scanner.IDETypeXcode,
		Name:           "Xcode",
		Version:        version,
		InstallPath:    xcodePath,
		ConfigPath:     filepath.Join(home, "Library", "Developer", "Xcode"),
		ExtensionsPath: extensionsPath,
		IsRunning:      IsProcessRunning("Xcode"),
	}

	ide.Extensions = parseXcodeExtensions(extensionsPath, home)
	return []scanner.IDE{ide}, nil
}

func findXcode() string {
	if PathExists("/Applications/Xcode.app") {
		return "/Applications/Xcode.app"
	}
	// Try xcode-select
	out, err := exec.Command("xcode-select", "-p").Output()
	if err == nil {
		devPath := strings.TrimSpace(string(out))
		if strings.Contains(devPath, "Xcode") {
			// e.g. /Applications/Xcode.app/Contents/Developer -> /Applications/Xcode.app
			parts := strings.SplitAfter(devPath, ".app")
			if len(parts) > 0 && PathExists(parts[0]) {
				return parts[0]
			}
		}
	}
	return ""
}

type infoPlist struct {
	CFBundleName                string            `plist:"CFBundleName"`
	CFBundleShortVersionString  string            `plist:"CFBundleShortVersionString"`
	CFBundleVersion             string            `plist:"CFBundleVersion"`
	CFBundleIdentifier          string            `plist:"CFBundleIdentifier"`
	NSExtension                 *nsExtensionInfo  `plist:"NSExtension"`
}

type nsExtensionInfo struct {
	NSExtensionPointIdentifier string `plist:"NSExtensionPointIdentifier"`
}

func xcodeVersion(xcodePath string) string {
	plistPath := filepath.Join(xcodePath, "Contents", "Info.plist")
	data, err := os.ReadFile(plistPath)
	if err != nil {
		return ""
	}
	var info infoPlist
	if _, err := plist.Unmarshal(data, &info); err != nil {
		return ""
	}
	if info.CFBundleShortVersionString != "" {
		return info.CFBundleShortVersionString
	}
	return info.CFBundleVersion
}

func parseXcodeExtensions(pluginsDir, home string) []scanner.Extension {
	var exts []scanner.Extension

	// .xcplugin bundles
	if pluginsDir != "" {
		entries, _ := filepath.Glob(filepath.Join(pluginsDir, "*.xcplugin"))
		for _, p := range entries {
			ext := parseXCPlugin(p)
			exts = append(exts, ext)
		}
	}

	// Source editor extensions from installed apps
	exts = append(exts, findSourceEditorExtensions(home)...)
	return exts
}

func parseXCPlugin(pluginPath string) scanner.Extension {
	stem := filepath.Base(pluginPath)
	stem = strings.TrimSuffix(stem, ".xcplugin")

	ext := scanner.Extension{
		ID:          stem,
		Name:        stem,
		Version:     "unknown",
		InstallPath: pluginPath,
		Enabled:     true,
	}

	plistPath := filepath.Join(pluginPath, "Contents", "Info.plist")
	data, err := os.ReadFile(plistPath)
	if err != nil {
		return ext
	}
	var info infoPlist
	if _, err := plist.Unmarshal(data, &info); err != nil {
		return ext
	}

	if info.CFBundleName != "" {
		ext.Name = info.CFBundleName
	}
	v := info.CFBundleShortVersionString
	if v == "" {
		v = info.CFBundleVersion
	}
	if v != "" {
		ext.Version = v
	}
	if info.CFBundleIdentifier != "" {
		ext.ID = info.CFBundleIdentifier
	}

	if i, err := os.Stat(pluginPath); err == nil {
		t := i.ModTime()
		ext.LastUpdated = &t
	}

	return ext
}

func findSourceEditorExtensions(home string) []scanner.Extension {
	var exts []scanner.Extension

	appDirs := []string{
		"/Applications",
		filepath.Join(home, "Applications"),
	}

	for _, appDir := range appDirs {
		if !PathExists(appDir) {
			continue
		}
		apps, _ := filepath.Glob(filepath.Join(appDir, "*.app"))
		for _, app := range apps {
			pluginsDir := filepath.Join(app, "Contents", "PlugIns")
			appexes, _ := filepath.Glob(filepath.Join(pluginsDir, "*.appex"))
			for _, appex := range appexes {
				plistPath := filepath.Join(appex, "Contents", "Info.plist")
				data, err := os.ReadFile(plistPath)
				if err != nil {
					continue
				}
				var info infoPlist
				if _, err := plist.Unmarshal(data, &info); err != nil {
					continue
				}
				if info.NSExtension == nil ||
					info.NSExtension.NSExtensionPointIdentifier != "com.apple.dt.Xcode.extension.source-editor" {
					continue
				}

				name := info.CFBundleName
				if name == "" {
					name = filepath.Base(appex)
					name = strings.TrimSuffix(name, ".appex")
				}
				version := info.CFBundleShortVersionString
				if version == "" {
					version = "unknown"
				}
				identifier := info.CFBundleIdentifier
				if identifier == "" {
					identifier = name
				}

				exts = append(exts, scanner.Extension{
					ID:          identifier,
					Name:        name + " (Source Editor Extension)",
					Version:     version,
					InstallPath: appex,
					Publisher:   strings.TrimSuffix(filepath.Base(app), ".app"),
					Enabled:     true,
				})
			}
		}
	}

	return exts
}
