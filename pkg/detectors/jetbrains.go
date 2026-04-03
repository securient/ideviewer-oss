package detectors

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/securient/ideviewer-oss/pkg/scanner"
)

type jetbrainsIDEConfig struct {
	ideType        scanner.IDEType
	name           string
	folderPatterns []string
	appNames       map[string][]string
	toolboxID      string
}

var jetbrainsIDEs = []jetbrainsIDEConfig{
	{
		ideType:        scanner.IDETypeJetBrainsIDEA,
		name:           "IntelliJ IDEA",
		folderPatterns: []string{"IntelliJIdea*", "IdeaIC*"},
		appNames: map[string][]string{
			"darwin":  {"IntelliJ IDEA.app", "IntelliJ IDEA CE.app", "IntelliJ IDEA Ultimate.app"},
			"windows": {"idea64.exe", "idea.exe"},
			"linux":   {"idea.sh", "idea"},
		},
		toolboxID: "intellij-idea",
	},
	{
		ideType:        scanner.IDETypeJetBrainsPyCharm,
		name:           "PyCharm",
		folderPatterns: []string{"PyCharm*"},
		appNames: map[string][]string{
			"darwin":  {"PyCharm.app", "PyCharm CE.app", "PyCharm Professional.app"},
			"windows": {"pycharm64.exe", "pycharm.exe"},
			"linux":   {"pycharm.sh", "pycharm"},
		},
		toolboxID: "pycharm",
	},
	{
		ideType:        scanner.IDETypeJetBrainsWebStorm,
		name:           "WebStorm",
		folderPatterns: []string{"WebStorm*"},
		appNames: map[string][]string{
			"darwin":  {"WebStorm.app"},
			"windows": {"webstorm64.exe", "webstorm.exe"},
			"linux":   {"webstorm.sh", "webstorm"},
		},
		toolboxID: "webstorm",
	},
	{
		ideType:        scanner.IDETypeJetBrainsGoLand,
		name:           "GoLand",
		folderPatterns: []string{"GoLand*"},
		appNames: map[string][]string{
			"darwin":  {"GoLand.app"},
			"windows": {"goland64.exe", "goland.exe"},
			"linux":   {"goland.sh", "goland"},
		},
		toolboxID: "goland",
	},
	{
		ideType:        scanner.IDETypeJetBrainsCLion,
		name:           "CLion",
		folderPatterns: []string{"CLion*"},
		appNames: map[string][]string{
			"darwin":  {"CLion.app"},
			"windows": {"clion64.exe", "clion.exe"},
			"linux":   {"clion.sh", "clion"},
		},
		toolboxID: "clion",
	},
	{
		ideType:        scanner.IDETypeJetBrainsRider,
		name:           "Rider",
		folderPatterns: []string{"Rider*"},
		appNames: map[string][]string{
			"darwin":  {"Rider.app"},
			"windows": {"rider64.exe", "rider.exe"},
			"linux":   {"rider.sh", "rider"},
		},
		toolboxID: "rider",
	},
	{
		ideType:        scanner.IDETypeJetBrainsPhpStorm,
		name:           "PhpStorm",
		folderPatterns: []string{"PhpStorm*"},
		appNames: map[string][]string{
			"darwin":  {"PhpStorm.app"},
			"windows": {"phpstorm64.exe", "phpstorm.exe"},
			"linux":   {"phpstorm.sh", "phpstorm"},
		},
		toolboxID: "phpstorm",
	},
	{
		ideType:        scanner.IDETypeJetBrainsRubyMine,
		name:           "RubyMine",
		folderPatterns: []string{"RubyMine*"},
		appNames: map[string][]string{
			"darwin":  {"RubyMine.app"},
			"windows": {"rubymine64.exe", "rubymine.exe"},
			"linux":   {"rubymine.sh", "rubymine"},
		},
		toolboxID: "rubymine",
	},
	{
		ideType:        scanner.IDETypeJetBrainsDataGrip,
		name:           "DataGrip",
		folderPatterns: []string{"DataGrip*"},
		appNames: map[string][]string{
			"darwin":  {"DataGrip.app"},
			"windows": {"datagrip64.exe", "datagrip.exe"},
			"linux":   {"datagrip.sh", "datagrip"},
		},
		toolboxID: "datagrip",
	},
	{
		ideType:        scanner.IDETypeAndroidStudio,
		name:           "Android Studio",
		folderPatterns: []string{"AndroidStudio*", "Google/AndroidStudio*"},
		appNames: map[string][]string{
			"darwin":  {"Android Studio.app"},
			"windows": {"studio64.exe", "studio.exe"},
			"linux":   {"studio.sh", "android-studio"},
		},
		toolboxID: "android-studio",
	},
}

// JetBrainsDetector detects JetBrains IDE installations.
type JetBrainsDetector struct{}

func (d *JetBrainsDetector) Name() string { return "jetbrains" }

func (d *JetBrainsDetector) Detect() ([]scanner.IDE, error) {
	var ides []scanner.IDE
	for _, cfg := range jetbrainsIDEs {
		found := detectJetBrainsIDE(cfg)
		for i := range found {
			found[i].Extensions = parseJetBrainsPlugins(found[i].ExtensionsPath)
		}
		ides = append(ides, found...)
	}
	return ides, nil
}

func configBasePaths() []string {
	home := HomeDir()
	plat := PlatformKey()
	var paths []string
	switch plat {
	case "darwin":
		paths = append(paths,
			filepath.Join(home, "Library", "Application Support", "JetBrains"),
			filepath.Join(home, "Library", "Preferences"),
		)
	case "linux":
		paths = append(paths,
			filepath.Join(home, ".config", "JetBrains"),
			filepath.Join(home, ".local", "share", "JetBrains"),
		)
	case "windows":
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			paths = append(paths, filepath.Join(appdata, "JetBrains"))
		}
	}
	var existing []string
	for _, p := range paths {
		if PathExists(p) {
			existing = append(existing, p)
		}
	}
	return existing
}

func installPaths() []string {
	home := HomeDir()
	plat := PlatformKey()
	var paths []string
	switch plat {
	case "darwin":
		paths = append(paths,
			"/Applications",
			filepath.Join(home, "Applications"),
			filepath.Join(home, "Library", "Application Support", "JetBrains", "Toolbox", "apps"),
		)
	case "linux":
		paths = append(paths,
			"/opt",
			"/usr/share",
			filepath.Join(home, ".local", "share", "JetBrains", "Toolbox", "apps"),
			"/snap",
		)
	case "windows":
		pf := os.Getenv("ProgramFiles")
		if pf == "" {
			pf = `C:\Program Files`
		}
		pf86 := os.Getenv("ProgramFiles(x86)")
		if pf86 == "" {
			pf86 = `C:\Program Files (x86)`
		}
		paths = append(paths,
			filepath.Join(pf, "JetBrains"),
			filepath.Join(pf86, "JetBrains"),
		)
		if localappdata := os.Getenv("LOCALAPPDATA"); localappdata != "" {
			paths = append(paths, filepath.Join(localappdata, "JetBrains", "Toolbox", "apps"))
		}
	}
	var existing []string
	for _, p := range paths {
		if PathExists(p) {
			existing = append(existing, p)
		}
	}
	return existing
}

func detectJetBrainsIDE(cfg jetbrainsIDEConfig) []scanner.IDE {
	plat := PlatformKey()
	var found []scanner.IDE

	// Search installed applications
	for _, ip := range installPaths() {
		for _, appName := range cfg.appNames[plat] {
			if plat == "darwin" {
				appPath := filepath.Join(ip, appName)
				if PathExists(appPath) {
					ide := createJetBrainsIDE(cfg, appPath)
					found = append(found, ide)
				}
			} else {
				// Walk to find executables
				_ = filepath.WalkDir(ip, func(path string, d os.DirEntry, err error) error {
					if err != nil {
						return filepath.SkipDir
					}
					if d.Name() == appName && !d.IsDir() {
						ide := createJetBrainsIDE(cfg, path)
						found = append(found, ide)
					}
					return nil
				})
			}
		}
	}

	// Look for config directories even if app not found
	for _, base := range configBasePaths() {
		for _, pattern := range cfg.folderPatterns {
			matches, _ := filepath.Glob(filepath.Join(base, pattern))
			for _, m := range matches {
				info, err := os.Stat(m)
				if err != nil || !info.IsDir() {
					continue
				}
				// Skip if we already found this config
				alreadyFound := false
				for _, f := range found {
					if f.ConfigPath == m {
						alreadyFound = true
						break
					}
				}
				if alreadyFound {
					continue
				}

				version := extractVersionFromFolder(filepath.Base(m))
				pluginsPath := findPluginsPath(m)
				ide := scanner.IDE{
					IDEType:        cfg.ideType,
					Name:           cfg.name,
					Version:        version,
					ConfigPath:     m,
					ExtensionsPath: pluginsPath,
				}
				found = append(found, ide)
			}
		}
	}

	return found
}

func createJetBrainsIDE(cfg jetbrainsIDEConfig, appPath string) scanner.IDE {
	var version, configPath, extensionsPath string

	// macOS: try to read version from Info.plist (just extract from config folder)
	for _, base := range configBasePaths() {
		for _, pattern := range cfg.folderPatterns {
			matches, _ := filepath.Glob(filepath.Join(base, pattern))
			for _, m := range matches {
				info, err := os.Stat(m)
				if err != nil || !info.IsDir() {
					continue
				}
				configPath = m
				if pp := findPluginsPath(m); pp != "" {
					extensionsPath = pp
				}
				if version == "" {
					version = extractVersionFromFolder(filepath.Base(m))
				}
				break
			}
			if configPath != "" {
				break
			}
		}
		if configPath != "" {
			break
		}
	}

	return scanner.IDE{
		IDEType:        cfg.ideType,
		Name:           cfg.name,
		Version:        version,
		InstallPath:    appPath,
		ConfigPath:     configPath,
		ExtensionsPath: extensionsPath,
	}
}

func findPluginsPath(configDir string) string {
	candidates := []string{
		filepath.Join(configDir, "plugins"),
		configDir + "-plugins",
	}
	for _, c := range candidates {
		if PathExists(c) {
			return c
		}
	}
	return ""
}

var versionRe = regexp.MustCompile(`(\d+\.\d+(?:\.\d+)?)`)

func extractVersionFromFolder(name string) string {
	m := versionRe.FindString(name)
	return m
}

// XML structures for plugin.xml parsing.
type pluginXML struct {
	XMLName     xml.Name        `xml:"idea-plugin"`
	ID          string          `xml:"id"`
	Name        string          `xml:"name"`
	Version     string          `xml:"version"`
	Vendor      pluginVendor    `xml:"vendor"`
	Description string          `xml:"description"`
	Depends     []string        `xml:"depends"`
	Extensions  []pluginExtElem `xml:"extensions"`
}

type pluginVendor struct {
	URL  string `xml:"url,attr"`
	Text string `xml:",chardata"`
}

type pluginExtElem struct {
	Children []xmlChild `xml:",any"`
}

type xmlChild struct {
	XMLName xml.Name
}

func parseJetBrainsPlugins(pluginsDir string) []scanner.Extension {
	if pluginsDir == "" {
		return nil
	}
	entries, err := os.ReadDir(pluginsDir)
	if err != nil {
		return nil
	}
	var exts []scanner.Extension
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		ext := parseJetBrainsPlugin(filepath.Join(pluginsDir, entry.Name()))
		exts = append(exts, ext)
	}
	return exts
}

func parseJetBrainsPlugin(dir string) scanner.Extension {
	// Try known plugin.xml locations
	candidates := []string{
		filepath.Join(dir, "META-INF", "plugin.xml"),
		filepath.Join(dir, "lib", "plugin.xml"),
	}
	for _, c := range candidates {
		if data, err := os.ReadFile(c); err == nil {
			if ext, ok := parsePluginXML(data, dir, c); ok {
				return ext
			}
		}
	}
	// Fallback: basic extension from folder name
	return scanner.Extension{
		ID:          filepath.Base(dir),
		Name:        filepath.Base(dir),
		Version:     "unknown",
		InstallPath: dir,
		Enabled:     true,
	}
}

func parsePluginXML(data []byte, dir, xmlPath string) (scanner.Extension, bool) {
	var p pluginXML
	if err := xml.Unmarshal(data, &p); err != nil {
		return scanner.Extension{}, false
	}

	id := p.ID
	if id == "" {
		id = filepath.Base(dir)
	}
	name := p.Name
	if name == "" {
		name = filepath.Base(dir)
	}
	version := p.Version
	if version == "" {
		version = "unknown"
	}

	publisher := strings.TrimSpace(p.Vendor.Text)
	homepage := strings.TrimSpace(p.Vendor.URL)

	desc := p.Description
	if len(desc) > 200 {
		desc = desc[:200]
	}

	// Permissions from extension points
	perms := extractJetBrainsPermissions(data, p)

	var lastUpdated *time.Time
	if info, err := os.Stat(xmlPath); err == nil {
		t := info.ModTime()
		lastUpdated = &t
	}

	return scanner.Extension{
		ID:           id,
		Name:         name,
		Version:      version,
		Publisher:    publisher,
		Homepage:     homepage,
		Description:  desc,
		InstallPath:  dir,
		Permissions:  perms,
		Dependencies: p.Depends,
		Enabled:      true,
		LastUpdated:  lastUpdated,
	}, true
}

func extractJetBrainsPermissions(raw []byte, p pluginXML) []scanner.Permission {
	var perms []scanner.Permission
	seen := make(map[string]bool)

	for _, ext := range p.Extensions {
		for _, child := range ext.Children {
			tag := strings.ToLower(child.XMLName.Local)
			if strings.Contains(tag, "action") && !seen["actions"] {
				seen["actions"] = true
				perms = append(perms, scanner.Permission{Name: "actions", Description: "Registers IDE actions", IsDangerous: false})
			}
			if strings.Contains(tag, "toolwindow") && !seen["toolWindow"] {
				seen["toolWindow"] = true
				perms = append(perms, scanner.Permission{Name: "toolWindow", Description: "Creates tool windows", IsDangerous: false})
			}
			if (strings.Contains(tag, "projectservice") || strings.Contains(tag, "applicationservice")) && !seen["services"] {
				seen["services"] = true
				perms = append(perms, scanner.Permission{Name: "services", Description: "Registers application/project services", IsDangerous: false})
			}
		}
	}

	// Check for dangerous patterns in the raw XML
	lower := strings.ToLower(string(raw))
	if (strings.Contains(lower, "exec") || strings.Contains(lower, "process")) && !seen["processExecution"] {
		seen["processExecution"] = true
		perms = append(perms, scanner.Permission{Name: "processExecution", Description: "May execute external processes", IsDangerous: true})
	}

	return perms
}
