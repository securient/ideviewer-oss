package detectors

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/securient/ideviewer-oss/pkg/scanner"
)

// SublimeTextDetector detects Sublime Text installations.
type SublimeTextDetector struct{}

func (d *SublimeTextDetector) Name() string { return "sublime" }

func (d *SublimeTextDetector) Detect() ([]scanner.IDE, error) {
	installPath := findSublime()
	packagesPath := sublimePackagesPath()

	if installPath == "" && packagesPath == "" {
		return nil, nil
	}

	var version string
	if installPath != "" {
		version = GetVersion(installPath, "--version")
	}

	configPath := sublimeConfigPath()

	ide := scanner.IDE{
		IDEType:        scanner.IDETypeSublimeText,
		Name:           "Sublime Text",
		Version:        version,
		InstallPath:    installPath,
		ConfigPath:     configPath,
		ExtensionsPath: packagesPath,
		IsRunning:      IsProcessRunning("sublime_text", "subl", "Sublime Text"),
	}

	ide.Extensions = parseSublimeExtensions(packagesPath)
	return []scanner.IDE{ide}, nil
}

func findSublime() string {
	plat := PlatformKey()
	var paths []string
	switch plat {
	case "darwin":
		paths = []string{
			"/Applications/Sublime Text.app/Contents/SharedSupport/bin/subl",
			"/Applications/Sublime Text 4.app/Contents/SharedSupport/bin/subl",
			"/usr/local/bin/subl",
		}
	case "linux":
		paths = []string{
			"/usr/bin/subl",
			"/usr/bin/sublime_text",
			"/opt/sublime_text/sublime_text",
			"/snap/bin/subl",
		}
	case "windows":
		paths = []string{
			`%ProgramFiles%\Sublime Text\subl.exe`,
			`%ProgramFiles%\Sublime Text 4\subl.exe`,
			`%ProgramFiles(x86)%\Sublime Text\subl.exe`,
		}
	}
	return FindExecutable("subl", paths...)
}

func sublimePackagesPath() string {
	home := HomeDir()
	plat := PlatformKey()
	var p string
	switch plat {
	case "darwin":
		p = filepath.Join(home, "Library", "Application Support", "Sublime Text", "Packages")
	case "linux":
		p = filepath.Join(home, ".config", "sublime-text", "Packages")
	case "windows":
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			p = filepath.Join(appdata, "Sublime Text", "Packages")
		}
	}
	if p != "" && PathExists(p) {
		return p
	}
	return ""
}

func sublimeConfigPath() string {
	home := HomeDir()
	plat := PlatformKey()
	var p string
	switch plat {
	case "darwin":
		p = filepath.Join(home, "Library", "Application Support", "Sublime Text")
	case "linux":
		p = filepath.Join(home, ".config", "sublime-text")
	case "windows":
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			p = filepath.Join(appdata, "Sublime Text")
		}
	}
	if p != "" && PathExists(p) {
		return p
	}
	return ""
}

func parseSublimeExtensions(packagesDir string) []scanner.Extension {
	if packagesDir == "" {
		return nil
	}
	var exts []scanner.Extension

	// User-installed packages (directories)
	entries, err := os.ReadDir(packagesDir)
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			name := entry.Name()
			if name == "User" || name[0] == '.' {
				continue
			}
			ext := parseSublimePackageDir(filepath.Join(packagesDir, name))
			exts = append(exts, ext)
		}
	}

	// Installed Packages (*.sublime-package ZIP files)
	installedDir := filepath.Join(filepath.Dir(packagesDir), "Installed Packages")
	zipEntries, err := os.ReadDir(installedDir)
	if err == nil {
		for _, entry := range zipEntries {
			if entry.IsDir() {
				continue
			}
			if filepath.Ext(entry.Name()) != ".sublime-package" {
				continue
			}
			stem := entry.Name()[:len(entry.Name())-len(".sublime-package")]
			ext := parseSublimePackageZip(filepath.Join(installedDir, entry.Name()), stem)
			exts = append(exts, ext)
		}
	}

	return exts
}

func parseSublimePackageDir(dir string) scanner.Extension {
	folderName := filepath.Base(dir)
	name := folderName
	version := "unknown"
	var description, homepage string

	// Try package.json
	pkgPath := filepath.Join(dir, "package.json")
	if data, err := os.ReadFile(pkgPath); err == nil {
		var pkg struct {
			Name        string `json:"name"`
			Version     string `json:"version"`
			Description string `json:"description"`
			Homepage    string `json:"homepage"`
		}
		if json.Unmarshal(data, &pkg) == nil {
			if pkg.Name != "" {
				name = pkg.Name
			}
			if pkg.Version != "" {
				version = pkg.Version
			}
			description = pkg.Description
			homepage = pkg.Homepage
		}
	}

	var lastUpdated *time.Time
	if info, err := os.Stat(dir); err == nil {
		t := info.ModTime()
		lastUpdated = &t
	}

	perms := sublimePermissions(dir)

	return scanner.Extension{
		ID:          folderName,
		Name:        name,
		Version:     version,
		Description: description,
		Homepage:    homepage,
		InstallPath: dir,
		Permissions: perms,
		Enabled:     true,
		LastUpdated: lastUpdated,
	}
}

func sublimePermissions(dir string) []scanner.Permission {
	var perms []scanner.Permission

	keymaps, _ := filepath.Glob(filepath.Join(dir, "*.sublime-keymap"))
	if len(keymaps) > 0 {
		perms = append(perms, scanner.Permission{
			Name:        "keybindings",
			Description: fmt.Sprintf("Registers %d keymap files", len(keymaps)),
			IsDangerous: false,
		})
	}

	commands, _ := filepath.Glob(filepath.Join(dir, "*.sublime-commands"))
	if len(commands) > 0 {
		perms = append(perms, scanner.Permission{
			Name:        "commands",
			Description: fmt.Sprintf("Registers %d command files", len(commands)),
			IsDangerous: false,
		})
	}

	builds, _ := filepath.Glob(filepath.Join(dir, "*.sublime-build"))
	if len(builds) > 0 {
		perms = append(perms, scanner.Permission{
			Name:        "buildSystems",
			Description: fmt.Sprintf("Registers %d build systems (may execute commands)", len(builds)),
			IsDangerous: true,
		})
	}

	return perms
}

func parseSublimePackageZip(zipPath, stem string) scanner.Extension {
	ext := scanner.Extension{
		ID:          stem,
		Name:        stem,
		Version:     "unknown",
		InstallPath: zipPath,
		Enabled:     true,
	}

	// Try to read package.json from the zip
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return ext
	}
	defer r.Close()

	for _, f := range r.File {
		if f.Name == "package.json" {
			rc, err := f.Open()
			if err != nil {
				break
			}
			var pkg struct {
				Name        string `json:"name"`
				Version     string `json:"version"`
				Description string `json:"description"`
			}
			if json.NewDecoder(rc).Decode(&pkg) == nil {
				if pkg.Name != "" {
					ext.Name = pkg.Name
				}
				if pkg.Version != "" {
					ext.Version = pkg.Version
				}
				ext.Description = pkg.Description
			}
			rc.Close()
			break
		}
	}

	return ext
}
