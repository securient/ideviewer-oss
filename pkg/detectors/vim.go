package detectors

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/securient/ideviewer-oss/pkg/scanner"
)

// VimDetector detects Vim and Neovim installations.
type VimDetector struct{}

func (d *VimDetector) Name() string { return "vim" }

func (d *VimDetector) Detect() ([]scanner.IDE, error) {
	var ides []scanner.IDE

	if ide, ok := detectVim(); ok {
		ide.Extensions = parseVimPlugins(ide)
		ides = append(ides, ide)
	}
	if ide, ok := detectNeovim(); ok {
		ide.Extensions = parseNeovimPlugins(ide)
		ides = append(ides, ide)
	}

	return ides, nil
}

func detectVim() (scanner.IDE, bool) {
	vimPath := FindExecutable("vim")
	if vimPath == "" {
		return scanner.IDE{}, false
	}
	home := HomeDir()
	version := GetVersion(vimPath)

	var configPath, extensionsPath string
	vimrc := filepath.Join(home, ".vimrc")
	if PathExists(vimrc) {
		configPath = vimrc
	}
	vimDir := filepath.Join(home, ".vim")
	if PathExists(vimDir) {
		extensionsPath = vimDir
	}

	return scanner.IDE{
		IDEType:        scanner.IDETypeVim,
		Name:           "Vim",
		Version:        version,
		InstallPath:    vimPath,
		ConfigPath:     configPath,
		ExtensionsPath: extensionsPath,
		IsRunning:      IsProcessRunning("vim", "gvim"),
	}, true
}

func detectNeovim() (scanner.IDE, bool) {
	nvimPath := FindExecutable("nvim")
	if nvimPath == "" {
		return scanner.IDE{}, false
	}
	home := HomeDir()
	plat := PlatformKey()
	version := GetVersion(nvimPath)

	var configBase, dataBase string
	if plat == "windows" {
		localAppData := os.Getenv("LOCALAPPDATA")
		configBase = filepath.Join(localAppData, "nvim")
		dataBase = configBase
	} else {
		configBase = filepath.Join(home, ".config", "nvim")
		dataBase = filepath.Join(home, ".local", "share", "nvim")
	}

	var configPath, extensionsPath string
	if PathExists(configBase) {
		configPath = configBase
	}

	// Check common plugin locations
	pluginPaths := []string{
		filepath.Join(dataBase, "site", "pack"),
		filepath.Join(dataBase, "plugged"),
		filepath.Join(dataBase, "lazy"),
		filepath.Join(configBase, "pack"),
	}
	for _, pp := range pluginPaths {
		if PathExists(pp) {
			extensionsPath = pp
			break
		}
	}

	return scanner.IDE{
		IDEType:        scanner.IDETypeNeovim,
		Name:           "Neovim",
		Version:        version,
		InstallPath:    nvimPath,
		ConfigPath:     configPath,
		ExtensionsPath: extensionsPath,
		IsRunning:      IsProcessRunning("nvim", "neovim"),
	}, true
}

func parseVimPlugins(ide scanner.IDE) []scanner.Extension {
	home := HomeDir()
	vimDir := filepath.Join(home, ".vim")
	var exts []scanner.Extension

	// bundle directory (Vundle, Pathogen)
	bundleDir := filepath.Join(vimDir, "bundle")
	exts = append(exts, parsePluginDir(bundleDir)...)

	// pack directory (native package manager)
	packDir := filepath.Join(vimDir, "pack")
	exts = append(exts, parsePackPlugins(packDir)...)

	// plugged directory (vim-plug)
	pluggedDir := filepath.Join(vimDir, "plugged")
	exts = append(exts, parsePluginDir(pluggedDir)...)

	return exts
}

func parseNeovimPlugins(ide scanner.IDE) []scanner.Extension {
	if ide.ExtensionsPath == "" {
		return nil
	}
	extPath := ide.ExtensionsPath
	base := filepath.Base(extPath)

	switch {
	case base == "pack":
		return parsePackPlugins(extPath)
	case base == "plugged":
		return parsePluginDir(extPath)
	case base == "lazy":
		return parseLazyPlugins(extPath)
	default:
		return parsePluginDir(extPath)
	}
}

func parsePackPlugins(packDir string) []scanner.Extension {
	if !PathExists(packDir) {
		return nil
	}
	var exts []scanner.Extension
	namespaces, _ := os.ReadDir(packDir)
	for _, ns := range namespaces {
		if !ns.IsDir() {
			continue
		}
		for _, loadType := range []string{"start", "opt"} {
			loadDir := filepath.Join(packDir, ns.Name(), loadType)
			entries, err := os.ReadDir(loadDir)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if !entry.IsDir() || entry.Name()[0] == '.' {
					continue
				}
				ext := parseVimPlugin(filepath.Join(loadDir, entry.Name()))
				ext.Enabled = (loadType == "start")
				exts = append(exts, ext)
			}
		}
	}
	return exts
}

func parseLazyPlugins(lazyDir string) []scanner.Extension {
	return parsePluginDir(lazyDir)
}

func parsePluginDir(dir string) []scanner.Extension {
	if !PathExists(dir) {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var exts []scanner.Extension
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name()[0] == '.' {
			continue
		}
		ext := parseVimPlugin(filepath.Join(dir, entry.Name()))
		exts = append(exts, ext)
	}
	return exts
}

var gitURLRe = regexp.MustCompile(`url\s*=\s*(.+)`)
var githubOwnerRe = regexp.MustCompile(`github\.com[:/]([^/]+)`)

func parseVimPlugin(dir string) scanner.Extension {
	name := filepath.Base(dir)

	// Try to get description from README
	var description string
	for _, rn := range []string{"README.md", "README", "README.txt", "readme.md"} {
		readmePath := filepath.Join(dir, rn)
		data, err := os.ReadFile(readmePath)
		if err != nil {
			continue
		}
		content := string(data)
		if len(content) > 500 {
			content = content[:500]
		}
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "=") {
				if len(line) > 200 {
					line = line[:200]
				}
				description = line
				break
			}
		}
		break
	}

	// Git info
	var maintainer, repository string
	gitConfig := filepath.Join(dir, ".git", "config")
	if data, err := os.ReadFile(gitConfig); err == nil {
		if m := gitURLRe.FindSubmatch(data); len(m) > 1 {
			repository = strings.TrimSpace(string(m[1]))
			if gm := githubOwnerRe.FindStringSubmatch(repository); len(gm) > 1 {
				maintainer = gm[1]
			}
		}
	}

	// Permissions
	var perms []scanner.Permission
	if PathExists(filepath.Join(dir, "autoload")) {
		perms = append(perms, scanner.Permission{Name: "autoload", Description: "Has autoload functions", IsDangerous: false})
	}
	if PathExists(filepath.Join(dir, "plugin")) {
		perms = append(perms, scanner.Permission{Name: "plugin", Description: "Runs on startup", IsDangerous: false})
	}
	if PathExists(filepath.Join(dir, "ftplugin")) {
		perms = append(perms, scanner.Permission{Name: "ftplugin", Description: "Filetype-specific plugin", IsDangerous: false})
	}

	// Check for dangerous patterns in lua/vim files
	if hasDangerousPatterns(dir) {
		perms = append(perms, scanner.Permission{Name: "shellExecution", Description: "May execute shell commands", IsDangerous: true})
	}

	var lastUpdated *time.Time
	if info, err := os.Stat(dir); err == nil {
		t := info.ModTime()
		lastUpdated = &t
	}

	return scanner.Extension{
		ID:          name,
		Name:        name,
		Version:     "unknown",
		Maintainer:  maintainer,
		Description: description,
		Repository:  repository,
		InstallPath: dir,
		Permissions: perms,
		Enabled:     true,
		LastUpdated: lastUpdated,
	}
}

func hasDangerousPatterns(dir string) bool {
	dangerous := false
	walkFn := func(path string, d os.DirEntry, err error) error {
		if err != nil || dangerous {
			return filepath.SkipDir
		}
		if d.IsDir() {
			// Skip .git and other hidden dirs within plugin
			if d.Name()[0] == '.' && path != dir {
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".lua" && ext != ".vim" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		content := string(data)
		if len(content) > 2000 {
			content = content[:2000]
		}
		if strings.Contains(content, "system(") ||
			strings.Contains(content, "os.execute") ||
			strings.Contains(content, "jobstart") {
			dangerous = true
			return filepath.SkipAll
		}
		return nil
	}
	_ = filepath.WalkDir(dir, walkFn)
	return dangerous
}
