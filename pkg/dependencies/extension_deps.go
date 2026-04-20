package dependencies

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// extensionDir defines an IDE's extension directory with its platform paths.
type extensionDir struct {
	ideName string
	paths   map[string][]string
}

// Known VS Code-family extension directories (duplicated from detectors to avoid import cycle).
var vscodeExtDirs = []extensionDir{
	{
		ideName: "VS Code",
		paths: map[string][]string{
			"darwin":  {"~/.vscode/extensions"},
			"linux":   {"~/.vscode/extensions"},
			"windows": {`%USERPROFILE%\.vscode\extensions`},
		},
	},
	{
		ideName: "Cursor",
		paths: map[string][]string{
			"darwin":  {"~/.cursor/extensions"},
			"linux":   {"~/.cursor/extensions"},
			"windows": {`%USERPROFILE%\.cursor\extensions`},
		},
	},
	{
		ideName: "VSCodium",
		paths: map[string][]string{
			"darwin":  {"~/.vscode-oss/extensions"},
			"linux":   {"~/.vscode-oss/extensions"},
			"windows": {`%USERPROFILE%\.vscode-oss\extensions`},
		},
	},
	{
		ideName: "Kiro",
		paths: map[string][]string{
			"darwin":  {"~/.kiro/extensions"},
			"linux":   {"~/.kiro/extensions"},
			"windows": {`%USERPROFILE%\.kiro\extensions`},
		},
	},
}

// expandPath expands ~ and environment variables.
// Handles both Unix ($VAR) and Windows (%VAR%) syntax.
func expandPath(p string) string {
	if strings.HasPrefix(p, "~/") || p == "~" {
		home, err := os.UserHomeDir()
		if err == nil {
			p = filepath.Join(home, p[1:])
		}
	}
	// Expand Windows %VAR% syntax
	if runtime.GOOS == "windows" && strings.Contains(p, "%") {
		for {
			start := strings.Index(p, "%")
			if start == -1 {
				break
			}
			end := strings.Index(p[start+1:], "%")
			if end == -1 {
				break
			}
			end += start + 1
			varName := p[start+1 : end]
			varValue := os.Getenv(varName)
			if varValue != "" {
				p = p[:start] + varValue + p[end+1:]
			} else {
				break
			}
		}
	}
	return os.ExpandEnv(p)
}

// scanExtensionDependencies discovers packages bundled inside IDE extensions.
func scanExtensionDependencies(packages *[]Package, seen map[string]bool, errors *[]string, addManager func(string)) {
	plat := runtime.GOOS

	// Scan VS Code / Cursor / VSCodium / Kiro extension node_modules
	for _, ed := range vscodeExtDirs {
		for _, p := range ed.paths[plat] {
			dir := expandPath(p)
			if info, err := os.Stat(dir); err != nil || !info.IsDir() {
				continue
			}
			scanVSCodeExtensionDeps(dir, ed.ideName, packages, seen, errors, addManager)
		}
	}

	// Scan JetBrains plugin directories
	scanJetBrainsExtensionDeps(packages, seen, errors, addManager)
}

// scanVSCodeExtensionDeps walks each extension's node_modules and extracts package info.
func scanVSCodeExtensionDeps(extensionsDir, ideName string, packages *[]Package,
	seen map[string]bool, errors *[]string, addManager func(string)) {

	entries, err := os.ReadDir(extensionsDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		extDir := filepath.Join(extensionsDir, entry.Name())

		// Get extension ID from package.json
		extID := getVSCodeExtensionID(extDir)
		if extID == "" {
			extID = entry.Name()
		}

		// Scan node_modules if present (some extensions ship unbundled deps)
		nodeModules := filepath.Join(extDir, "node_modules")
		if info, err := os.Stat(nodeModules); err == nil && info.IsDir() {
			scanNodeModulesForExtension(nodeModules, extID, packages, seen, errors, addManager)
		}

		// Also extract declared dependencies from the extension's package.json
		// (many extensions webpack their deps so node_modules doesn't exist,
		// but the dependency declarations are still in package.json)
		scanExtensionPackageJSON(extDir, extID, packages, seen, addManager)
	}
}

// scanExtensionPackageJSON extracts declared dependencies from an extension's package.json.
// This captures deps even when they're webpacked and node_modules doesn't exist.
func scanExtensionPackageJSON(extDir, extID string, packages *[]Package,
	seen map[string]bool, addManager func(string)) {

	data, err := os.ReadFile(filepath.Join(extDir, "package.json"))
	if err != nil {
		return
	}

	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if json.Unmarshal(data, &pkg) != nil {
		return
	}

	if len(pkg.Dependencies) == 0 {
		return
	}

	addManager("npm")

	// Only report production dependencies (devDependencies are build-time only)
	for name, version := range pkg.Dependencies {
		// Clean version string (remove ^, ~, >= etc.)
		version = strings.TrimLeft(version, "^~>=<")

		key := fmt.Sprintf("npm:%s:%s:extpkg:%s", name, version, extID)
		if seen[key] {
			continue
		}
		// Also skip if we already found this exact package in node_modules
		nmKey := fmt.Sprintf("npm:%s:%s:ext:%s", name, version, extID)
		if seen[nmKey] {
			continue
		}
		seen[key] = true

		*packages = append(*packages, Package{
			Name:            name,
			Version:         version,
			PackageManager:  "npm",
			InstallType:     "project",
			ProjectPath:     extDir,
			SourceType:      "extension",
			SourceExtension: extID,
		})
	}
}

// getVSCodeExtensionID reads the extension's package.json to get publisher.name.
func getVSCodeExtensionID(extDir string) string {
	data, err := os.ReadFile(filepath.Join(extDir, "package.json"))
	if err != nil {
		return ""
	}
	var pkg struct {
		Name      string `json:"name"`
		Publisher string `json:"publisher"`
	}
	if json.Unmarshal(data, &pkg) != nil || pkg.Name == "" {
		return ""
	}
	if pkg.Publisher != "" {
		return pkg.Publisher + "." + pkg.Name
	}
	return pkg.Name
}

// scanNodeModulesForExtension walks a node_modules directory and adds packages.
func scanNodeModulesForExtension(nodeModules, extID string, packages *[]Package,
	seen map[string]bool, errors *[]string, addManager func(string)) {

	entries, err := os.ReadDir(nodeModules)
	if err != nil {
		return
	}

	addManager("npm")

	for _, entry := range entries {
		name := entry.Name()

		// Skip hidden dirs and non-packages
		if strings.HasPrefix(name, ".") {
			continue
		}

		// Handle scoped packages (@scope/name)
		if strings.HasPrefix(name, "@") && entry.IsDir() {
			scopeDir := filepath.Join(nodeModules, name)
			scopeEntries, err := os.ReadDir(scopeDir)
			if err != nil {
				continue
			}
			for _, se := range scopeEntries {
				if se.IsDir() {
					scopedName := name + "/" + se.Name()
					addExtensionPackage(filepath.Join(scopeDir, se.Name()), scopedName, extID, packages, seen)
				}
			}
			continue
		}

		if !entry.IsDir() {
			continue
		}

		addExtensionPackage(filepath.Join(nodeModules, name), name, extID, packages, seen)
	}
}

// addExtensionPackage reads a package.json from a node_modules subdirectory and adds it.
func addExtensionPackage(pkgDir, name, extID string, packages *[]Package, seen map[string]bool) {
	pkgJSONPath := filepath.Join(pkgDir, "package.json")
	data, err := os.ReadFile(pkgJSONPath)
	if err != nil {
		return
	}

	var pkg struct {
		Name    string            `json:"name"`
		Version string            `json:"version"`
		Scripts map[string]string `json:"scripts"`
	}
	if json.Unmarshal(data, &pkg) != nil {
		return
	}

	pkgName := pkg.Name
	if pkgName == "" {
		pkgName = name
	}
	version := pkg.Version
	if version == "" {
		version = "unknown"
	}

	key := fmt.Sprintf("npm:%s:%s:ext:%s", pkgName, version, extID)
	if seen[key] {
		return
	}
	seen[key] = true

	// Check lifecycle hooks
	var hooks map[string]string
	if pkg.Scripts != nil {
		hooks = make(map[string]string)
		for _, hookName := range npmLifecycleHooks {
			if cmd, ok := pkg.Scripts[hookName]; ok {
				hooks[hookName] = cmd
			}
		}
		if len(hooks) == 0 {
			hooks = nil
		}
	}

	*packages = append(*packages, Package{
		Name:            pkgName,
		Version:         version,
		PackageManager:  "npm",
		InstallType:     "project",
		ProjectPath:     filepath.Dir(filepath.Dir(pkgJSONPath)), // extension dir
		LifecycleHooks:  hooks,
		SourceType:      "extension",
		SourceExtension: extID,
	})
}

// scanJetBrainsExtensionDeps scans JetBrains plugin directories for JAR dependencies.
func scanJetBrainsExtensionDeps(packages *[]Package, seen map[string]bool, errors *[]string, addManager func(string)) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}

	// JetBrains config directories by platform
	var configBases []string
	switch runtime.GOOS {
	case "darwin":
		configBases = []string{
			filepath.Join(home, "Library", "Application Support", "JetBrains"),
		}
	case "linux":
		configBases = []string{
			filepath.Join(home, ".config", "JetBrains"),
			filepath.Join(home, ".local", "share", "JetBrains"),
		}
	case "windows":
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			configBases = []string{filepath.Join(appdata, "JetBrains")}
		}
	}

	for _, base := range configBases {
		if info, err := os.Stat(base); err != nil || !info.IsDir() {
			continue
		}
		// Walk IDE version dirs (e.g., IntelliJIdea2024.1, PyCharm2024.1)
		ideVersionDirs, _ := os.ReadDir(base)
		for _, ideDir := range ideVersionDirs {
			if !ideDir.IsDir() {
				continue
			}
			pluginsDir := filepath.Join(base, ideDir.Name(), "plugins")
			if info, err := os.Stat(pluginsDir); err != nil || !info.IsDir() {
				continue
			}
			scanJetBrainsPluginJARs(pluginsDir, packages, seen, errors, addManager)
		}
	}
}

// scanJetBrainsPluginJARs scans JetBrains plugin directories for JAR files and extracts
// Maven dependency info from pom.properties inside JARs.
func scanJetBrainsPluginJARs(pluginsDir string, packages *[]Package,
	seen map[string]bool, errors *[]string, addManager func(string)) {

	entries, err := os.ReadDir(pluginsDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pluginName := entry.Name()
		libDir := filepath.Join(pluginsDir, pluginName, "lib")
		if info, err := os.Stat(libDir); err != nil || !info.IsDir() {
			continue
		}

		// Scan all JAR files in the plugin's lib directory
		jarFiles, _ := os.ReadDir(libDir)
		for _, jf := range jarFiles {
			if jf.IsDir() || !strings.HasSuffix(strings.ToLower(jf.Name()), ".jar") {
				continue
			}
			jarPath := filepath.Join(libDir, jf.Name())
			extractJARDependencies(jarPath, pluginName, packages, seen, addManager)
		}
	}
}

// extractJARDependencies reads a JAR (ZIP) file and looks for Maven pom.properties
// files to extract dependency coordinates.
func extractJARDependencies(jarPath, pluginName string, packages *[]Package,
	seen map[string]bool, addManager func(string)) {

	r, err := zip.OpenReader(jarPath)
	if err != nil {
		return
	}
	defer r.Close()

	for _, f := range r.File {
		// Look for META-INF/maven/<groupId>/<artifactId>/pom.properties
		if !strings.Contains(f.Name, "META-INF/maven/") || !strings.HasSuffix(f.Name, "pom.properties") {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}
		buf := make([]byte, 4096)
		n, _ := rc.Read(buf)
		rc.Close()

		props := string(buf[:n])
		groupID := extractProperty(props, "groupId")
		artifactID := extractProperty(props, "artifactId")
		version := extractProperty(props, "version")

		if artifactID == "" {
			continue
		}

		name := artifactID
		if groupID != "" {
			name = groupID + ":" + artifactID
		}
		if version == "" {
			version = "unknown"
		}

		key := fmt.Sprintf("maven:%s:%s:ext:%s", name, version, pluginName)
		if seen[key] {
			continue
		}
		seen[key] = true
		addManager("maven")

		*packages = append(*packages, Package{
			Name:            name,
			Version:         version,
			PackageManager:  "maven",
			InstallType:     "project",
			ProjectPath:     jarPath,
			SourceType:      "extension",
			SourceExtension: pluginName,
		})
	}
}

// extractProperty extracts a Java properties value by key.
func extractProperty(props, key string) string {
	for _, line := range strings.Split(props, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, key+"=") {
			return strings.TrimPrefix(line, key+"=")
		}
	}
	return ""
}
