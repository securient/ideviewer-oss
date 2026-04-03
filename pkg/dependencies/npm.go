package dependencies

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// npmLifecycleHooks are npm lifecycle hooks that are security-relevant.
var npmLifecycleHooks = []string{
	"preinstall", "install", "postinstall",
	"preuninstall", "uninstall", "postuninstall",
	"prepare", "prepublish", "prepublishOnly",
}

// scanNPMGlobal scans globally installed npm packages.
func scanNPMGlobal(packages *[]Package, seen map[string]bool, errors *[]string, addManager func(string)) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "npm", "list", "-g", "--json", "--depth=0")
	out, err := cmd.Output()
	// npm may return non-zero but still have valid output.
	if out == nil && err != nil {
		return
	}

	var data struct {
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if json.Unmarshal(out, &data) != nil {
		return
	}
	if len(data.Dependencies) == 0 {
		return
	}

	addManager("npm")

	// Get global node_modules path for lifecycle hook detection.
	globalNM := npmGlobalRoot()

	for name, info := range data.Dependencies {
		version := info.Version
		if version == "" {
			version = "unknown"
		}
		key := fmt.Sprintf("npm:%s:%s:global", name, version)
		if seen[key] {
			continue
		}
		seen[key] = true
		hooks := checkNPMLifecycleHooks(name, globalNM)
		*packages = append(*packages, Package{
			Name:           name,
			Version:        version,
			PackageManager: "npm",
			InstallType:    "global",
			LifecycleHooks: hooks,
		})
	}
}

// npmGlobalRoot returns the global node_modules path.
func npmGlobalRoot() string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "npm", "root", "-g")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// checkNPMLifecycleHooks checks if an npm package has lifecycle hooks.
func checkNPMLifecycleHooks(packageName, nodeModulesPath string) map[string]string {
	if nodeModulesPath == "" {
		return nil
	}

	pkgJSONPath := filepath.Join(nodeModulesPath, packageName, "package.json")

	// Handle scoped packages like @scope/name.
	if _, err := os.Stat(pkgJSONPath); err != nil && strings.Contains(packageName, "/") {
		parts := strings.SplitN(packageName, "/", 2)
		pkgJSONPath = filepath.Join(nodeModulesPath, parts[0], parts[1], "package.json")
	}

	data, err := os.ReadFile(pkgJSONPath)
	if err != nil {
		return nil
	}

	var pkgJSON struct {
		Scripts map[string]string `json:"scripts"`
	}
	if json.Unmarshal(data, &pkgJSON) != nil {
		return nil
	}

	hooks := make(map[string]string)
	for _, hookName := range npmLifecycleHooks {
		if cmd, ok := pkgJSON.Scripts[hookName]; ok {
			hooks[hookName] = cmd
		}
	}
	if len(hooks) == 0 {
		return nil
	}
	return hooks
}

// parsePackageJSON parses an npm package.json file.
func parsePackageJSON(filePath string, packages *[]Package, scannedProjects *[]string,
	seen map[string]bool, addManager func(string)) {

	data, err := os.ReadFile(filePath)
	if err != nil {
		return
	}

	dir := filepath.Dir(filePath)
	*scannedProjects = append(*scannedProjects, dir)
	addManager("npm")

	var pkgJSON struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if json.Unmarshal(data, &pkgJSON) != nil {
		return
	}

	nodeModules := filepath.Join(dir, "node_modules")
	nmExists := false
	if info, err := os.Stat(nodeModules); err == nil && info.IsDir() {
		nmExists = true
	}

	for _, deps := range []map[string]string{pkgJSON.Dependencies, pkgJSON.DevDependencies} {
		for name, version := range deps {
			key := fmt.Sprintf("npm:%s:%s:%s", name, version, dir)
			if seen[key] {
				continue
			}
			seen[key] = true
			var hooks map[string]string
			if nmExists {
				hooks = checkNPMLifecycleHooks(name, nodeModules)
			}
			*packages = append(*packages, Package{
				Name:           name,
				Version:        version,
				PackageManager: "npm",
				InstallType:    "project",
				ProjectPath:    dir,
				LifecycleHooks: hooks,
			})
		}
	}
}
