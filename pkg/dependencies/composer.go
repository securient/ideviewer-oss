package dependencies

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type composerPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// addComposerPackage records one Composer package, deduplicating on the key
// the caller supplies. Shared by the lockfile, manifest and global scanners so
// the three cannot drift apart in how they populate a Package.
func addComposerPackage(name, version, key, projectPath, installType string,
	packages *[]Package, seen map[string]bool) {

	if name == "" {
		name = "unknown"
	}
	if version == "" {
		version = "unknown"
	}
	if seen[key] {
		return
	}
	seen[key] = true
	*packages = append(*packages, Package{
		Name:           name,
		Version:        version,
		PackageManager: "composer",
		InstallType:    installType,
		ProjectPath:    projectPath,
	})
}

// parseComposerLock parses a PHP composer.lock file.
//
// Both "packages" and "packages-dev" are read: a dev-only dependency still
// executes on the workstation, which is the threat this scanner exists to see.
func parseComposerLock(filePath string, packages *[]Package, scannedProjects *[]string,
	seen map[string]bool, addManager func(string)) {

	data, err := os.ReadFile(filePath)
	if err != nil {
		return
	}

	dir := filepath.Dir(filePath)
	*scannedProjects = append(*scannedProjects, dir)
	addManager("composer")

	var lockfile struct {
		Packages    []composerPkg `json:"packages"`
		PackagesDev []composerPkg `json:"packages-dev"`
	}
	if json.Unmarshal(data, &lockfile) != nil {
		return
	}

	all := append(lockfile.Packages, lockfile.PackagesDev...)
	for _, pkg := range all {
		key := fmt.Sprintf("composer:%s:%s:%s", pkg.Name, pkg.Version, dir)
		addComposerPackage(pkg.Name, pkg.Version, key, dir, "project", packages, seen)
	}
}

// parseComposerJSON parses a composer.json manifest.
//
// This runs only when composer.lock is absent. A lockfile carries resolved
// versions and is strictly better, so when both exist the lockfile wins and
// this is not called -- otherwise every package would be reported twice, once
// resolved and once as a constraint.
//
// The versions here are constraints ("^6.3"), not installed versions, which is
// the same thing parsePackageJSON records for a lockfile-less Node project.
// They make the project and its declared dependencies visible in the
// inventory; they will not match an OSV advisory, so a project in this state
// is reported but not correlated.
func parseComposerJSON(filePath string, packages *[]Package, scannedProjects *[]string,
	seen map[string]bool, addManager func(string)) {

	data, err := os.ReadFile(filePath)
	if err != nil {
		return
	}

	var manifest struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if json.Unmarshal(data, &manifest) != nil {
		return
	}

	dir := filepath.Dir(filePath)
	*scannedProjects = append(*scannedProjects, dir)
	addManager("composer")

	for _, deps := range []map[string]string{manifest.Require, manifest.RequireDev} {
		for name, constraint := range deps {
			if !isComposerPackageName(name) {
				continue
			}
			key := fmt.Sprintf("composer:%s:%s:%s", name, constraint, dir)
			addComposerPackage(name, constraint, key, dir, "project", packages, seen)
		}
	}
}

// isComposerPackageName reports whether a "require" key names a real Packagist
// package rather than a platform requirement.
//
// Composer mixes the runtime itself into the same map: "php": "^8.1",
// "ext-json": "*", "lib-curl" and "composer-runtime-api" are requirements but
// not packages. Every Packagist package is "vendor/name", so the slash is the
// discriminator.
func isComposerPackageName(name string) bool {
	return strings.Contains(name, "/")
}

// scanComposerGlobal scans packages installed by "composer global require".
//
// These matter more than their count suggests: a global Composer install puts
// executables on PATH, which is where a malicious package does the most damage,
// and nothing about it appears in any project's lockfile.
func scanComposerGlobal(homeDir string, packages *[]Package, seen map[string]bool, addManager func(string)) {
	for _, dir := range composerGlobalDirs(homeDir) {
		installed := filepath.Join(dir, "vendor", "composer", "installed.json")
		data, err := os.ReadFile(installed)
		if err != nil {
			continue
		}
		for _, pkg := range parseComposerInstalled(data) {
			key := fmt.Sprintf("composer:%s:%s:global", pkg.Name, pkg.Version)
			if !seen[key] {
				addManager("composer")
			}
			addComposerPackage(pkg.Name, pkg.Version, key, "", "global", packages, seen)
		}
	}
}

// parseComposerInstalled decodes vendor/composer/installed.json, which changed
// shape between major versions: Composer 1 wrote a bare array of packages,
// Composer 2 wraps them in an object under "packages". Both are still found on
// real machines, so both are accepted.
func parseComposerInstalled(data []byte) []composerPkg {
	var v2 struct {
		Packages []composerPkg `json:"packages"`
	}
	if json.Unmarshal(data, &v2) == nil && v2.Packages != nil {
		return v2.Packages
	}

	var v1 []composerPkg
	if json.Unmarshal(data, &v1) == nil {
		return v1
	}
	return nil
}

// composerGlobalDirs returns candidate COMPOSER_HOME directories, in the order
// Composer itself resolves them.
func composerGlobalDirs(homeDir string) []string {
	var dirs []string

	// An explicit COMPOSER_HOME overrides every default.
	if h := os.Getenv("COMPOSER_HOME"); h != "" {
		dirs = append(dirs, h)
	}
	if homeDir == "" {
		return dirs
	}

	if runtime.GOOS == "windows" {
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			dirs = append(dirs, filepath.Join(appdata, "Composer"))
		}
	}

	// ~/.composer is the historical location; ~/.config/composer is where
	// current Composer puts it. Machines upgraded in place often have both.
	dirs = append(dirs, filepath.Join(homeDir, ".composer"))
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		dirs = append(dirs, filepath.Join(xdg, "composer"))
	}
	dirs = append(dirs, filepath.Join(homeDir, ".config", "composer"))

	return dirs
}
