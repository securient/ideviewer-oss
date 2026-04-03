package dependencies

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// parseComposerLock parses a PHP composer.lock file.
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
		name := pkg.Name
		version := pkg.Version
		if name == "" {
			name = "unknown"
		}
		if version == "" {
			version = "unknown"
		}

		key := fmt.Sprintf("composer:%s:%s:%s", name, version, dir)
		if seen[key] {
			continue
		}
		seen[key] = true
		*packages = append(*packages, Package{
			Name:           name,
			Version:        version,
			PackageManager: "composer",
			InstallType:    "project",
			ProjectPath:    dir,
		})
	}
}

type composerPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
