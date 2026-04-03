package dependencies

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// scanGoGlobal scans Go installed tools in ~/go/bin.
func scanGoGlobal(homeDir string, packages *[]Package, seen map[string]bool, addManager func(string)) {
	goBin := filepath.Join(homeDir, "go", "bin")
	entries, err := os.ReadDir(goBin)
	if err != nil {
		return
	}

	addManager("go")

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		// Check if executable.
		if info.Mode()&0111 == 0 {
			continue
		}
		name := entry.Name()
		key := fmt.Sprintf("go:%s:installed:global", name)
		if seen[key] {
			continue
		}
		seen[key] = true
		*packages = append(*packages, Package{
			Name:           name,
			Version:        "installed",
			PackageManager: "go",
			InstallType:    "global",
		})
	}
}

// parseGoMod parses a Go go.mod file.
func parseGoMod(filePath string, packages *[]Package, scannedProjects *[]string,
	seen map[string]bool, addManager func(string)) {

	data, err := os.ReadFile(filePath)
	if err != nil {
		return
	}

	dir := filepath.Dir(filePath)
	*scannedProjects = append(*scannedProjects, dir)
	addManager("go")

	inRequire := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "require (") {
			inRequire = true
			continue
		}
		if line == ")" {
			inRequire = false
			continue
		}
		if strings.HasPrefix(line, "require ") {
			parts := strings.Fields(line[8:])
			if len(parts) >= 2 {
				addGoPackage(parts[0], parts[1], dir, packages, seen)
			}
			continue
		}
		if inRequire && line != "" && !strings.HasPrefix(line, "//") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				addGoPackage(parts[0], parts[1], dir, packages, seen)
			}
		}
	}
}

func addGoPackage(name, version, dir string, packages *[]Package, seen map[string]bool) {
	key := fmt.Sprintf("go:%s:%s:%s", name, version, dir)
	if seen[key] {
		return
	}
	seen[key] = true
	*packages = append(*packages, Package{
		Name:           name,
		Version:        version,
		PackageManager: "go",
		InstallType:    "project",
		ProjectPath:    dir,
	})
}
