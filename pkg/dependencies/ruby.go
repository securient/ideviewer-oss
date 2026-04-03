package dependencies

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var gemListRe = regexp.MustCompile(`^([a-zA-Z0-9_-]+)\s+\((.+)\)$`)
var gemfileLockRe = regexp.MustCompile(`^\s{4}([a-zA-Z0-9_-]+)\s+\(([^)]+)\)`)

// scanGemGlobal scans globally installed Ruby gems.
func scanGemGlobal(packages *[]Package, seen map[string]bool, errors *[]string, addManager func(string)) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "gem", "list", "--local")
	out, err := cmd.Output()
	if err != nil {
		return
	}

	output := string(out)
	if output == "" {
		return
	}

	addManager("gem")

	for _, line := range strings.Split(output, "\n") {
		m := gemListRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		name := m[1]
		versions := strings.Split(m[2], ", ")
		version := "unknown"
		if len(versions) > 0 {
			version = strings.TrimSpace(versions[0])
		}

		key := fmt.Sprintf("gem:%s:%s:global", name, version)
		if seen[key] {
			continue
		}
		seen[key] = true
		*packages = append(*packages, Package{
			Name:           name,
			Version:        version,
			PackageManager: "gem",
			InstallType:    "global",
		})
	}
}

// parseGemfileLock parses a Ruby Gemfile.lock file.
func parseGemfileLock(filePath string, packages *[]Package, scannedProjects *[]string,
	seen map[string]bool, addManager func(string)) {

	data, err := os.ReadFile(filePath)
	if err != nil {
		return
	}

	dir := filepath.Dir(filePath)
	*scannedProjects = append(*scannedProjects, dir)
	addManager("gem")

	inSpecs := false
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "  specs:") {
			inSpecs = true
			continue
		}
		if inSpecs && len(line) > 0 && line[0] != ' ' {
			inSpecs = false
			continue
		}
		if !inSpecs {
			continue
		}

		m := gemfileLockRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name, version := m[1], m[2]

		key := fmt.Sprintf("gem:%s:%s:%s", name, version, dir)
		if seen[key] {
			continue
		}
		seen[key] = true
		*packages = append(*packages, Package{
			Name:           name,
			Version:        version,
			PackageManager: "gem",
			InstallType:    "project",
			ProjectPath:    dir,
		})
	}
}
