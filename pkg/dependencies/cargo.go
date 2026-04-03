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

var cargoInstallRe = regexp.MustCompile(`^([a-zA-Z0-9_-]+)\s+v(.+):$`)
var cargoLockPkgRe = regexp.MustCompile(`(?s)\[\[package\]\]\s+name\s*=\s*"([^"]+)"\s+version\s*=\s*"([^"]+)"`)

// scanCargoGlobal scans globally installed Rust cargo packages.
func scanCargoGlobal(packages *[]Package, seen map[string]bool, errors *[]string, addManager func(string)) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "cargo", "install", "--list")
	out, err := cmd.Output()
	if err != nil {
		return
	}

	output := string(out)
	if output == "" {
		return
	}

	addManager("cargo")

	for _, line := range strings.Split(output, "\n") {
		m := cargoInstallRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		name, version := m[1], m[2]
		key := fmt.Sprintf("cargo:%s:%s:global", name, version)
		if seen[key] {
			continue
		}
		seen[key] = true
		*packages = append(*packages, Package{
			Name:           name,
			Version:        version,
			PackageManager: "cargo",
			InstallType:    "global",
		})
	}
}

// parseCargoLock parses a Rust Cargo.lock file.
func parseCargoLock(filePath string, packages *[]Package, scannedProjects *[]string,
	seen map[string]bool, addManager func(string)) {

	data, err := os.ReadFile(filePath)
	if err != nil {
		return
	}

	dir := filepath.Dir(filePath)
	*scannedProjects = append(*scannedProjects, dir)
	addManager("cargo")

	for _, m := range cargoLockPkgRe.FindAllStringSubmatch(string(data), -1) {
		name, version := m[1], m[2]
		key := fmt.Sprintf("cargo:%s:%s:%s", name, version, dir)
		if seen[key] {
			continue
		}
		seen[key] = true
		*packages = append(*packages, Package{
			Name:           name,
			Version:        version,
			PackageManager: "cargo",
			InstallType:    "project",
			ProjectPath:    dir,
		})
	}
}
