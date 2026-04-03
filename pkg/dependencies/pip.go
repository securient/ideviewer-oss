package dependencies

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// scanPipGlobal scans globally installed pip packages.
func scanPipGlobal(packages *[]Package, seen map[string]bool, errors *[]string, addManager func(string)) {
	pipCommands := [][]string{
		{"pip3", "list", "--format=json"},
		{"pip", "list", "--format=json"},
	}

	for _, cmd := range pipCommands {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
		c.Env = append(os.Environ(), "PIP_DISABLE_PIP_VERSION_CHECK=1")
		out, err := c.Output()
		cancel()

		if err != nil {
			continue
		}

		var pkgs []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if json.Unmarshal(out, &pkgs) != nil {
			continue
		}
		if len(pkgs) == 0 {
			continue
		}

		addManager("pip")
		for _, p := range pkgs {
			if p.Name == "" {
				continue
			}
			key := fmt.Sprintf("pip:%s:%s:global", p.Name, p.Version)
			if seen[key] {
				continue
			}
			seen[key] = true
			*packages = append(*packages, Package{
				Name:           p.Name,
				Version:        p.Version,
				PackageManager: "pip",
				InstallType:    "global",
			})
		}
		return // Success with first working command.
	}
}

var requirementsRe = regexp.MustCompile(`^([a-zA-Z0-9_-]+)(?:[=<>!~]+(.+))?`)

// parseRequirementsTxt parses a Python requirements.txt file.
func parseRequirementsTxt(filePath string, packages *[]Package, scannedProjects *[]string,
	seen map[string]bool, addManager func(string)) {

	data, err := os.ReadFile(filePath)
	if err != nil {
		return
	}

	dir := filepath.Dir(filePath)
	*scannedProjects = append(*scannedProjects, dir)
	addManager("pip")

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		m := requirementsRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := m[1]
		version := m[2]
		if version == "" {
			version = "any"
		}

		key := fmt.Sprintf("pip:%s:%s:%s", name, version, dir)
		if seen[key] {
			continue
		}
		seen[key] = true
		*packages = append(*packages, Package{
			Name:           name,
			Version:        version,
			PackageManager: "pip",
			InstallType:    "project",
			ProjectPath:    dir,
		})
	}
}

// parsePipfileLock parses a Pipenv Pipfile.lock file.
func parsePipfileLock(filePath string, packages *[]Package, scannedProjects *[]string,
	seen map[string]bool, addManager func(string)) {

	data, err := os.ReadFile(filePath)
	if err != nil {
		return
	}

	dir := filepath.Dir(filePath)
	*scannedProjects = append(*scannedProjects, dir)
	addManager("pipenv")

	var lockfile map[string]json.RawMessage
	if json.Unmarshal(data, &lockfile) != nil {
		return
	}

	for _, section := range []string{"default", "develop"} {
		raw, ok := lockfile[section]
		if !ok {
			continue
		}
		var pkgs map[string]struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(raw, &pkgs) != nil {
			continue
		}
		for name, info := range pkgs {
			version := strings.TrimLeft(info.Version, "=")
			if version == "" {
				version = "unknown"
			}
			key := fmt.Sprintf("pipenv:%s:%s:%s", name, version, dir)
			if seen[key] {
				continue
			}
			seen[key] = true
			*packages = append(*packages, Package{
				Name:           name,
				Version:        version,
				PackageManager: "pipenv",
				InstallType:    "project",
				ProjectPath:    dir,
			})
		}
	}
}

var poetryPkgRe = regexp.MustCompile(`(?s)\[\[package\]\]\s+name\s*=\s*"([^"]+)"\s+version\s*=\s*"([^"]+)"`)

// parsePoetryLock parses a Poetry poetry.lock file.
func parsePoetryLock(filePath string, packages *[]Package, scannedProjects *[]string,
	seen map[string]bool, addManager func(string)) {

	data, err := os.ReadFile(filePath)
	if err != nil {
		return
	}

	dir := filepath.Dir(filePath)
	*scannedProjects = append(*scannedProjects, dir)
	addManager("poetry")

	for _, m := range poetryPkgRe.FindAllStringSubmatch(string(data), -1) {
		name, version := m[1], m[2]
		key := fmt.Sprintf("poetry:%s:%s:%s", name, version, dir)
		if seen[key] {
			continue
		}
		seen[key] = true
		*packages = append(*packages, Package{
			Name:           name,
			Version:        version,
			PackageManager: "poetry",
			InstallType:    "project",
			ProjectPath:    dir,
		})
	}
}
