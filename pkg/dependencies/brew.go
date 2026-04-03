//go:build darwin

package dependencies

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// scanBrewGlobal scans Homebrew installed packages (macOS only).
func scanBrewGlobal(packages *[]Package, seen map[string]bool, errors *[]string, addManager func(string)) {
	// Formulae.
	scanBrewList(packages, seen, errors, addManager, "brew", "--formula")

	// Casks.
	scanBrewList(packages, seen, errors, addManager, "brew-cask", "--cask")
}

func scanBrewList(packages *[]Package, seen map[string]bool, errors *[]string,
	addManager func(string), manager, flag string) {

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "brew", "list", flag, "--versions")
	out, err := cmd.Output()
	if err != nil {
		return
	}

	output := string(out)
	if output == "" {
		return
	}

	addManager(manager)

	for _, line := range strings.Split(output, "\n") {
		parts := strings.Fields(strings.TrimSpace(line))
		if len(parts) < 2 {
			continue
		}
		name := parts[0]
		version := parts[1] // Take first version if multiple.

		key := fmt.Sprintf("%s:%s:%s:global", manager, name, version)
		if seen[key] {
			continue
		}
		seen[key] = true
		*packages = append(*packages, Package{
			Name:           name,
			Version:        version,
			PackageManager: manager,
			InstallType:    "global",
		})
	}
}
