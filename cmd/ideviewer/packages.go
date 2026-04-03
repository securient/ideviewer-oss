package main

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/securient/ideviewer-oss/pkg/dependencies"
	"github.com/spf13/cobra"
)

var packagesCmd = &cobra.Command{
	Use:   "packages",
	Short: "Scan for installed packages and dependencies",
	Long: `Detect packages from various package managers including:
  - Python (pip, pipenv, poetry)
  - Node.js (npm, yarn)
  - Go modules
  - Rust (cargo)
  - Ruby (bundler)
  - PHP (composer)
  - Homebrew (macOS)`,
	RunE: runPackages,
}

func init() {
	packagesCmd.Flags().Bool("json", false, "Output as JSON")
	packagesCmd.Flags().Bool("global-only", false, "Only scan globally installed packages")
	packagesCmd.Flags().Bool("portal", false, "Send results to the portal")
}

func runPackages(cmd *cobra.Command, args []string) error {
	outputJSON, _ := cmd.Flags().GetBool("json")
	globalOnly, _ := cmd.Flags().GetBool("global-only")
	portal, _ := cmd.Flags().GetBool("portal")

	fmt.Println("Scanning for installed packages...")

	sc := dependencies.NewScanner()
	result, err := sc.Scan()
	if err != nil {
		return fmt.Errorf("dependency scan failed: %w", err)
	}

	// Portal mode.
	if portal {
		sendDepsToPortal(result)
	}

	if outputJSON {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}

	fmt.Println()
	colorCyan.Printf("Found %d packages\n\n", result.TotalPackages)

	if len(result.PackageManagersFound) > 0 {
		colorDim.Printf("Package managers: %s\n\n",
			join(result.PackageManagersFound, ", "))
	}

	// Group by manager.
	byManager := make(map[string][]dependencies.Package)
	for _, pkg := range result.Packages {
		if globalOnly && pkg.InstallType != "global" {
			continue
		}
		byManager[pkg.PackageManager] = append(byManager[pkg.PackageManager], pkg)
	}

	// Sort manager names.
	var managers []string
	for m := range byManager {
		managers = append(managers, m)
	}
	sort.Strings(managers)

	for _, mgr := range managers {
		pkgs := byManager[mgr]
		fmt.Printf("--- %s Packages (%d) ---\n", mgr, len(pkgs))

		limit := 25
		if len(pkgs) < limit {
			limit = len(pkgs)
		}

		var rows [][]string
		for _, pkg := range pkgs[:limit] {
			rows = append(rows, []string{pkg.Name, pkg.Version, pkg.InstallType})
		}
		printTable([]string{"Package", "Version", "Type"}, rows)

		if len(pkgs) > 25 {
			colorDim.Printf("... and %d more\n", len(pkgs)-25)
		}
		fmt.Println()
	}

	colorDim.Printf("Scanned %d project directories\n", len(result.ScannedProjects))

	return nil
}

func join(ss []string, sep string) string {
	if len(ss) == 0 {
		return ""
	}
	result := ss[0]
	for _, s := range ss[1:] {
		result += sep + s
	}
	return result
}
