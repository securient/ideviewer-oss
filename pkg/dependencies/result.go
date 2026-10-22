package dependencies

import "time"

// Package represents a detected software package.
type Package struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	PackageManager  string            `json:"package_manager"`
	InstallType     string            `json:"install_type"` // "global" or "project"
	ProjectPath     string            `json:"project_path,omitempty"`
	LifecycleHooks  map[string]string `json:"lifecycle_hooks,omitempty"`
	SourceType      string            `json:"source_type"`                // "project", "global", or "extension"
	SourceExtension string            `json:"source_extension,omitempty"` // Extension ID when SourceType == "extension"
}

// DependencyResult holds the complete result of a dependency scan.
type DependencyResult struct {
	Timestamp            string               `json:"timestamp"`
	Packages             []Package            `json:"packages"`
	PackagesByManager    map[string][]Package `json:"packages_by_manager"`
	TotalPackages        int                  `json:"total_packages"`
	PackageManagersFound []string             `json:"package_managers_found"`
	ScannedProjects      []string             `json:"scanned_projects"`
	Summary              map[string]int       `json:"summary"`
	Errors               []string             `json:"errors"`
}

// NewDependencyResult creates a DependencyResult with computed totals.
func NewDependencyResult(packages []Package, scannedProjects []string, errors []string) *DependencyResult {
	byManager := make(map[string][]Package)
	summary := make(map[string]int)
	managersSet := make(map[string]bool)

	for i := range packages {
		// Default SourceType from InstallType if not explicitly set (backwards compat)
		if packages[i].SourceType == "" {
			packages[i].SourceType = packages[i].InstallType
		}
		byManager[packages[i].PackageManager] = append(byManager[packages[i].PackageManager], packages[i])
		summary[packages[i].PackageManager]++
		managersSet[packages[i].PackageManager] = true
	}

	managers := make([]string, 0, len(managersSet))
	for m := range managersSet {
		managers = append(managers, m)
	}

	return &DependencyResult{
		Timestamp:            time.Now().UTC().Format(time.RFC3339),
		Packages:             packages,
		PackagesByManager:    byManager,
		TotalPackages:        len(packages),
		PackageManagersFound: managers,
		ScannedProjects:      dedupeProjects(scannedProjects),
		Summary:              summary,
		Errors:               errors,
	}
}

// dedupeProjects removes repeated directories while preserving scan order.
//
// Every parser appends the directory it ran in, so a project holding both a
// package.json and a composer.lock was listed once per manifest, and a project
// reachable from two scan roots was listed again for each. The field is meant
// to answer "which projects were scanned", so repeats are noise.
func dedupeProjects(dirs []string) []string {
	if len(dirs) == 0 {
		return dirs
	}
	seen := make(map[string]bool, len(dirs))
	out := make([]string, 0, len(dirs))
	for _, d := range dirs {
		if seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}
