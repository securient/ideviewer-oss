package dependencies

import (
	"os"
	"path/filepath"
	"strings"
)

// searchDirs are subdirectories of home to search (empty string = home itself).
var searchDirs = []string{
	"",
	"Documents",
	"Projects",
	"Development",
	"dev",
	"projects",
	"code",
	"src",
	"work",
	"workspace",
	"repos",
	"git",
	"github",
	"go/src",
}

// skipDirs are directories to skip during recursive scanning.
var skipDirs = map[string]bool{
	"node_modules": true, "venv": true, ".venv": true, "__pycache__": true,
	".git": true, "vendor": true, "dist": true, "build": true,
	".cache": true, "target": true, ".cargo": true,
	"Library": true, "Applications": true, ".Trash": true,
	"tmp": true, "temp": true,
}

// Scanner scans for installed packages across multiple package managers.
type Scanner struct {
	MaxDepth   int
	ScanGlobal bool
	HomeDir    string
}

// NewScanner creates a Scanner with sensible defaults.
func NewScanner() *Scanner {
	home, _ := os.UserHomeDir()
	return &Scanner{
		MaxDepth:   4,
		ScanGlobal: true,
		HomeDir:    home,
	}
}

// Scan scans for installed dependencies.
func (s *Scanner) Scan(additionalPaths ...string) (*DependencyResult, error) {
	var (
		packages        []Package
		scannedProjects []string
		managers        []string
		errors          []string
	)
	seen := make(map[string]bool) // Dedupe: "manager:name:version:path"
	managersSet := make(map[string]bool)

	// Helper to track managers.
	addManager := func(m string) {
		if !managersSet[m] {
			managersSet[m] = true
			managers = append(managers, m)
		}
	}

	// Scan global packages.
	if s.ScanGlobal {
		scanPipGlobal(&packages, seen, &errors, addManager)
		scanNPMGlobal(&packages, seen, &errors, addManager)
		scanGoGlobal(s.HomeDir, &packages, seen, addManager)
		scanCargoGlobal(&packages, seen, &errors, addManager)
		scanGemGlobal(&packages, seen, &errors, addManager)
		scanComposerGlobal(s.HomeDir, &packages, seen, addManager)
		scanBrewGlobal(&packages, seen, &errors, addManager)
	}

	// Build scan directories.
	//
	// Roots are deduplicated by filesystem identity rather than by path
	// string. searchDirs lists spellings that differ only in case ("Projects"
	// and "projects", "dev" and "Development"), and on a case-insensitive
	// filesystem -- APFS by default on macOS, NTFS on Windows -- several of
	// them stat successfully and resolve to one directory. Each spelling then
	// walked the same tree and produced a different dedup key for every
	// package found, so a machine with ~/Projects reported its whole project
	// inventory twice.
	var scanDirsSlice []string
	var seenRoots []os.FileInfo

	addRoot := func(dir string) {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			return
		}
		for _, prior := range seenRoots {
			if os.SameFile(prior, info) {
				return
			}
		}
		seenRoots = append(seenRoots, info)
		scanDirsSlice = append(scanDirsSlice, dir)
	}

	for _, subdir := range searchDirs {
		if subdir == "" {
			addRoot(s.HomeDir)
			continue
		}
		addRoot(filepath.Join(s.HomeDir, subdir))
	}

	for _, p := range additionalPaths {
		addRoot(p)
	}

	// Scan project directories.
	for _, dir := range scanDirsSlice {
		s.scanDirectory(dir, &packages, &scannedProjects, seen, &errors, addManager, 0)
	}

	// Scan IDE extension bundled dependencies.
	scanExtensionDependencies(&packages, seen, &errors, addManager)

	return NewDependencyResult(packages, scannedProjects, errors), nil
}

// scanDirectory recursively scans directories for project dependency files.
func (s *Scanner) scanDirectory(directory string, packages *[]Package, scannedProjects *[]string,
	seen map[string]bool, errors *[]string, addManager func(string), depth int) {

	if depth > s.MaxDepth {
		return
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		return
	}

	nameSet := make(map[string]bool)
	for _, e := range entries {
		nameSet[e.Name()] = true
	}

	// Python projects.
	if nameSet["requirements.txt"] {
		parseRequirementsTxt(filepath.Join(directory, "requirements.txt"), packages, scannedProjects, seen, addManager)
	}
	if nameSet["Pipfile.lock"] {
		parsePipfileLock(filepath.Join(directory, "Pipfile.lock"), packages, scannedProjects, seen, addManager)
	}
	if nameSet["poetry.lock"] {
		parsePoetryLock(filepath.Join(directory, "poetry.lock"), packages, scannedProjects, seen, addManager)
	}

	// Node.js projects.
	if nameSet["package.json"] {
		parsePackageJSON(filepath.Join(directory, "package.json"), packages, scannedProjects, seen, addManager)
	}

	// Go projects.
	if nameSet["go.mod"] {
		parseGoMod(filepath.Join(directory, "go.mod"), packages, scannedProjects, seen, addManager)
	}

	// Rust projects.
	if nameSet["Cargo.lock"] {
		parseCargoLock(filepath.Join(directory, "Cargo.lock"), packages, scannedProjects, seen, addManager)
	}

	// Ruby projects.
	if nameSet["Gemfile.lock"] {
		parseGemfileLock(filepath.Join(directory, "Gemfile.lock"), packages, scannedProjects, seen, addManager)
	}

	// PHP projects. The lockfile carries resolved versions, so it wins; the
	// manifest is only read when there is no lockfile, which is how a project
	// that gitignores composer.lock still appears in the inventory.
	if nameSet["composer.lock"] {
		parseComposerLock(filepath.Join(directory, "composer.lock"), packages, scannedProjects, seen, addManager)
	} else if nameSet["composer.json"] {
		parseComposerJSON(filepath.Join(directory, "composer.json"), packages, scannedProjects, seen, addManager)
	}

	// Recurse into subdirectories.
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if skipDirs[name] || strings.HasPrefix(name, ".") {
			continue
		}
		s.scanDirectory(filepath.Join(directory, name), packages, scannedProjects, seen, errors, addManager, depth+1)
	}
}
