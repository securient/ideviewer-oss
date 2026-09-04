package watcher

import (
	"os"
	"path/filepath"
	"runtime"
)

// Category classifies what a watched directory holds.
//
// A change is only interesting in terms of what it invalidates: a new file in
// an extension directory says nothing about the machine's Python packages. The
// category rides along on every ChangeEvent so the daemon can run just the
// rescan the change implies instead of re-inventorying the whole workstation
// on every touched file.
type Category string

const (
	// CategoryExtensions covers IDE extension and plugin directories.
	CategoryExtensions Category = "extensions"
	// CategoryAITools covers AI assistant configuration and MCP server
	// definitions.
	CategoryAITools Category = "aitools"
	// CategoryProjects covers project directories holding dependency
	// manifests. Secrets live in the same directories (.env and friends), so
	// this category invalidates both the dependency and the secret inventory.
	CategoryProjects Category = "projects"
)

// maxWatches bounds how many directories we hand to the kernel.
//
// Each watched path costs a file descriptor under kqueue (macOS/BSD) and an
// inotify watch on Linux, where max_user_watches still defaults to 8192 on
// some distributions. Project discovery is data-dependent -- a machine with a
// large repo collection could otherwise exhaust the budget and take unrelated
// software down with it -- so discovery stops here and says so.
const maxWatches = 2048

// maxProjectDepth is how deep below each search root a project may sit.
//
// Matches the dependency scanner's own MaxDepth, so the watcher covers the
// same ground the periodic scan does and the two cannot disagree about which
// projects exist.
const maxProjectDepth = 4

// projectSearchDirs are the subdirectories of home that may hold projects
// (empty string means home itself). Kept in step with the dependency and
// secret scanners, which walk the same list.
var projectSearchDirs = []string{
	"", "Documents", "Projects", "Development", "dev", "projects",
	"code", "src", "work", "workspace", "repos", "git", "github", "go/src",
}

// skipDirs are never descended into when looking for projects.
//
// node_modules is the important one: watching it would mean tens of thousands
// of directories, and it buys nothing. Installing a package rewrites the
// manifest and lockfile in the project directory itself, which we do watch, so
// the change is caught there.
var skipDirs = map[string]bool{
	"node_modules": true, "venv": true, ".venv": true, "__pycache__": true,
	".git": true, "vendor": true, "dist": true, "build": true,
	".cache": true, "target": true, ".cargo": true,
	"Library": true, "Applications": true, ".Trash": true,
	"tmp": true, "temp": true,
}

// manifestFiles mark a directory as a project worth watching. Presence of any
// one of these is enough; the daemon rescans the whole project on a change
// rather than trying to map file to package manager.
var manifestFiles = map[string]bool{
	// Node
	"package.json": true, "package-lock.json": true,
	"yarn.lock": true, "pnpm-lock.yaml": true,
	// Python
	"requirements.txt": true, "Pipfile": true, "Pipfile.lock": true,
	"poetry.lock": true, "pyproject.toml": true,
	// Go
	"go.mod": true, "go.sum": true,
	// Rust
	"Cargo.toml": true, "Cargo.lock": true,
	// Ruby
	"Gemfile": true, "Gemfile.lock": true,
	// PHP
	"composer.json": true, "composer.lock": true,
}

// watchRoot is one directory to watch and what a change in it means.
type watchRoot struct {
	Path     string
	Category Category
}

// discoverRoots returns every directory worth watching, in priority order.
//
// Order matters because of maxWatches: extension and AI-tool directories are a
// fixed handful and are the highest-signal (an extension or MCP server
// appearing is the attack this product exists to catch), so they are claimed
// first. Project directories are unbounded in principle and take what is left.
func discoverRoots() []watchRoot {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	var roots []watchRoot
	seen := make(map[string]bool)

	add := func(path string, cat Category) {
		if path == "" || seen[path] || len(roots) >= maxWatches {
			return
		}
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() {
			return
		}
		seen[path] = true
		roots = append(roots, watchRoot{Path: path, Category: cat})
	}

	for _, d := range extensionDirs() {
		add(d, CategoryExtensions)
	}
	for _, d := range aiToolDirs(home) {
		add(d, CategoryAITools)
	}
	for _, d := range projectDirs(home) {
		add(d, CategoryProjects)
	}

	return roots
}

// aiToolDirs returns directories holding AI assistant config and MCP server
// definitions: ~/.cursor/mcp.json, ~/.kiro/settings/mcp.json, ~/.claude, the
// IDE "User" settings directories, and the openclaw/clawdbot config trees.
//
// These are watched rather than the individual files because editors write
// config by writing a temporary file and renaming it over the target. A watch
// on the file itself follows the replaced inode and goes silent after the
// first save; a watch on the directory sees the rename.
func aiToolDirs(home string) []string {
	dirs := []string{
		filepath.Join(home, ".claude"),
		filepath.Join(home, ".cursor"),
		filepath.Join(home, ".kiro"),
		filepath.Join(home, ".kiro", "settings"),
		filepath.Join(home, ".openclaw"),
		filepath.Join(home, ".clawdbot"),
		filepath.Join(home, ".config", "openclaw"),
		filepath.Join(home, ".config", "clawdbot"),
	}

	// IDE user-settings directories, which carry MCP server definitions under
	// the editor's own settings.json.
	editors := []string{"Code", "Cursor", "Kiro", "VSCodium"}
	for _, editor := range editors {
		switch runtime.GOOS {
		case "darwin":
			dirs = append(dirs,
				filepath.Join(home, "Library", "Application Support", editor, "User"))
		case "linux":
			dirs = append(dirs, filepath.Join(home, ".config", editor, "User"))
		case "windows":
			if appdata := os.Getenv("APPDATA"); appdata != "" {
				dirs = append(dirs, filepath.Join(appdata, editor, "User"))
			}
		}
	}

	return dirs
}

// projectDirs returns directories that contain a dependency manifest.
//
// Only directories holding a manifest are watched, not every directory walked:
// on a developer laptop the walk sees thousands of directories but only a
// couple of hundred are projects, and watching the rest would spend the watch
// budget on noise.
func projectDirs(home string) []string {
	var found []string
	budget := maxWatches

	for _, sub := range projectSearchDirs {
		if budget <= 0 {
			break
		}
		root := home
		if sub != "" {
			root = filepath.Join(home, sub)
		}
		walkProjects(root, 0, &found, &budget)
	}
	return found
}

// walkProjects descends up to maxProjectDepth collecting manifest-bearing
// directories. It reads each directory once and never follows symlinks, so a
// symlink loop cannot hang the daemon at startup.
func walkProjects(dir string, depth int, found *[]string, budget *int) {
	if depth > maxProjectDepth || *budget <= 0 {
		return
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	hasManifest := false
	var subdirs []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			// IsDir() is false for symlinks, so this skips them by
			// construction -- a symlinked directory is never descended.
			if !skipDirs[name] {
				subdirs = append(subdirs, filepath.Join(dir, name))
			}
			continue
		}
		if manifestFiles[name] {
			hasManifest = true
		}
	}

	if hasManifest {
		*found = append(*found, dir)
		*budget--
	}

	for _, sub := range subdirs {
		walkProjects(sub, depth+1, found, budget)
	}
}
