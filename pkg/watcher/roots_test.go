package watcher

import (
	"os"
	"path/filepath"
	"testing"
)

// mkdirs creates dir and any parents under root, failing the test on error.
func mkdirs(t *testing.T, parts ...string) string {
	t.Helper()
	p := filepath.Join(parts...)
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", p, err)
	}
	return p
}

func touch(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o644); err != nil {
		t.Fatalf("write %s/%s: %v", dir, name, err)
	}
}

// setHome points os.UserHomeDir() at dir.
//
// It sets USERPROFILE as well as HOME because that is what os.UserHomeDir()
// reads on Windows -- setting only HOME left discoverRoots scanning the real
// home directory there, so the fixtures were invisible and the categories came
// back empty.
func setHome(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
}

func contains(dirs []string, want string) bool {
	for _, d := range dirs {
		if d == want {
			return true
		}
	}
	return false
}

func TestProjectDirsFindsManifestDirectories(t *testing.T) {
	home := t.TempDir()

	node := mkdirs(t, home, "Projects", "web")
	touch(t, node, "package.json")

	golang := mkdirs(t, home, "code", "svc")
	touch(t, golang, "go.mod")

	rust := mkdirs(t, home, "src", "cli")
	touch(t, rust, "Cargo.lock")

	// A directory with no manifest must not be watched.
	plain := mkdirs(t, home, "Documents", "notes")

	dirs := projectDirs(home)

	for _, want := range []string{node, golang, rust} {
		if !contains(dirs, want) {
			t.Errorf("expected %s to be watched, got %v", want, dirs)
		}
	}
	if contains(dirs, plain) {
		t.Errorf("directory without a manifest should not be watched: %s", plain)
	}
}

func TestProjectDirsSkipsNodeModules(t *testing.T) {
	home := t.TempDir()

	proj := mkdirs(t, home, "Projects", "app")
	touch(t, proj, "package.json")

	// node_modules is full of package.json files. Watching it would cost tens
	// of thousands of watches and buys nothing, because an install rewrites
	// the manifest in the project directory we already watch.
	dep := mkdirs(t, proj, "node_modules", "left-pad")
	touch(t, dep, "package.json")

	dirs := projectDirs(home)

	if !contains(dirs, proj) {
		t.Errorf("expected the project itself to be watched, got %v", dirs)
	}
	if contains(dirs, dep) {
		t.Errorf("node_modules must never be watched, got %v", dirs)
	}
}

func TestProjectDirsRespectsMaxDepth(t *testing.T) {
	home := t.TempDir()

	// One level deeper than maxProjectDepth allows from the home root.
	parts := []string{home}
	for i := 0; i <= maxProjectDepth+1; i++ {
		parts = append(parts, "d")
	}
	deep := mkdirs(t, parts...)
	touch(t, deep, "package.json")

	if contains(projectDirs(home), deep) {
		t.Errorf("directory below maxProjectDepth should not be watched: %s", deep)
	}
}

func TestAIToolDirsCoversConfigAndMCPLocations(t *testing.T) {
	home := t.TempDir()
	dirs := aiToolDirs(home)

	// These hold MCP server definitions and assistant permissions, which is
	// exactly the config an attacker would add a server to.
	for _, want := range []string{
		filepath.Join(home, ".claude"),
		filepath.Join(home, ".cursor"),
		filepath.Join(home, ".kiro", "settings"),
	} {
		if !contains(dirs, want) {
			t.Errorf("expected %s among AI tool dirs, got %v", want, dirs)
		}
	}
}

func TestDiscoverRootsTagsEachDirectory(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)

	proj := mkdirs(t, home, "Projects", "app")
	touch(t, proj, "go.mod")
	mkdirs(t, home, ".claude")
	mkdirs(t, home, ".vscode", "extensions")

	byPath := make(map[string]Category)
	for _, r := range discoverRoots() {
		byPath[r.Path] = r.Category
	}

	if got := byPath[proj]; got != CategoryProjects {
		t.Errorf("project dir category = %q, want %q", got, CategoryProjects)
	}
	if got := byPath[filepath.Join(home, ".claude")]; got != CategoryAITools {
		t.Errorf(".claude category = %q, want %q", got, CategoryAITools)
	}
	if got := byPath[filepath.Join(home, ".vscode", "extensions")]; got != CategoryExtensions {
		t.Errorf("extensions category = %q, want %q", got, CategoryExtensions)
	}
}

func TestDiscoverRootsIsDeduplicated(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)

	// ~/.cursor is both an AI tool config directory and the parent of an
	// extensions directory, so the two lists can name overlapping paths.
	mkdirs(t, home, ".cursor", "extensions")
	mkdirs(t, home, ".claude")

	roots := discoverRoots()
	if len(roots) == 0 {
		// Guard against passing vacuously: with no roots discovered there is
		// nothing to duplicate, which is how this test stayed green on
		// Windows while the home override was not taking effect.
		t.Fatal("expected at least one discovered root")
	}

	seen := make(map[string]int)
	for _, r := range roots {
		seen[r.Path]++
	}
	for path, n := range seen {
		if n > 1 {
			t.Errorf("%s watched %d times, want 1", path, n)
		}
	}
}
