package dependencies

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// composerPackages returns just the Composer entries, keyed name -> version.
func composerPackages(packages []Package) map[string]string {
	out := make(map[string]string)
	for _, p := range packages {
		if p.PackageManager == "composer" {
			out[p.Name] = p.Version
		}
	}
	return out
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

const composerLockFixture = `{
  "packages": [
    {"name": "monolog/monolog", "version": "2.9.1"},
    {"name": "guzzlehttp/guzzle", "version": "7.8.0"}
  ],
  "packages-dev": [
    {"name": "phpunit/phpunit", "version": "10.4.2"}
  ]
}`

// A dev dependency still executes on the workstation, so it has to be
// inventoried alongside the runtime ones.
func TestParseComposerLockReadsBothPackageLists(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "composer.lock", composerLockFixture)

	var packages []Package
	var projects []string
	seen := make(map[string]bool)
	var managers []string

	parseComposerLock(path, &packages, &projects, seen, func(m string) { managers = append(managers, m) })

	got := composerPackages(packages)
	want := map[string]string{
		"monolog/monolog":   "2.9.1",
		"guzzlehttp/guzzle": "7.8.0",
		"phpunit/phpunit":   "10.4.2",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d packages, want %d: %v", len(got), len(want), got)
	}
	for name, version := range want {
		if got[name] != version {
			t.Errorf("%s = %q, want %q", name, got[name], version)
		}
	}

	if len(managers) == 0 || managers[0] != "composer" {
		t.Errorf("managers = %v, want composer registered", managers)
	}
	if len(projects) != 1 || projects[0] != dir {
		t.Errorf("scannedProjects = %v, want [%s]", projects, dir)
	}
	for _, p := range packages {
		if p.InstallType != "project" {
			t.Errorf("%s InstallType = %q, want project", p.Name, p.InstallType)
		}
		if p.ProjectPath != dir {
			t.Errorf("%s ProjectPath = %q, want %q", p.Name, p.ProjectPath, dir)
		}
	}
}

func TestParseComposerLockIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "composer.lock", composerLockFixture)

	var packages []Package
	var projects []string
	seen := make(map[string]bool)
	noop := func(string) {}

	parseComposerLock(path, &packages, &projects, seen, noop)
	first := len(packages)
	parseComposerLock(path, &packages, &projects, seen, noop)

	if len(packages) != first {
		t.Errorf("rescanning the same lockfile added packages: %d then %d", first, len(packages))
	}
}

func TestParseComposerLockIgnoresMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "composer.lock", "{not json")

	var packages []Package
	var projects []string

	parseComposerLock(path, &packages, &projects, make(map[string]bool), func(string) {})

	if len(packages) != 0 {
		t.Errorf("malformed lockfile produced %d packages, want 0", len(packages))
	}
}

// Platform requirements share the "require" map with real packages but are not
// installable Packagist entries, so they must not reach the inventory as
// packages that a vulnerability lookup would then try to resolve.
func TestParseComposerJSONSkipsPlatformRequirements(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "composer.json", `{
	  "require": {
	    "php": "^8.1",
	    "ext-json": "*",
	    "lib-curl": "*",
	    "composer-runtime-api": "^2.0",
	    "symfony/console": "^6.3"
	  },
	  "require-dev": {
	    "phpunit/phpunit": "^10.0"
	  }
	}`)

	var packages []Package
	var projects []string

	parseComposerJSON(path, &packages, &projects, make(map[string]bool), func(string) {})

	got := composerPackages(packages)
	if len(got) != 2 {
		t.Fatalf("got %d packages, want 2 (symfony/console, phpunit/phpunit): %v", len(got), got)
	}
	if got["symfony/console"] != "^6.3" {
		t.Errorf("symfony/console = %q, want ^6.3", got["symfony/console"])
	}
	if got["phpunit/phpunit"] != "^10.0" {
		t.Errorf("phpunit/phpunit = %q, want ^10.0", got["phpunit/phpunit"])
	}
	for _, bad := range []string{"php", "ext-json", "lib-curl", "composer-runtime-api"} {
		if _, found := got[bad]; found {
			t.Errorf("platform requirement %q was reported as a package", bad)
		}
	}
}

// The lockfile holds resolved versions and the manifest holds constraints.
// Reading both would report every package twice, once as "2.9.1" and once as
// "^2.9", so the manifest is only a fallback.
func TestScannerPrefersLockfileOverManifest(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "Documents", "php-app")
	writeFile(t, proj, "composer.lock", composerLockFixture)
	writeFile(t, proj, "composer.json", `{"require": {"monolog/monolog": "^2.9"}}`)

	s := &Scanner{MaxDepth: 4, ScanGlobal: false, HomeDir: home}
	res, err := s.Scan()
	if err != nil {
		t.Fatal(err)
	}

	got := composerPackages(res.Packages)
	if v := got["monolog/monolog"]; v != "2.9.1" {
		t.Errorf("monolog/monolog = %q, want the resolved 2.9.1 from the lockfile", v)
	}

	count := 0
	for _, p := range res.Packages {
		if p.PackageManager == "composer" && p.Name == "monolog/monolog" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("monolog/monolog reported %d times, want 1", count)
	}
}

func TestScannerFallsBackToManifestWithoutLockfile(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "Documents", "php-app")
	writeFile(t, proj, "composer.json", `{"require": {"laravel/framework": "^10.0"}}`)

	s := &Scanner{MaxDepth: 4, ScanGlobal: false, HomeDir: home}
	res, err := s.Scan()
	if err != nil {
		t.Fatal(err)
	}

	if v := composerPackages(res.Packages)["laravel/framework"]; v != "^10.0" {
		t.Errorf("laravel/framework = %q, want ^10.0 from the manifest", v)
	}
}

// Composer 2 wraps packages in an object; Composer 1 wrote a bare array. Both
// still exist on real machines.
func TestParseComposerInstalledAcceptsBothLayouts(t *testing.T) {
	v2 := []byte(`{"packages": [{"name": "psy/psysh", "version": "v0.11.0"}], "dev": false}`)
	if got := parseComposerInstalled(v2); len(got) != 1 || got[0].Name != "psy/psysh" {
		t.Errorf("Composer 2 layout parsed as %v", got)
	}

	v1 := []byte(`[{"name": "psy/psysh", "version": "v0.11.0"}]`)
	if got := parseComposerInstalled(v1); len(got) != 1 || got[0].Name != "psy/psysh" {
		t.Errorf("Composer 1 layout parsed as %v", got)
	}

	if got := parseComposerInstalled([]byte("{not json")); len(got) != 0 {
		t.Errorf("malformed installed.json parsed as %v, want nothing", got)
	}
}

// A "composer global require" package puts executables on PATH and appears in
// no project lockfile, so the global scan is the only thing that can see it.
func TestScanComposerGlobalFindsInstalledPackages(t *testing.T) {
	home := t.TempDir()
	t.Setenv("COMPOSER_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")

	vendor := filepath.Join(home, ".composer", "vendor", "composer")
	writeFile(t, vendor, "installed.json", `{"packages": [
	  {"name": "psy/psysh", "version": "v0.11.0"},
	  {"name": "friendsofphp/php-cs-fixer", "version": "v3.40.0"}
	]}`)

	var packages []Package
	var managers []string
	scanComposerGlobal(home, &packages, make(map[string]bool), func(m string) { managers = append(managers, m) })

	got := composerPackages(packages)
	if got["psy/psysh"] != "v0.11.0" {
		t.Errorf("psy/psysh = %q, want v0.11.0", got["psy/psysh"])
	}
	if got["friendsofphp/php-cs-fixer"] != "v3.40.0" {
		t.Errorf("php-cs-fixer = %q, want v3.40.0", got["friendsofphp/php-cs-fixer"])
	}
	for _, p := range packages {
		if p.InstallType != "global" {
			t.Errorf("%s InstallType = %q, want global", p.Name, p.InstallType)
		}
	}
	if len(managers) == 0 {
		t.Error("composer was not registered as a found package manager")
	}
}

// A machine upgraded in place can have both ~/.composer and ~/.config/composer.
func TestScanComposerGlobalDedupesAcrossHomes(t *testing.T) {
	home := t.TempDir()
	t.Setenv("COMPOSER_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")

	body := `{"packages": [{"name": "psy/psysh", "version": "v0.11.0"}]}`
	writeFile(t, filepath.Join(home, ".composer", "vendor", "composer"), "installed.json", body)
	writeFile(t, filepath.Join(home, ".config", "composer", "vendor", "composer"), "installed.json", body)

	var packages []Package
	scanComposerGlobal(home, &packages, make(map[string]bool), func(string) {})

	if len(packages) != 1 {
		t.Errorf("got %d packages, want 1 after deduplication: %v", len(packages), packages)
	}
}

func TestScanComposerGlobalHonoursComposerHome(t *testing.T) {
	custom := t.TempDir()
	t.Setenv("COMPOSER_HOME", custom)
	writeFile(t, filepath.Join(custom, "vendor", "composer"), "installed.json",
		`{"packages": [{"name": "vendor/tool", "version": "1.2.3"}]}`)

	var packages []Package
	scanComposerGlobal(t.TempDir(), &packages, make(map[string]bool), func(string) {})

	if got := composerPackages(packages)["vendor/tool"]; got != "1.2.3" {
		t.Errorf("vendor/tool = %q, want 1.2.3 via COMPOSER_HOME", got)
	}
}

func TestScanComposerGlobalWithoutComposerInstalled(t *testing.T) {
	t.Setenv("COMPOSER_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")

	var packages []Package
	managerCalled := false
	scanComposerGlobal(t.TempDir(), &packages, make(map[string]bool), func(string) { managerCalled = true })

	if len(packages) != 0 {
		t.Errorf("got %d packages on a machine without Composer, want 0", len(packages))
	}
	if managerCalled {
		t.Error("composer was registered as found although nothing was installed")
	}
}

// The regression: searchDirs lists both "Projects" and "projects". On a
// case-insensitive filesystem both stat successfully and name one directory,
// so each was walked separately and every package was counted once per
// spelling. Roots are now deduplicated by filesystem identity.
func TestScannerDoesNotDoubleCountCaseAliasedRoots(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "Projects", "php-app")
	writeFile(t, proj, "composer.lock", composerLockFixture)

	// Confirm the filesystem really is case-insensitive before asserting on
	// the behaviour that only matters there; on a case-sensitive filesystem
	// ~/projects simply does not exist and there is nothing to deduplicate.
	lower := filepath.Join(home, "projects")
	if _, err := os.Stat(lower); err != nil {
		t.Skipf("filesystem is case-sensitive (%s does not exist); no aliasing to test", lower)
	}

	s := &Scanner{MaxDepth: 4, ScanGlobal: false, HomeDir: home}
	res, err := s.Scan()
	if err != nil {
		t.Fatal(err)
	}

	for name, count := range countByName(res.Packages) {
		if count != 1 {
			t.Errorf("%s reported %d times, want 1", name, count)
		}
	}
	if n := len(res.ScannedProjects); n != 1 {
		t.Errorf("ScannedProjects has %d entries, want 1: %v", n, res.ScannedProjects)
	}
}

func countByName(packages []Package) map[string]int {
	out := make(map[string]int)
	for _, p := range packages {
		if p.PackageManager == "composer" {
			out[p.Name]++
		}
	}
	return out
}

// A project holding manifests for several ecosystems was listed once per
// parser that ran in it.
func TestScannedProjectsListsEachDirectoryOnce(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "Documents", "polyglot")
	writeFile(t, proj, "composer.lock", composerLockFixture)
	writeFile(t, proj, "package.json", `{"dependencies": {"express": "^4.18.0"}}`)
	writeFile(t, proj, "go.mod", "module example.com/x\n\ngo 1.21\n")

	s := &Scanner{MaxDepth: 4, ScanGlobal: false, HomeDir: home}
	res, err := s.Scan()
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for _, d := range res.ScannedProjects {
		if d == proj {
			count++
		}
	}
	if count != 1 {
		t.Errorf("project listed %d times in ScannedProjects, want 1: %v", count, res.ScannedProjects)
	}
}

func TestComposerGlobalDirsIncludesPlatformLocations(t *testing.T) {
	t.Setenv("COMPOSER_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	home := "/home/dev"

	dirs := composerGlobalDirs(home)
	for _, want := range []string{
		filepath.Join(home, ".composer"),
		filepath.Join(home, ".config", "composer"),
	} {
		found := false
		for _, d := range dirs {
			if d == want {
				found = true
			}
		}
		if !found {
			t.Errorf("expected %s among composer dirs, got %v", want, dirs)
		}
	}

	if runtime.GOOS == "windows" {
		t.Setenv("APPDATA", `C:\Users\dev\AppData\Roaming`)
		if got := composerGlobalDirs(home); len(got) == 0 {
			t.Error("expected an APPDATA location on Windows")
		}
	}
}
