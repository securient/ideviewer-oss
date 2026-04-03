//go:build !darwin

package dependencies

// scanBrewGlobal is a no-op on non-macOS platforms.
func scanBrewGlobal(packages *[]Package, seen map[string]bool, errors *[]string, addManager func(string)) {
	// Homebrew is only available on macOS.
}
