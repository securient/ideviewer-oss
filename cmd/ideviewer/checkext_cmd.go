package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/securient/ideviewer-oss/pkg/shiftleft"
	"github.com/spf13/cobra"
)

var checkExtCmd = &cobra.Command{
	Use:   "check-extension <publisher.name>",
	Short: "Check an extension against the threat feed before installing it (shift-left)",
	Long: `Evaluates an extension id against IDEViewer's threat-intelligence feed
(banned extensions, malicious publishers, typosquats) and prints any warnings.

This is the "warn" tier: by default it only warns and exits 0. Pass --strict to
exit non-zero when a threat is found (useful for wrapping installs in CI or a
shell function that should refuse on a hit).

  ideviewer check-extension ms-pythonn.python
  ideviewer check-extension evilcorp.tool --strict`,
	Args: cobra.ExactArgs(1),
	RunE: runCheckExt,
}

var installExtCmd = &cobra.Command{
	Use:   "install-extension <publisher.name>",
	Short: "Warn on threats, then install an extension via the IDE CLI (shift-left wrapper)",
	Long: `A drop-in wrapper around 'code --install-extension' that runs a threat
check first. In the default warn tier it always proceeds with the install after
printing any warnings; with --strict it refuses to install on a threat hit.

Tip: alias it in your shell so installs are checked automatically, e.g.
  code() { if [ "$1" = "--install-extension" ]; then ideviewer install-extension "$2"; else command code "$@"; fi; }`,
	Args: cobra.ExactArgs(1),
	RunE: runInstallExt,
}

func init() {
	checkExtCmd.Flags().String("publisher", "", "Explicit publisher (otherwise derived from the id)")
	checkExtCmd.Flags().Bool("strict", false, "Exit non-zero if a threat is found")
	installExtCmd.Flags().String("editor", "code", "Editor CLI to delegate the install to (code|codium|cursor)")
	installExtCmd.Flags().Bool("strict", false, "Refuse to install if a threat is found")
}

// printWarnings renders warnings and returns true if any were found.
func printWarnings(extID string, warnings []shiftleft.Warning) bool {
	if len(warnings) == 0 {
		colorGreen.Printf("  No threat-intel hits for %s (feed %s)\n", extID, shiftleft.FeedVersion())
		return false
	}
	colorYellow.Printf("  WARNING: %s matched %d threat indicator(s):\n", extID, len(warnings))
	for _, w := range warnings {
		colorRed.Printf("    • [%s/%s] %s\n", w.Severity, w.IndicatorType, w.Detail)
	}
	return true
}

func runCheckExt(cmd *cobra.Command, args []string) error {
	publisher, _ := cmd.Flags().GetString("publisher")
	strict, _ := cmd.Flags().GetBool("strict")
	found := printWarnings(args[0], shiftleft.CheckExtension(args[0], publisher, ""))
	if found && strict {
		os.Exit(2)
	}
	return nil
}

func runInstallExt(cmd *cobra.Command, args []string) error {
	editor, _ := cmd.Flags().GetString("editor")
	strict, _ := cmd.Flags().GetBool("strict")
	extID := args[0]

	found := printWarnings(extID, shiftleft.CheckExtension(extID, "", ""))
	if found && strict {
		colorRed.Println("  Refusing to install (--strict and a threat was found).")
		os.Exit(2)
	}
	if found {
		colorYellow.Println("  Proceeding with install anyway (warn tier). Use --strict to block.")
	}

	bin, err := exec.LookPath(editor)
	if err != nil {
		return fmt.Errorf("editor CLI %q not found on PATH: %w", editor, err)
	}
	c := exec.Command(bin, "--install-extension", extID)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}
