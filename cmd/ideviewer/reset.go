package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/securient/ideviewer-oss/internal/config"
	"github.com/securient/ideviewer-oss/internal/platform"
	"github.com/securient/ideviewer-oss/pkg/daemon"
	"github.com/securient/ideviewer-oss/pkg/hooks"
	"github.com/spf13/cobra"
)

// resetCmd removes the state a reinstall would otherwise inherit.
//
// Uninstalling has never cleaned up completely — on Windows the installer
// deletes %LOCALAPPDATA%\IDEViewer and nothing else, so ProgramData and
// %USERPROFILE%\.ideviewer survive. Because Load() prefers those paths, the
// next install silently ran on a config from the previous one: the old portal
// URL, the old customer key, a host token for a database that no longer
// exists. This makes the cleanup a single, explicit command.
var resetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Remove local IDEViewer state (configuration, logs, hooks) for a clean reinstall",
	Long: `Remove the local state a reinstall would otherwise inherit.

By default this removes every configuration file IDEViewer can load, including
the ones an older install left in higher-priority directories. Nothing is sent
to the portal and no host records are deleted there.

Examples:
  ideviewer reset --config          # stale configuration only (the usual fix)
  ideviewer reset --all             # configuration, logs, hooks, quarantine
  ideviewer reset --all --yes       # no confirmation prompt`,
	RunE: runReset,
}

func init() {
	resetCmd.Flags().Bool("config", false, "Remove every IDEViewer configuration file (default when no other flag is given)")
	resetCmd.Flags().Bool("logs", false, "Remove daemon log files")
	resetCmd.Flags().Bool("hooks", false, "Uninstall the global git pre-commit hooks")
	resetCmd.Flags().Bool("quarantine", false, "Remove the quarantine directory (quarantined extensions are deleted)")
	resetCmd.Flags().Bool("all", false, "Everything above")
	resetCmd.Flags().BoolP("yes", "y", false, "Skip the confirmation prompt")
	resetCmd.Flags().Bool("keep-daemon", false, "Do not stop the running daemon first")
}

func runReset(cmd *cobra.Command, args []string) error {
	all, _ := cmd.Flags().GetBool("all")
	doConfig, _ := cmd.Flags().GetBool("config")
	doLogs, _ := cmd.Flags().GetBool("logs")
	doHooks, _ := cmd.Flags().GetBool("hooks")
	doQuarantine, _ := cmd.Flags().GetBool("quarantine")
	yes, _ := cmd.Flags().GetBool("yes")
	keepDaemon, _ := cmd.Flags().GetBool("keep-daemon")

	if all {
		doConfig, doLogs, doHooks, doQuarantine = true, true, true, true
	}
	// Bare 'ideviewer reset' means the common case: clear stale configuration.
	if !doConfig && !doLogs && !doHooks && !doQuarantine {
		doConfig = true
	}

	var targets []string
	if doConfig {
		targets = append(targets, config.ExistingPaths()...)
	}
	if doLogs {
		for _, p := range logPaths() {
			if platform.PathExists(p) {
				targets = append(targets, p)
			}
		}
	}
	if doQuarantine && platform.PathExists(platform.QuarantineDir()) {
		targets = append(targets, platform.QuarantineDir())
	}

	if len(targets) == 0 && !doHooks {
		colorGreen.Println("Nothing to remove — no IDEViewer state found.")
		return nil
	}

	fmt.Println("The following will be removed:")
	for _, t := range targets {
		fmt.Printf("  %s\n", t)
	}
	if doHooks {
		fmt.Printf("  global git pre-commit hooks (%s)\n", platform.HooksDir())
	}
	fmt.Println()

	if !yes && !confirm("Continue? [y/N] ") {
		colorYellow.Println("Cancelled.")
		return nil
	}

	// Stop the daemon first. Removing the config out from under a running
	// daemon leaves it happily using the copy it already has in memory, which
	// looks exactly like the reset not having worked.
	if !keepDaemon {
		pidFile := platform.DefaultPIDFile()
		if daemon.IsRunning(pidFile) {
			if pid, err := daemon.ReadPIDFile(pidFile); err == nil {
				colorDim.Printf("Stopping the daemon (PID %d)...\n", pid)
				if err := stopProcess(pid); err != nil {
					colorYellow.Printf("Could not stop the daemon: %v\n", err)
					colorYellow.Println("Stop it manually before reinstalling, or it will keep using the old configuration.")
				}
			}
		}
		daemon.RemovePIDFile(pidFile)
	}

	failures := 0
	for _, t := range targets {
		if err := os.RemoveAll(t); err != nil {
			colorRed.Printf("  Could not remove %s: %v\n", t, err)
			if os.IsPermission(err) {
				colorDim.Println("    This path needs elevated privileges (run as administrator / with sudo).")
			}
			failures++
			continue
		}
		colorGreen.Printf("  Removed %s\n", t)
	}

	if doHooks {
		if err := hooks.Uninstall(); err != nil {
			colorRed.Printf("  Could not uninstall git hooks: %v\n", err)
			failures++
		} else {
			colorGreen.Println("  Uninstalled global git pre-commit hooks")
		}
	}

	fmt.Println()
	if failures > 0 {
		return fmt.Errorf("%d item(s) could not be removed", failures)
	}
	colorGreen.Println("Reset complete.")
	if doConfig {
		colorDim.Println("Re-register with: ideviewer register --customer-key KEY --portal-url URL")
	}
	return nil
}

// logPaths returns the daemon log files this platform may have written.
func logPaths() []string {
	paths := []string{filepath.Join(platform.LogDir(), "daemon.log")}
	if runtime.GOOS == "darwin" {
		paths = append(paths, platform.DaemonLogFile())
	}
	return paths
}

func confirm(prompt string) bool {
	fmt.Print(prompt)
	answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false
	}
	answer = strings.TrimSpace(strings.ToLower(answer))
	return answer == "y" || answer == "yes"
}
