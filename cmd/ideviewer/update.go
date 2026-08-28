package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/securient/ideviewer-oss/internal/platform"
	"github.com/securient/ideviewer-oss/pkg/daemon"
	"github.com/securient/ideviewer-oss/pkg/updater"
	"github.com/spf13/cobra"
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Check for and install updates from GitHub releases",
	RunE:  runUpdate,
}

func init() {
	updateCmd.Flags().Bool("check", false, "Only check for updates, don't install")
	updateCmd.Flags().BoolP("yes", "y", false, "Skip confirmation prompt")
}

func runUpdate(cmd *cobra.Command, args []string) error {
	checkOnly, _ := cmd.Flags().GetBool("check")
	yes, _ := cmd.Flags().GetBool("yes")

	colorCyan.Println("Checking for updates...")

	info, err := updater.CheckForUpdate()
	if err != nil {
		return fmt.Errorf("failed to check for updates: %w", err)
	}

	if !info.UpdateAvailable {
		colorGreen.Printf("You're up to date! (v%s)\n", info.CurrentVersion)
		return nil
	}

	colorYellow.Printf("Update available: v%s -> v%s\n", info.CurrentVersion, info.LatestVersion)

	if checkOnly {
		colorDim.Println("Run 'ideviewer update' to install.")
		return nil
	}

	if info.DownloadURL == "" {
		return fmt.Errorf("no download available for this platform")
	}

	colorDim.Printf("Package: %s\n", info.AssetName)

	if !yes {
		fmt.Print("Install this update? [y/N] ")
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer != "y" && answer != "yes" {
			colorYellow.Println("Update cancelled.")
			return nil
		}
	}

	// Stop the daemon before the installer runs. On Windows the running
	// ideviewer.exe is locked, so a silent Inno upgrade either fails or defers
	// the replacement to the next reboot -- the user is told the update
	// succeeded while an old daemon keeps talking to the portal. Everywhere
	// else this just avoids running a half-replaced binary.
	pidFile := platform.DefaultPIDFile()
	wasRunning := daemon.IsRunning(pidFile)
	if wasRunning {
		colorDim.Println("Stopping the daemon before installing...")
		if err := stopDaemonForUpdate(pidFile); err != nil {
			return fmt.Errorf("could not stop the running daemon before updating: %w\n"+
				"Stop it manually with 'ideviewer stop' and re-run 'ideviewer update'", err)
		}
	}

	fmt.Println("Downloading update...")
	if err := updater.DownloadAndInstall(info); err != nil {
		if wasRunning {
			colorYellow.Println("Update failed; restarting the previous daemon.")
			restartDaemonAfterUpdate()
		}
		return fmt.Errorf("update failed: %w", err)
	}

	colorGreen.Printf("Updated to v%s!\n", info.LatestVersion)

	if wasRunning {
		colorDim.Println("Restarting the daemon...")
		restartDaemonAfterUpdate()
	} else {
		colorDim.Println("Start the daemon with: ideviewer daemon --foreground")
	}
	colorDim.Println("Verify with: ideviewer status")

	return nil
}

// stopDaemonForUpdate stops the daemon and waits for the process to exit, so
// the installer never races a live process holding the binary open.
func stopDaemonForUpdate(pidFile string) error {
	pid, err := daemon.ReadPIDFile(pidFile)
	if err != nil {
		return nil // nothing recorded, nothing to stop
	}
	if err := stopProcess(pid); err != nil {
		return err
	}
	for i := 0; i < 50; i++ {
		if !daemon.IsRunning(pidFile) {
			daemon.RemovePIDFile(pidFile)
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("daemon (PID %d) did not exit within 10s", pid)
}

// restartDaemonAfterUpdate relaunches the daemon from the installed location,
// reusing the same detach handling as registration.
func restartDaemonAfterUpdate() {
	if startDaemonService() {
		return
	}
	colorYellow.Println("Could not restart the daemon automatically.")
	colorCyan.Println("  Start it with: ideviewer daemon --foreground")
}
