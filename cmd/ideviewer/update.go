package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

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

	fmt.Println("Downloading update...")
	if err := updater.DownloadAndInstall(info); err != nil {
		return fmt.Errorf("update failed: %w", err)
	}

	colorGreen.Printf("Updated to v%s!\n", info.LatestVersion)
	colorDim.Println("Restart the daemon to use the new version: ideviewer daemon --foreground")

	return nil
}
