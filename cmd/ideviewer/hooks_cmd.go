package main

import (
	"fmt"

	"github.com/securient/ideviewer-oss/pkg/gitleaks"
	"github.com/securient/ideviewer-oss/pkg/hooks"
	"github.com/spf13/cobra"
)

var hooksCmd = &cobra.Command{
	Use:   "hooks",
	Short: "Manage pre-commit hooks for secret scanning",
}

var hooksStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the current status of global pre-commit hooks",
	RunE:  runHooksStatus,
}

var hooksInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install global pre-commit hooks",
	RunE:  runHooksInstall,
}

var hooksUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall global pre-commit hooks",
	RunE:  runHooksUninstall,
}

func init() {
	hooksCmd.AddCommand(hooksStatusCmd)
	hooksCmd.AddCommand(hooksInstallCmd)
	hooksCmd.AddCommand(hooksUninstallCmd)
}

func runHooksStatus(cmd *cobra.Command, args []string) error {
	status, err := hooks.Status()
	if err != nil {
		return fmt.Errorf("failed to check hook status: %w", err)
	}

	fmt.Println("=== Pre-commit Hook Status ===")
	fmt.Println()

	if status.Installed {
		colorGreen.Println("  Installed:  Yes")
	} else {
		colorRed.Println("  Installed:  No")
	}

	colorCyan.Printf("  Hook path:  %s\n", status.HookPath)
	colorCyan.Printf("  Scanner:    %s\n", status.ScannerType)

	if status.GitleaksVersion != "" {
		colorCyan.Printf("  Gitleaks:   %s\n", status.GitleaksVersion)
	} else {
		colorDim.Println("  Gitleaks:   Not installed (using built-in scanner)")
	}

	return nil
}

func runHooksInstall(cmd *cobra.Command, args []string) error {
	colorCyan.Println("Installing gitleaks...")
	if err := gitleaks.Install(); err != nil {
		colorYellow.Printf("  Could not install gitleaks; built-in scanner will be used: %v\n", err)
	} else {
		if v, err := gitleaks.GetVersion(); err == nil {
			colorGreen.Printf("  gitleaks installed (version: %s)\n", v)
		}
	}

	colorCyan.Println("Installing global hooks...")
	if err := hooks.Install(); err != nil {
		colorRed.Printf("  Failed to install global hooks: %v\n", err)
		return fmt.Errorf("hook installation failed: %w", err)
	}

	colorGreen.Println("  Global pre-commit hooks installed")
	return nil
}

func runHooksUninstall(cmd *cobra.Command, args []string) error {
	if err := hooks.Uninstall(); err != nil {
		colorRed.Printf("Failed to uninstall global hooks: %v\n", err)
		return fmt.Errorf("hook uninstall failed: %w", err)
	}

	colorGreen.Println("Global hooks uninstalled")
	return nil
}
