package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/securient/ideviewer-oss/internal/config"
	"github.com/securient/ideviewer-oss/internal/platform"
	"github.com/securient/ideviewer-oss/internal/version"
	"github.com/securient/ideviewer-oss/pkg/api"
	"github.com/securient/ideviewer-oss/pkg/daemon"
	"github.com/spf13/cobra"
)

// statusCmd answers the first question of every support conversation: which
// config is actually in force, is the daemon alive, and can it reach the
// portal? Those three facts previously had to be reconstructed by hand from
// three different directories and a log file.
var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the active configuration, daemon state, and portal connectivity",
	RunE:  runStatus,
}

func init() {
	statusCmd.Flags().Bool("no-portal", false, "Skip the portal connectivity check")
	statusCmd.Flags().String("pid-file", "", "PID file path")
}

func runStatus(cmd *cobra.Command, args []string) error {
	skipPortal, _ := cmd.Flags().GetBool("no-portal")
	pidFile, _ := cmd.Flags().GetString("pid-file")
	if pidFile == "" {
		pidFile = platform.DefaultPIDFile()
	}

	colorCyan.Println("=== IDEViewer Status ===")
	fmt.Printf("Version:  %s\n", version.Version)
	fmt.Printf("Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Println()

	cfg := reportConfig()
	reportDaemon(pidFile)

	if cfg != nil && !skipPortal {
		reportPortal(cfg)
	}

	return nil
}

// reportConfig prints every candidate config path, marks the one Load will
// actually use, and flags the rest as shadowed. Returns the loaded config.
func reportConfig() *config.Config {
	colorCyan.Println("Configuration")

	candidates := config.Candidates()
	existing := config.ExistingPaths()
	active := ""
	if len(existing) > 0 {
		active = existing[0]
	}

	for _, p := range candidates {
		switch {
		case p == active:
			colorGreen.Printf("  [active] %s\n", p)
		case platform.PathExists(p):
			colorYellow.Printf("  [shadowed, ignored] %s\n", p)
		default:
			colorDim.Printf("  [absent] %s\n", p)
		}
	}

	if len(existing) > 1 {
		fmt.Println()
		colorYellow.Println("  More than one configuration is present. Only the first is used;")
		colorYellow.Println("  the others are leftovers from an earlier install. Clear them with:")
		colorCyan.Println("    ideviewer reset --config")
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Println()
		colorRed.Printf("  Not registered: %v\n", err)
		colorDim.Println("  Run: ideviewer register --customer-key KEY --portal-url URL")
		fmt.Println()
		return nil
	}

	fmt.Println()
	fmt.Printf("  Portal URL:    %s\n", cfg.PortalURL)
	fmt.Printf("  Customer key:  %s\n", maskSecret(cfg.CustomerKey))
	if cfg.HostToken != "" {
		fmt.Printf("  Host token:    %s\n", maskSecret(cfg.HostToken))
	} else {
		colorYellow.Println("  Host token:    none (the daemon will enrol on its next check-in)")
	}
	fmt.Printf("  Scan interval: %d minutes\n", cfg.ScanIntervalMinutes)
	mode := cfg.EnforcementMode
	if mode == "" {
		mode = "unset (resolved from enforcement_enabled)"
	}
	fmt.Printf("  Enforcement:   %s\n", mode)
	fmt.Printf("  Pinned keys:   %d\n", len(cfg.CommandPublicKeys))
	fmt.Println()

	return cfg
}

func reportDaemon(pidFile string) {
	colorCyan.Println("Daemon")
	fmt.Printf("  PID file: %s\n", pidFile)

	pid, err := daemon.ReadPIDFile(pidFile)
	switch {
	case err != nil && os.IsNotExist(err):
		colorYellow.Println("  Not running (no PID file)")
		colorDim.Println("  Start it with: ideviewer daemon --foreground")
	case err != nil:
		colorRed.Printf("  Unreadable PID file: %v\n", err)
	case daemon.IsRunning(pidFile):
		colorGreen.Printf("  Running (PID %d)\n", pid)
	default:
		colorYellow.Printf("  Not running (stale PID %d)\n", pid)
		colorDim.Println("  Clear it with: ideviewer stop")
	}

	logPath := filepath.Join(platform.LogDir(), "daemon.log")
	if runtime.GOOS == "darwin" {
		// The LaunchAgent redirects here; see register.go.
		logPath = "/tmp/ideviewer-daemon.log"
	}
	fmt.Printf("  Log file: %s\n", logPath)
	if info, err := os.Stat(logPath); err == nil {
		colorDim.Printf("  Last written: %s (%d bytes)\n",
			info.ModTime().Format("2006-01-02 15:04:05"), info.Size())
	} else {
		colorDim.Println("  Last written: never")
	}
	fmt.Println()
}

// reportPortal separates "unreachable" from "rejected", which a failed scan
// submission alone cannot distinguish.
func reportPortal(cfg *config.Config) {
	colorCyan.Println("Portal")

	client := api.NewClientWithToken(cfg.PortalURL, cfg.CustomerKey, cfg.HostToken)

	if _, err := client.Health(); err != nil {
		colorRed.Printf("  Unreachable: %v\n", err)
		colorDim.Printf("  Check that the portal is running and that %s is correct.\n", cfg.PortalURL)
		fmt.Println()
		return
	}
	colorGreen.Println("  Reachable")

	// Validate against the customer key specifically: the host token can be
	// revoked independently, and conflating the two hides which one is stale.
	keyClient := api.NewClient(cfg.PortalURL, cfg.CustomerKey)
	result, err := keyClient.ValidateKey()
	if err != nil {
		colorRed.Printf("  Customer key rejected: %v\n", err)
		fmt.Println()
		return
	}
	if valid, ok := result["valid"].(bool); !ok || !valid {
		colorRed.Printf("  Customer key invalid: %v\n", result["error"])
		fmt.Println()
		return
	}
	colorGreen.Printf("  Customer key valid: %v\n", result["key_name"])

	if pub, ok := result["command_public_key"].(string); !ok || pub == "" {
		colorYellow.Println("  Command signing: not configured on the portal")
		colorDim.Println("  Enrolment and scanning work; enforcement commands cannot be issued.")
	} else {
		colorGreen.Println("  Command signing: configured")
	}
	fmt.Println()
}

// maskSecret renders a credential as a recognisable but unusable fragment.
func maskSecret(s string) string {
	if s == "" {
		return "(none)"
	}
	if len(s) <= 12 {
		return strings.Repeat("*", len(s))
	}
	return s[:8] + "..." + s[len(s)-4:]
}
