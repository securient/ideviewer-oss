package main

import (
	"fmt"
	"log"
	"os"

	"github.com/securient/ideviewer-oss/internal/config"
	"github.com/securient/ideviewer-oss/internal/platform"
	"github.com/securient/ideviewer-oss/pkg/api"
	"github.com/securient/ideviewer-oss/pkg/daemon"
	"github.com/securient/ideviewer-oss/pkg/scanner"
	"github.com/spf13/cobra"
)

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Start the daemon for continuous monitoring",
	Long: `Start the daemon to check in with the portal at the specified interval
and report IDE/extension information.

Examples:
  # Run with 30-minute check-in interval
  ideviewer daemon --interval 30 --foreground

  # Use saved configuration
  ideviewer daemon --foreground`,
	RunE: runDaemon,
}

func init() {
	daemonCmd.Flags().StringP("customer-key", "k", "", "Customer key (UUID) for portal authentication")
	daemonCmd.Flags().StringP("portal-url", "p", "", "Portal URL (e.g., http://portal.example.com)")
	daemonCmd.Flags().IntP("interval", "i", 0, "Check-in/scan interval in minutes (default: 60)")
	daemonCmd.Flags().StringP("output", "o", "", "Output file for results")
	daemonCmd.Flags().String("log-file", "", "Log file path")
	daemonCmd.Flags().String("pid-file", "", "PID file path")
	daemonCmd.Flags().BoolP("foreground", "f", false, "Run in foreground (don't daemonize)")
}

func runDaemon(cmd *cobra.Command, args []string) error {
	customerKey, _ := cmd.Flags().GetString("customer-key")
	portalURL, _ := cmd.Flags().GetString("portal-url")
	interval, _ := cmd.Flags().GetInt("interval")
	logFile, _ := cmd.Flags().GetString("log-file")
	pidFile, _ := cmd.Flags().GetString("pid-file")
	foreground, _ := cmd.Flags().GetBool("foreground")

	if pidFile == "" {
		pidFile = platform.DefaultPIDFile()
	}

	// Setup logging.
	setupDaemonLogging(logFile, !foreground)

	var cfg *config.Config

	if customerKey != "" && portalURL != "" {
		// New configuration provided via flags.
		fmt.Println("Validating customer key...")
		client := api.NewClient(portalURL, customerKey)
		result, err := client.ValidateKey()
		if err != nil {
			return fmt.Errorf("failed to validate key: %w", err)
		}
		if valid, ok := result["valid"].(bool); !ok || !valid {
			return fmt.Errorf("invalid customer key")
		}
		colorGreen.Printf("Key validated: %v\n", result["key_name"])

		saveInterval := interval
		if saveInterval <= 0 {
			saveInterval = 60
		}

		cfg = &config.Config{
			PortalURL:           portalURL,
			CustomerKey:         customerKey,
			ScanIntervalMinutes: saveInterval,
		}
		if err := config.Save(cfg); err != nil {
			colorYellow.Printf("Warning: could not save config: %v\n", err)
		}
	} else if customerKey != "" || portalURL != "" {
		return fmt.Errorf("both --customer-key and --portal-url are required together")
	} else {
		// Load saved config.
		var err error
		cfg, err = config.Load()
		if err != nil {
			return fmt.Errorf("no configuration: %w\nRun 'ideviewer register' first", err)
		}
		colorDim.Printf("Using saved configuration (check-in interval: %d min)\n", cfg.ScanIntervalMinutes)
	}

	if interval > 0 {
		cfg.ScanIntervalMinutes = interval
	}
	if cfg.ScanIntervalMinutes <= 0 {
		cfg.ScanIntervalMinutes = 60
	}

	// Create PID file.
	if err := daemon.CreatePIDFile(pidFile); err != nil {
		return fmt.Errorf("daemon already running: %w", err)
	}
	defer daemon.RemovePIDFile(pidFile)

	// Build scanner with all detectors.
	ideScanner := scanner.New(allDetectors()...)

	d, err := daemon.New(cfg, ideScanner)
	if err != nil {
		return fmt.Errorf("failed to create daemon: %w", err)
	}

	if foreground {
		colorGreen.Printf("Daemon running (check-in interval: %d minutes)\n", cfg.ScanIntervalMinutes)
		colorDim.Printf("Reporting to: %s\n", cfg.PortalURL)
		colorDim.Println("Press Ctrl+C to stop")
	} else {
		colorCyan.Println("Starting daemon in background...")
	}

	return d.Start(false)
}

func setupDaemonLogging(logFile string, daemonMode bool) {
	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			log.SetOutput(f)
		}
		return
	}

	if daemonMode {
		logDir := platform.LogDir()
		_ = os.MkdirAll(logDir, 0755)
		logPath := logDir + "/daemon.log"
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			log.SetOutput(f)
		}
	}
}
