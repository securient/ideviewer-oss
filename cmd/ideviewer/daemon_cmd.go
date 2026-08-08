package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

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
	daemonCmd.Flags().Bool("wait-for-config", true, "When no configuration exists, wait for 'ideviewer register' instead of exiting")
}

// configPollInterval is how often an unregistered daemon re-checks for a
// configuration written by 'ideviewer register'.
const configPollInterval = 30 * time.Second

// waitForConfig blocks until a configuration becomes readable, returning nil if
// interrupted first.
//
// Exiting when unregistered is not survivable under launchd: the LaunchAgent
// sets KeepAlive with no ThrottleInterval, so the default 10-second floor
// respawns the daemon ~8,600 times a day, each appending to an unrotated log in
// /tmp (~70 MB/day). And that is not an error state — it is simply the normal
// gap between installing the package and running 'ideviewer register'. Parking
// in a single healthy process keeps launchd quiet and still picks the config up
// promptly, while leaving genuine crashes to restart on the usual 10s floor.
func waitForConfig(pollInterval time.Duration, load func() (*config.Config, error)) *config.Config {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case s := <-sigCh:
			// launchctl bootout sends SIGTERM and SIGKILLs shortly after, so
			// return rather than block and let the caller's defers run.
			log.Printf("Received %s while waiting for configuration.", s)
			return nil
		case <-ticker.C:
			if cfg, err := load(); err == nil {
				return cfg
			}
		}
	}
}

func runDaemon(cmd *cobra.Command, args []string) error {
	customerKey, _ := cmd.Flags().GetString("customer-key")
	portalURL, _ := cmd.Flags().GetString("portal-url")
	interval, _ := cmd.Flags().GetInt("interval")
	logFile, _ := cmd.Flags().GetString("log-file")
	pidFile, _ := cmd.Flags().GetString("pid-file")
	foreground, _ := cmd.Flags().GetBool("foreground")
	waitForCfg, _ := cmd.Flags().GetBool("wait-for-config")

	if pidFile == "" {
		pidFile = platform.DefaultPIDFile()
	}

	// Setup logging.
	setupDaemonLogging(logFile, !foreground)

	// Create the PID file before resolving configuration so that a daemon
	// parked waiting for registration is still visible to 'ideviewer stop',
	// and so two instances cannot sit waiting at once.
	if err := daemon.CreatePIDFile(pidFile); err != nil {
		return fmt.Errorf("daemon already running: %w", err)
	}
	defer daemon.RemovePIDFile(pidFile)

	var cfg *config.Config

	if customerKey != "" && portalURL != "" {
		// New configuration provided via flags.
		fmt.Println("Validating customer key...")
		client := api.NewClientWithToken(portalURL, customerKey, "")
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
			if !waitForCfg {
				return fmt.Errorf("no configuration: %w\nRun 'ideviewer register' first", err)
			}
			log.Printf("No configuration found: %v", err)
			log.Printf("Waiting for registration (re-checking every %s). "+
				"Run: ideviewer register --customer-key KEY --portal-url URL", configPollInterval)
			colorYellow.Println("No configuration — waiting for 'ideviewer register' (Ctrl+C to exit)")

			cfg = waitForConfig(configPollInterval, config.Load)
			if cfg == nil {
				log.Println("Interrupted before registration completed; exiting.")
				return nil
			}
			log.Println("Configuration detected; starting daemon.")
		}
		colorDim.Printf("Using saved configuration (check-in interval: %d min)\n", cfg.ScanIntervalMinutes)
	}

	if interval > 0 {
		cfg.ScanIntervalMinutes = interval
	}
	if cfg.ScanIntervalMinutes <= 0 {
		cfg.ScanIntervalMinutes = 60
	}

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
