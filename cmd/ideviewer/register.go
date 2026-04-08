package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/securient/ideviewer-oss/internal/config"
	"github.com/securient/ideviewer-oss/internal/platform"
	"github.com/securient/ideviewer-oss/pkg/api"
	"github.com/securient/ideviewer-oss/pkg/gitleaks"
	"github.com/securient/ideviewer-oss/pkg/hooks"
	"github.com/securient/ideviewer-oss/pkg/scanner"
	"github.com/spf13/cobra"
)

var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Register this machine with the portal and validate the customer key",
	RunE:  runRegister,
}

func init() {
	registerCmd.Flags().StringP("customer-key", "k", "", "Customer key (UUID)")
	registerCmd.Flags().StringP("portal-url", "p", "", "Portal URL")
	registerCmd.Flags().IntP("interval", "i", 30, "Full scan interval in minutes (default: 30, real-time monitoring runs independently)")
	_ = registerCmd.MarkFlagRequired("customer-key")
	_ = registerCmd.MarkFlagRequired("portal-url")
}

func runRegister(cmd *cobra.Command, args []string) error {
	customerKey, _ := cmd.Flags().GetString("customer-key")
	portalURL, _ := cmd.Flags().GetString("portal-url")
	interval, _ := cmd.Flags().GetInt("interval")

	fmt.Println("=== IDE Viewer Registration ===")
	fmt.Printf("Portal:   %s\n", portalURL)
	if len(customerKey) > 12 {
		fmt.Printf("Key:      %s...%s\n", customerKey[:8], customerKey[len(customerKey)-4:])
	} else {
		fmt.Printf("Key:      %s\n", customerKey)
	}
	fmt.Printf("Interval: %d minutes\n\n", interval)

	client := api.NewClient(portalURL, customerKey)

	// Step 1: Validate key.
	colorCyan.Println("Step 1: Validating customer key...")
	result, err := client.ValidateKey()
	if err != nil {
		colorRed.Printf("  Validation failed: %v\n", err)
		return fmt.Errorf("key validation failed")
	}
	if valid, ok := result["valid"].(bool); !ok || !valid {
		colorRed.Printf("  Invalid key: %v\n", result["error"])
		return fmt.Errorf("invalid customer key")
	}
	colorGreen.Printf("  Key is valid: %v\n", result["key_name"])
	colorDim.Printf("  Hosts: %v/%v\n", result["current_hosts"], result["max_hosts"])

	// Step 2: Register host.
	fmt.Println()
	colorCyan.Println("Step 2: Registering this machine...")
	regResult, err := client.RegisterHost()
	if err != nil {
		colorRed.Printf("  Registration failed: %v\n", err)
		return fmt.Errorf("host registration failed")
	}
	if msg, ok := regResult["message"].(string); ok {
		colorGreen.Printf("  %s\n", msg)
	} else {
		colorGreen.Println("  Host registered")
	}

	// Step 3: Save configuration.
	fmt.Println()
	colorCyan.Println("Step 3: Saving configuration...")
	cfg := &config.Config{
		PortalURL:           portalURL,
		CustomerKey:         customerKey,
		ScanIntervalMinutes: interval,
	}
	// Save to user-level config dir (daemon runs as user via LaunchAgent)
	if err := config.Save(cfg); err != nil {
		colorYellow.Printf("  Could not save user config: %v\n", err)
	} else {
		colorGreen.Printf("  Configuration saved to %s\n", config.Path())
		colorDim.Printf("  Check-in interval: %d minutes\n", interval)
	}

	// Step 4: Run initial scan.
	fmt.Println()
	colorCyan.Println("Step 4: Running initial scan...")
	ideScanner := scanner.New(allDetectors()...)
	scanResult, err := ideScanner.Scan()
	if err != nil {
		colorYellow.Printf("  Initial scan failed: %v\n", err)
	} else {
		resp, err := client.SubmitReport(toMap(scanResult))
		if err != nil {
			colorYellow.Printf("  Scan completed but failed to submit: %v\n", err)
		} else {
			stats, _ := resp["stats"].(map[string]any)
			colorGreen.Println("  Scan submitted successfully")
			if stats != nil {
				colorDim.Printf("  IDEs: %v, Extensions: %v, Dangerous: %v\n",
					stats["total_ides"], stats["total_extensions"], stats["dangerous_extensions"])
			}
		}
	}

	// Step 5: Install gitleaks + hooks.
	fmt.Println()
	colorCyan.Println("Step 5: Installing pre-commit hooks...")
	if err := gitleaks.Install(); err != nil {
		colorYellow.Printf("  Could not install gitleaks; built-in scanner will be used: %v\n", err)
	} else {
		if v, err := gitleaks.GetVersion(); err == nil {
			colorGreen.Printf("  gitleaks installed (version: %s)\n", v)
		}
	}

	if err := hooks.Install(); err != nil {
		colorYellow.Printf("  Could not install global hooks: %v\n", err)
	} else {
		colorGreen.Println("  Global pre-commit hooks installed")
	}

	// Step 6: Start daemon.
	fmt.Println()
	colorCyan.Println("Step 6: Starting daemon...")
	daemonStarted := startDaemonService()

	fmt.Println()
	fmt.Println("==================================================")
	colorGreen.Println("Registration complete!")
	if daemonStarted {
		fmt.Println("\nDaemon is running in the background.")
		if runtime.GOOS == "darwin" {
			colorDim.Println("Logs: /tmp/ideviewer-daemon.log")
		} else {
			colorDim.Printf("Logs: %s/daemon.log\n", platform.LogDir())
		}
	} else {
		fmt.Println("\nTo start the daemon manually:")
		colorCyan.Println("  ideviewer daemon --foreground")
	}

	return nil
}

// startDaemonService attempts to start the daemon as a system service.
func startDaemonService() bool {
	label := "com.ideviewer.daemon"

	switch runtime.GOOS {
	case "darwin":
		// Try LaunchAgent first (user-level, has access to ~/), then LaunchDaemon
		agentPlist := "/Library/LaunchAgents/com.ideviewer.daemon.plist"
		daemonPlist := platform.ServiceFilePath() // /Library/LaunchDaemons/...
		plist := ""
		if _, err := os.Stat(agentPlist); err == nil {
			plist = agentPlist
		} else if _, err := os.Stat(daemonPlist); err == nil {
			plist = daemonPlist
		}
		if plist != "" {
			uid := fmt.Sprintf("%d", os.Getuid())
			// Stop any existing instance
			_ = exec.Command("launchctl", "bootout", "gui/"+uid+"/"+label).Run()
			_ = exec.Command("launchctl", "bootout", "system/"+label).Run()
			// Try user domain first (LaunchAgent — runs as current user)
			if err := exec.Command("launchctl", "bootstrap", "gui/"+uid, plist).Run(); err == nil {
				colorGreen.Println("  Daemon started via launchd (user agent)")
				return true
			}
			// Fallback to system domain
			if err := exec.Command("launchctl", "bootstrap", "system", plist).Run(); err == nil {
				colorGreen.Println("  Daemon started via launchd (system)")
				return true
			}
			// Legacy fallback
			_ = exec.Command("launchctl", "load", plist).Run()
			if err := exec.Command("launchctl", "start", label).Run(); err == nil {
				colorGreen.Println("  Daemon started via launchd (legacy)")
				return true
			}
			colorYellow.Println("  Could not start via launchd — trying background process")
		}
	case "linux":
		svc := platform.ServiceFilePath()
		if _, err := os.Stat(svc); err == nil {
			_ = exec.Command("systemctl", "daemon-reload").Run()
			_ = exec.Command("systemctl", "enable", "ideviewer").Run()
			if err := exec.Command("systemctl", "start", "ideviewer").Run(); err == nil {
				colorGreen.Println("  Daemon started via systemd")
				return true
			}
			colorYellow.Println("  Could not start via systemd — trying background process")
		}
	}

	// Fallback: start as a properly detached background process.
	binary, err := os.Executable()
	if err != nil {
		binary = "ideviewer"
	}
	logDir := platform.LogDir()
	_ = os.MkdirAll(logDir, 0755)

	logFile, err := os.OpenFile(filepath.Join(logDir, "daemon.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		logFile = nil
	}

	proc := exec.Command(binary, "daemon", "--foreground")
	proc.Stdout = logFile
	proc.Stderr = logFile
	proc.Stdin = nil
	// Detach from parent process group so daemon survives after register exits
	setSysProcAttr(proc)
	if err := proc.Start(); err != nil {
		colorYellow.Printf("  Could not start daemon: %v\n", err)
		if logFile != nil {
			logFile.Close()
		}
		return false
	}
	// Release the child so it continues running after we exit
	_ = proc.Process.Release()
	if logFile != nil {
		logFile.Close()
	}
	colorGreen.Printf("  Daemon started as background process (PID %d)\n", proc.Process.Pid)
	return true
}

