package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/securient/ideviewer-oss/internal/config"
	"github.com/securient/ideviewer-oss/internal/platform"
	"github.com/securient/ideviewer-oss/pkg/api"
	"github.com/securient/ideviewer-oss/pkg/daemon"
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
	registerCmd.Flags().Bool("enable-enforcement", false, "Allow the daemon to quarantine extensions flagged by 'quarantine' policies (off by default)")
	_ = registerCmd.MarkFlagRequired("customer-key")
	_ = registerCmd.MarkFlagRequired("portal-url")
}

func runRegister(cmd *cobra.Command, args []string) error {
	customerKey, _ := cmd.Flags().GetString("customer-key")
	portalURL, _ := cmd.Flags().GetString("portal-url")
	interval, _ := cmd.Flags().GetInt("interval")
	enableEnforcement, _ := cmd.Flags().GetBool("enable-enforcement")

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
	if current, ok := result["current_hosts"]; ok {
		colorDim.Printf("  Hosts registered: %v\n", current)
	}

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

	// Capture per-host token if the portal issued one.
	var hostToken string
	if tokRaw, ok := regResult["host_token"]; ok {
		if tok, ok := tokRaw.(string); ok && tok != "" {
			hostToken = tok
			client.SetHostToken(hostToken)
			colorDim.Println("  Host token issued")
		}
	}

	// Capture the portal's command-signing public key so the daemon can verify
	// signed enforcement commands. Pinned at enrollment; refreshable later.
	var commandKeys []string
	if pub, ok := regResult["command_public_key"].(string); ok && pub != "" {
		commandKeys = []string{pub}
		colorDim.Println("  Command signing key pinned")
	}

	// Enforcement mode: --enable-enforcement opts into "verified" (act on
	// signed commands); otherwise leave unset so the daemon's default applies.
	enforcementMode := ""
	if enableEnforcement {
		enforcementMode = "verified"
	}

	// Step 3: Save configuration.
	fmt.Println()
	colorCyan.Println("Step 3: Saving configuration...")
	cfg := &config.Config{
		PortalURL:           portalURL,
		CustomerKey:         customerKey,
		HostToken:           hostToken,
		ScanIntervalMinutes: interval,
		EnforcementEnabled:  enableEnforcement,
		EnforcementMode:     enforcementMode,
		CommandPublicKeys:   commandKeys,
	}
	// Save to user-level config dir (daemon runs as user via LaunchAgent)
	if err := config.Save(cfg); err != nil {
		colorYellow.Printf("  Could not save user config: %v\n", err)
	} else {
		colorGreen.Printf("  Configuration saved to %s\n", config.UserPath())
		colorDim.Printf("  Check-in interval: %d minutes\n", interval)
	}

	// A leftover config at a higher-priority path wins at load time, so the
	// daemon would keep using the old key and portal URL and this registration
	// would appear to have done nothing. Windows is where this bites: the
	// uninstaller cleaned only %LOCALAPPDATA%, leaving ProgramData and
	// %USERPROFILE%\.ideviewer behind for the next install to inherit.
	if shadowing := config.ShadowedBy(config.UserPath()); len(shadowing) > 0 {
		fmt.Println()
		colorYellow.Println("  Warning: an older configuration takes priority over the one just written:")
		for _, p := range shadowing {
			colorYellow.Printf("    %s\n", p)
		}
		colorYellow.Println("  The daemon will keep using that file. Remove the stale configs with:")
		colorCyan.Println("    ideviewer reset --config")
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
		colorDim.Printf("Logs: %s\n", platform.DaemonLogFile())
	} else {
		fmt.Println("\nTo start the daemon manually:")
		colorCyan.Println("  ideviewer daemon --foreground")
	}

	return nil
}

// startDaemonService attempts to start the daemon as a system service.
func startDaemonService() bool {
	label := "com.ideviewer.daemon"

	// Retire any daemon already running before starting one with the config we
	// just wrote. Without this, re-registering left the previous process alive
	// holding the previous portal URL and key — two daemons, and the portal
	// hearing from the wrong one.
	stopExistingDaemon()

	switch runtime.GOOS {
	case "windows":
		if registerWindowsAutostart() {
			return true
		}
		colorYellow.Println("  Could not register the logon task — starting a background process instead")
		colorDim.Println("  The daemon will not restart automatically after a reboot.")

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
	logPath := platform.DaemonLogFile()
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		// Say so rather than discarding the daemon's output in silence, which
		// left operators with no log and no indication why.
		colorYellow.Printf("  Could not open %s for logging (%v) — the daemon will run without a log\n", logPath, err)
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

	// Read the pid before Release(): Release marks the handle as no longer
	// usable and sets Pid to -1, so reporting it afterwards printed
	// "(PID -1)" and looked like a failure on an otherwise healthy start.
	pid := proc.Process.Pid

	// Release the child so it continues running after we exit
	_ = proc.Process.Release()
	if logFile != nil {
		logFile.Close()
	}
	colorGreen.Printf("  Daemon started as background process (PID %d)\n", pid)
	if logFile != nil {
		colorDim.Printf("  Logging to %s\n", logPath)
	}
	return true
}

// stopExistingDaemon terminates a daemon left over from a previous
// registration or an earlier version, so the newly written config is the one
// actually in use.
func stopExistingDaemon() {
	pidFile := platform.DefaultPIDFile()
	if !daemon.IsRunning(pidFile) {
		daemon.RemovePIDFile(pidFile)
		return
	}
	pid, err := daemon.ReadPIDFile(pidFile)
	if err != nil {
		return
	}
	colorDim.Printf("  Stopping the existing daemon (PID %d)...\n", pid)
	if err := stopProcess(pid); err != nil {
		colorYellow.Printf("  Could not stop the running daemon (PID %d): %v\n", pid, err)
		return
	}
	for i := 0; i < 25; i++ {
		if !daemon.IsRunning(pidFile) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	daemon.RemovePIDFile(pidFile)
}

// registerWindowsAutostart installs a per-user Scheduled Task that starts the
// daemon at logon, then runs it now.
//
// Windows had no service registration at all: 'register' fell through to a
// detached background process, so the daemon vanished at the next reboot and
// the portal simply showed a host that had stopped checking in. A logon task
// is the lightest thing that survives a restart without requiring the daemon
// to be rewritten as a real Windows service, and it runs in the user's session
// where the IDE and extension directories actually live.
func registerWindowsAutostart() bool {
	if runtime.GOOS != "windows" {
		return false
	}
	binary, err := os.Executable()
	if err != nil {
		return false
	}

	const taskName = "IDEViewer Daemon"
	// /F replaces an existing task, which is what makes re-registering and
	// upgrading idempotent instead of failing on "task already exists".
	create := exec.Command("schtasks", "/Create", "/F",
		"/TN", taskName,
		"/SC", "ONLOGON",
		"/RL", "LIMITED",
		"/TR", fmt.Sprintf(`"%s" daemon`, binary),
	)
	if out, err := create.CombinedOutput(); err != nil {
		colorDim.Printf("  schtasks /Create failed: %v: %s\n", err, strings.TrimSpace(string(out)))
		return false
	}

	if out, err := exec.Command("schtasks", "/Run", "/TN", taskName).CombinedOutput(); err != nil {
		colorDim.Printf("  schtasks /Run failed: %v: %s\n", err, strings.TrimSpace(string(out)))
		return false
	}

	colorGreen.Println("  Daemon registered as a logon task and started")
	colorDim.Printf("  Manage it with: schtasks /Query /TN %q\n", taskName)
	return true
}
