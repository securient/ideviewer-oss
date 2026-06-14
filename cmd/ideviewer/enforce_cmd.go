package main

import (
	"fmt"

	"github.com/securient/ideviewer-oss/internal/config"
	"github.com/spf13/cobra"
)

var enforceCmd = &cobra.Command{
	Use:   "enforce",
	Short: "Enable or disable the local enforcement kill-switch",
	Long: `Controls whether this daemon may quarantine extensions flagged by
'quarantine' policies. Enforcement is OFF by default.

  ideviewer enforce            # show current state
  ideviewer enforce --enable   # allow the daemon to quarantine
  ideviewer enforce --disable  # stop the daemon from quarantining

The setting is written to the (HMAC-signed) daemon config. Restart the
daemon for the change to take effect.`,
	RunE: runEnforce,
}

func init() {
	enforceCmd.Flags().Bool("enable", false, "Enable enforcement (allow quarantine)")
	enforceCmd.Flags().Bool("disable", false, "Disable enforcement")
}

func runEnforce(cmd *cobra.Command, args []string) error {
	enable, _ := cmd.Flags().GetBool("enable")
	disable, _ := cmd.Flags().GetBool("disable")
	if enable && disable {
		return fmt.Errorf("--enable and --disable are mutually exclusive")
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("could not load config (is this host registered?): %w", err)
	}

	// No flag: report current state.
	if !enable && !disable {
		if cfg.EnforcementEnabled {
			colorGreen.Println("Enforcement is ENABLED")
		} else {
			colorYellow.Println("Enforcement is DISABLED")
		}
		colorDim.Printf("Config: %s\n", config.Path())
		return nil
	}

	cfg.EnforcementEnabled = enable // true for --enable, false for --disable
	if err := config.SaveToPath(cfg, config.Path()); err != nil {
		return fmt.Errorf("could not save config (try sudo if the daemon runs as root): %w", err)
	}

	if enable {
		colorGreen.Println("Enforcement ENABLED — the daemon may now quarantine flagged extensions.")
	} else {
		colorYellow.Println("Enforcement DISABLED — the daemon will no longer quarantine.")
	}
	colorDim.Println("Restart the daemon for this to take effect (e.g. `ideviewer stop`; launchd/systemd will relaunch it).")
	return nil
}
