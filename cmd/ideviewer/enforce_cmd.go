package main

import (
	"fmt"
	"strings"

	"github.com/securient/ideviewer-oss/internal/config"
	"github.com/spf13/cobra"
)

var enforceCmd = &cobra.Command{
	Use:   "enforce",
	Short: "Control whether this daemon acts on signed enforcement commands",
	Long: `Controls whether this daemon quarantines extensions flagged by
'quarantine' policies.

Enforcement runs in one of two modes:
  verified  the daemon executes a command ONLY if its ed25519 signature
            verifies against the portal's pinned key (the default)
  off       the daemon never polls or executes enforcement commands

Because commands are signed, "verified" is safe as the default: a missing or
forged signature always blocks execution.

  ideviewer enforce               # show current state
  ideviewer enforce --enable      # set mode to "verified"
  ideviewer enforce --disable     # set mode to "off"
  ideviewer enforce --mode off    # set mode explicitly

The setting is written to the (HMAC-signed) daemon config. Restart the
daemon for the change to take effect.`,
	RunE: runEnforce,
}

func init() {
	enforceCmd.Flags().Bool("enable", false, "Enable enforcement (alias for --mode verified)")
	enforceCmd.Flags().Bool("disable", false, "Disable enforcement (alias for --mode off)")
	enforceCmd.Flags().String("mode", "", `Set enforcement mode explicitly: "verified" or "off"`)
}

// effectiveMode mirrors the daemon's resolveEnforcementMode for display.
func effectiveMode(cfg *config.Config) string {
	switch strings.ToLower(strings.TrimSpace(cfg.EnforcementMode)) {
	case "off":
		return "off"
	case "verified":
		return "verified"
	}
	return "verified" // unset defaults to verified
}

func runEnforce(cmd *cobra.Command, args []string) error {
	enable, _ := cmd.Flags().GetBool("enable")
	disable, _ := cmd.Flags().GetBool("disable")
	modeFlag, _ := cmd.Flags().GetString("mode")
	modeFlag = strings.ToLower(strings.TrimSpace(modeFlag))

	// Resolve the requested mode from the (mutually exclusive) flags.
	chosen := ""
	switch {
	case enable && disable:
		return fmt.Errorf("--enable and --disable are mutually exclusive")
	case modeFlag != "" && (enable || disable):
		return fmt.Errorf("--mode cannot be combined with --enable/--disable")
	case enable:
		chosen = "verified"
	case disable:
		chosen = "off"
	case modeFlag != "":
		if modeFlag != "verified" && modeFlag != "off" {
			return fmt.Errorf("invalid --mode %q (want \"verified\" or \"off\")", modeFlag)
		}
		chosen = modeFlag
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("could not load config (is this host registered?): %w", err)
	}

	// No change requested: report current state.
	if chosen == "" {
		if effectiveMode(cfg) == "off" {
			colorYellow.Println("Enforcement is OFF")
		} else {
			colorGreen.Println("Enforcement is VERIFIED (acts on signed commands)")
			if len(cfg.CommandPublicKeys) == 0 {
				colorYellow.Println("  No command signing key is pinned yet — the daemon will " +
					"fetch one from the portal on its next enforcement check.")
			}
		}
		colorDim.Printf("Config: %s\n", config.Path())
		return nil
	}

	cfg.EnforcementMode = chosen
	// Keep the legacy boolean roughly consistent for any old reader.
	cfg.EnforcementEnabled = chosen == "verified"
	if err := config.SaveToPath(cfg, config.Path()); err != nil {
		return fmt.Errorf("could not save config (try sudo if the daemon runs as root): %w", err)
	}

	if chosen == "verified" {
		colorGreen.Println("Enforcement set to VERIFIED — the daemon will act on signed quarantine commands.")
	} else {
		colorYellow.Println("Enforcement set to OFF — the daemon will not quarantine.")
	}
	colorDim.Println("Restart the daemon for this to take effect (e.g. `ideviewer stop`; launchd/systemd will relaunch it).")
	return nil
}
