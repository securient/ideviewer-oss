package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/securient/ideviewer-oss/pkg/behavior"
	"github.com/spf13/cobra"
)

var behaviorScanCmd = &cobra.Command{
	Use:   "behavior-scan",
	Short: "EXPERIMENTAL: flag suspicious processes spawned under an IDE/extension host",
	Long: `Single-OS spike of runtime/behavioral telemetry (B6). Enumerates the
process tree and flags any process that runs a known-suspicious command
(reverse shell, pipe-to-shell, raw socket one-liner) AND descends from an IDE
or extension-host process — i.e. an extension spawning a shell home.

This is a userspace proof of concept, NOT the full kernel-grade collector
(macOS ESF / Windows ETW / Linux eBPF), which is the documented follow-up.`,
	RunE: runBehaviorScan,
}

func init() {
	behaviorScanCmd.Flags().Bool("json", false, "Emit findings as JSON")
}

func runBehaviorScan(cmd *cobra.Command, args []string) error {
	asJSON, _ := cmd.Flags().GetBool("json")

	procs, err := behavior.EnumerateProcesses()
	if err != nil {
		return fmt.Errorf("could not enumerate processes: %w", err)
	}
	if procs == nil {
		colorYellow.Println("behavior-scan is only supported on macOS and Linux.")
		return nil
	}
	findings := behavior.DetectSuspicious(procs)

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(findings)
	}

	if len(findings) == 0 {
		colorGreen.Printf("  No suspicious IDE-spawned processes (scanned %d processes).\n", len(procs))
		return nil
	}
	colorRed.Printf("  %d suspicious process(es) detected:\n", len(findings))
	for _, f := range findings {
		colorRed.Printf("    • pid %d (%s): %s\n", f.PID, f.Comm, f.Reason)
		colorYellow.Printf("      under %s (pid %d): %s\n", f.AncestorComm, f.AncestorPID, f.Args)
	}
	return nil
}
