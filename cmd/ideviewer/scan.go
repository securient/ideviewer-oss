package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/securient/ideviewer-oss/internal/version"
	"github.com/securient/ideviewer-oss/pkg/detectors"
	"github.com/securient/ideviewer-oss/pkg/scanner"
	"github.com/securient/ideviewer-oss/pkg/sarif"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan for installed IDEs and their extensions",
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().Bool("json", false, "Output as JSON")
	scanCmd.Flags().Bool("output-sarif", false, "Output in SARIF v2.1.0 format")
	scanCmd.Flags().StringP("output", "o", "", "Output file path")
	scanCmd.Flags().StringSliceP("ide", "i", nil, "Filter by IDE type (can be used multiple times)")
	scanCmd.Flags().Bool("portal", false, "Send results to the portal")
}

func runScan(cmd *cobra.Command, args []string) error {
	outputJSON, _ := cmd.Flags().GetBool("json")
	outputSARIF, _ := cmd.Flags().GetBool("output-sarif")
	outputPath, _ := cmd.Flags().GetString("output")
	portal, _ := cmd.Flags().GetBool("portal")

	fmt.Println("Scanning for IDEs...")

	s := scanner.New(allDetectors()...)
	result, err := s.Scan()
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Portal mode: also run secrets + deps scans.
	if portal {
		sendScanToPortal(result, true, true)
	}

	if outputSARIF {
		sarifData := sarif.FormatScanResult(result, version.Version)
		return writeSARIF(sarifData, outputPath)
	}

	if outputJSON || outputPath != "" {
		return writeJSON(result, outputPath)
	}

	displayScanResult(result)
	return nil
}

func displayScanResult(result *scanner.ScanResult) {
	fmt.Println()
	fmt.Printf("Platform: %s\n", result.Platform)
	fmt.Printf("Timestamp: %s\n", result.Timestamp)
	fmt.Println()

	if len(result.IDEs) == 0 {
		colorYellow.Println("No IDEs detected.")
		return
	}

	for _, ide := range result.IDEs {
		status := "o"
		if ide.IsRunning {
			status = "*"
		}
		versionStr := ""
		if ide.Version != "" {
			versionStr = " v" + ide.Version
		}
		colorCyan.Printf("[%s] %s%s (%d extensions)\n", status, ide.Name, versionStr, ide.ExtensionCount)

		if ide.InstallPath != "" {
			colorDim.Printf("    Install: %s\n", ide.InstallPath)
		}
		if ide.ExtensionsPath != "" {
			colorDim.Printf("    Extensions: %s\n", ide.ExtensionsPath)
		}

		if len(ide.Extensions) > 0 {
			for _, ext := range ide.Extensions {
				publisher := ""
				if ext.Publisher != "" {
					publisher = " by " + ext.Publisher
				}
				fmt.Printf("    - %s v%s%s\n", ext.Name, ext.Version, publisher)

				var dangerousPerms []string
				for _, p := range ext.Permissions {
					if p.IsDangerous {
						dangerousPerms = append(dangerousPerms, p.Name)
					}
				}
				if len(dangerousPerms) > 0 {
					colorRed.Printf("      ! Dangerous: %s\n", strings.Join(dangerousPerms, ", "))
				}
			}
		}
		fmt.Println()
	}

	if len(result.Errors) > 0 {
		colorRed.Println("Errors during scan:")
		for _, e := range result.Errors {
			colorRed.Printf("  - %s\n", e)
		}
	}
}

func allDetectors() []scanner.Detector {
	return []scanner.Detector{
		&detectors.VSCodeDetector{},
		&detectors.JetBrainsDetector{},
		&detectors.SublimeTextDetector{},
		&detectors.VimDetector{},
		&detectors.XcodeDetector{},
	}
}

func writeJSON(v any, path string) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}

	if path != "" {
		if err := os.WriteFile(path, data, 0644); err != nil {
			return fmt.Errorf("write file: %w", err)
		}
		colorGreen.Printf("Results written to %s\n", path)
		return nil
	}

	fmt.Println(string(data))
	return nil
}

func writeSARIF(sarifData map[string]any, path string) error {
	data, err := sarif.ToJSON(sarifData)
	if err != nil {
		return fmt.Errorf("marshal SARIF: %w", err)
	}

	if path != "" {
		if err := os.WriteFile(path, data, 0644); err != nil {
			return fmt.Errorf("write file: %w", err)
		}
		colorGreen.Printf("SARIF results written to %s\n", path)
		return nil
	}

	fmt.Println(string(data))
	return nil
}
