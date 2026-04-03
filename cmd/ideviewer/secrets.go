package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/securient/ideviewer-oss/internal/version"
	"github.com/securient/ideviewer-oss/pkg/sarif"
	"github.com/securient/ideviewer-oss/pkg/secrets"
	"github.com/spf13/cobra"
)

var secretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Scan for plaintext secrets in configuration files",
	Long: `Scan .env files and similar configuration files for exposed secrets
like Ethereum private keys, mnemonics, and API credentials.

IMPORTANT: This scanner does NOT extract or display actual secret values.
It only reports the presence and location of potential secrets.`,
	RunE: runSecrets,
}

func init() {
	secretsCmd.Flags().Bool("json", false, "Output as JSON")
	secretsCmd.Flags().Bool("output-sarif", false, "Output in SARIF v2.1.0 format")
	secretsCmd.Flags().Bool("portal", false, "Send results to the portal")
	secretsCmd.Flags().Bool("check-staged", false, "Only scan files currently staged in git")
	secretsCmd.Flags().Bool("exit-code", false, "Exit with code 1 if secrets found (for hooks)")
}

func runSecrets(cmd *cobra.Command, args []string) error {
	outputJSON, _ := cmd.Flags().GetBool("json")
	outputSARIF, _ := cmd.Flags().GetBool("output-sarif")
	portal, _ := cmd.Flags().GetBool("portal")
	checkStaged, _ := cmd.Flags().GetBool("check-staged")
	exitCode, _ := cmd.Flags().GetBool("exit-code")

	sc := secrets.NewScanner()

	var result *secrets.SecretsResult
	var err error

	if checkStaged {
		result, err = sc.ScanStaged()
		if err != nil {
			return fmt.Errorf("staged secrets scan failed: %w", err)
		}
		if len(result.Findings) > 0 {
			colorRed.Printf("Found %d secret(s) in staged files:\n", len(result.Findings))
			for _, f := range result.Findings {
				c := severityColor(f.Severity)
				c.Printf("  %s ", strings.ToUpper(f.Severity))
				fmt.Printf("%s (%s) in %s:%d\n",
					strings.ReplaceAll(f.SecretType, "_", " "),
					f.VariableName, f.FilePath, f.LineNumber)
			}
			if exitCode {
				os.Exit(1)
			}
		}
		return nil
	}

	fmt.Println("Scanning for plaintext secrets...")
	result, err = sc.Scan()
	if err != nil {
		return fmt.Errorf("secrets scan failed: %w", err)
	}

	// Portal mode.
	if portal {
		sendSecretsToPortal(result)
	}

	if outputSARIF {
		sarifData := sarif.FormatSecretsResult(result, version.Version)
		data, err := sarif.ToJSON(sarifData)
		if err != nil {
			return fmt.Errorf("marshal SARIF: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	if outputJSON {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}

	// Table display.
	if len(result.Findings) > 0 {
		fmt.Println()
		colorRed.Printf("Found %d plaintext secret(s)!\n\n", len(result.Findings))

		var rows [][]string
		for _, f := range result.Findings {
			lineStr := "-"
			if f.LineNumber > 0 {
				lineStr = fmt.Sprintf("%d", f.LineNumber)
			}
			varName := f.VariableName
			if varName == "" {
				varName = "N/A"
			}
			rows = append(rows, []string{
				strings.ReplaceAll(f.SecretType, "_", " "),
				varName,
				f.FilePath,
				lineStr,
				strings.ToUpper(f.Severity),
			})
		}
		printTable([]string{"Type", "Variable", "File", "Line", "Severity"}, rows)

		// Recommendations.
		fmt.Println()
		fmt.Println("Recommendations:")
		seen := make(map[string]bool)
		for _, f := range result.Findings {
			if !seen[f.SecretType] {
				seen[f.SecretType] = true
				fmt.Printf("  - %s\n", f.Recommendation)
			}
		}
	} else {
		colorGreen.Println("No plaintext secrets detected.")
	}

	fmt.Println()
	colorDim.Printf("Scanned %d files\n", len(result.ScannedPaths))

	if exitCode && len(result.Findings) > 0 {
		os.Exit(1)
	}

	return nil
}
