package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/securient/ideviewer-oss/internal/version"
	"github.com/spf13/cobra"
)

var (
	verbose bool

	// Color printers used across commands.
	colorRed    = color.New(color.FgRed, color.Bold)
	colorYellow = color.New(color.FgYellow)
	colorGreen  = color.New(color.FgGreen)
	colorCyan   = color.New(color.FgCyan)
	colorDim    = color.New(color.Faint)
)

var rootCmd = &cobra.Command{
	Use:   "ideviewer",
	Short: "IDE Viewer - Cross-platform IDE and Extension Scanner",
	Long: "IDE Viewer scans for installed IDEs, extensions, secrets, and dependencies.\n" +
		"Designed for IT security teams to monitor developer environments.",
	SilenceUsage: true,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("ideviewer %s\n", version.Version)
	},
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(statsCmd)
	rootCmd.AddCommand(dangerousCmd)
	rootCmd.AddCommand(secretsCmd)
	rootCmd.AddCommand(packagesCmd)
	rootCmd.AddCommand(daemonCmd)
	rootCmd.AddCommand(registerCmd)
	rootCmd.AddCommand(stopCmd)
	rootCmd.AddCommand(hooksCmd)
	rootCmd.AddCommand(updateCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// severityColor returns the appropriate color function for a risk/severity level.
func severityColor(severity string) *color.Color {
	switch strings.ToLower(severity) {
	case "critical":
		return color.New(color.FgRed, color.Bold)
	case "high":
		return color.New(color.FgYellow, color.Bold)
	case "medium":
		return color.New(color.FgYellow)
	case "low":
		return color.New(color.FgGreen)
	default:
		return color.New(color.Reset)
	}
}

// printTable prints rows in an aligned table with the given headers.
// Each row should have the same number of columns as headers.
func printTable(headers []string, rows [][]string) {
	if len(rows) == 0 {
		return
	}

	// Compute column widths.
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	// Build format string.
	fmtParts := make([]string, len(widths))
	for i, w := range widths {
		fmtParts[i] = fmt.Sprintf("%%-%ds", w+2)
	}
	fmtStr := strings.Join(fmtParts, "")

	// Print header.
	headerIfaces := make([]any, len(headers))
	for i, h := range headers {
		headerIfaces[i] = h
	}
	color.New(color.Bold).Printf(fmtStr+"\n", headerIfaces...)

	// Separator.
	sepParts := make([]any, len(widths))
	for i, w := range widths {
		sepParts[i] = strings.Repeat("-", w+1)
	}
	fmt.Printf(fmtStr+"\n", sepParts...)

	// Rows.
	for _, row := range rows {
		rowIfaces := make([]any, len(headers))
		for i := range headers {
			if i < len(row) {
				rowIfaces[i] = row[i]
			} else {
				rowIfaces[i] = ""
			}
		}
		fmt.Printf(fmtStr+"\n", rowIfaces...)
	}
}
