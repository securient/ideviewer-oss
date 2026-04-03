package main

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/securient/ideviewer-oss/pkg/scanner"
	"github.com/spf13/cobra"
)

var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show statistics about installed IDEs and extensions",
	RunE:  runStats,
}

func init() {
	statsCmd.Flags().Bool("json", false, "Output as JSON")
}

func runStats(cmd *cobra.Command, args []string) error {
	outputJSON, _ := cmd.Flags().GetBool("json")

	fmt.Println("Scanning for IDEs...")

	s := scanner.New(allDetectors()...)
	result, err := s.Scan()
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	stats := scanner.GetExtensionStats(result)

	if outputJSON {
		data, err := json.MarshalIndent(stats, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}

	displayStats(stats)
	return nil
}

func displayStats(stats map[string]any) {
	fmt.Println()
	fmt.Println("=== Summary ===")
	fmt.Printf("  Total IDEs:        %v\n", stats["total_ides"])
	fmt.Printf("  Total Extensions:  %v\n", stats["total_extensions"])

	dangCount := stats["extensions_with_dangerous_permissions"]
	if d, ok := dangCount.(int); ok && d > 0 {
		colorRed.Printf("  Dangerous Extensions: %d\n", d)
	} else {
		fmt.Printf("  Dangerous Extensions: %v\n", dangCount)
	}
	fmt.Println()

	// Extensions by IDE.
	if extsByIDE, ok := stats["extensions_by_ide"].(map[string]int); ok && len(extsByIDE) > 0 {
		fmt.Println("=== Extensions by IDE ===")
		type kv struct {
			k string
			v int
		}
		var sorted []kv
		for k, v := range extsByIDE {
			sorted = append(sorted, kv{k, v})
		}
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].v > sorted[j].v })

		var rows [][]string
		for _, s := range sorted {
			rows = append(rows, []string{s.k, fmt.Sprintf("%d", s.v)})
		}
		printTable([]string{"IDE", "Extensions"}, rows)
		fmt.Println()
	}

	// Permission counts.
	if permCounts, ok := stats["permission_counts"].(map[string]map[string]any); ok && len(permCounts) > 0 {
		fmt.Println("=== Top Permission Usage ===")
		type permEntry struct {
			name        string
			count       int
			isDangerous bool
		}
		var perms []permEntry
		for name, data := range permCounts {
			count, _ := data["count"].(int)
			isDang, _ := data["is_dangerous"].(bool)
			perms = append(perms, permEntry{name, count, isDang})
		}
		sort.Slice(perms, func(i, j int) bool { return perms[i].count > perms[j].count })

		limit := 15
		if len(perms) < limit {
			limit = len(perms)
		}

		var rows [][]string
		for _, p := range perms[:limit] {
			risk := "Normal"
			if p.isDangerous {
				risk = "Dangerous"
			}
			rows = append(rows, []string{p.name, fmt.Sprintf("%d", p.count), risk})
		}
		printTable([]string{"Permission", "Count", "Risk"}, rows)
		fmt.Println()
	}
}
