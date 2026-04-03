package main

import (
	"fmt"
	"strings"

	"github.com/securient/ideviewer-oss/pkg/scanner"
	"github.com/spf13/cobra"
)

var dangerousCmd = &cobra.Command{
	Use:   "dangerous",
	Short: "List extensions with dangerous permissions",
	RunE:  runDangerous,
}

func runDangerous(cmd *cobra.Command, args []string) error {
	fmt.Println("Scanning for extensions with dangerous permissions...")

	s := scanner.New(allDetectors()...)
	result, err := s.Scan()
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	var rows [][]string
	for _, ide := range result.IDEs {
		for _, ext := range ide.Extensions {
			var dangerousPerms []string
			for _, p := range ext.Permissions {
				if p.IsDangerous {
					dangerousPerms = append(dangerousPerms, p.Name)
				}
			}
			if len(dangerousPerms) > 0 {
				rows = append(rows, []string{
					ide.Name,
					ext.Name,
					ext.Version,
					strings.Join(dangerousPerms, ", "),
				})
			}
		}
	}

	fmt.Println()
	if len(rows) > 0 {
		printTable(
			[]string{"IDE", "Extension", "Version", "Dangerous Permissions"},
			rows,
		)
	} else {
		colorGreen.Println("No extensions with dangerous permissions found.")
	}

	return nil
}
