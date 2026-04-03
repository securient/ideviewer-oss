package main

import (
	"encoding/json"
	"fmt"

	"github.com/securient/ideviewer-oss/internal/config"
	"github.com/securient/ideviewer-oss/pkg/api"
	"github.com/securient/ideviewer-oss/pkg/dependencies"
	"github.com/securient/ideviewer-oss/pkg/scanner"
	"github.com/securient/ideviewer-oss/pkg/secrets"
)

// sendScanToPortal sends IDE scan results (and optionally secrets/deps) to the portal.
func sendScanToPortal(result *scanner.ScanResult, includeSecrets, includeDeps bool) {
	cfg, client, err := portalClient()
	if err != nil {
		colorRed.Printf("Portal error: %v\n", err)
		return
	}
	_ = cfg

	scanData := toMap(result)

	if includeSecrets {
		sc := secrets.NewScanner()
		secResult, err := sc.Scan()
		if err == nil && secResult != nil {
			scanData["secrets"] = toMap(secResult)
		}
	}

	if includeDeps {
		dc := dependencies.NewScanner()
		depResult, err := dc.Scan()
		if err == nil && depResult != nil {
			scanData["dependencies"] = toMap(depResult)
		}
	}

	submitToPortal(client, scanData)
}

// sendSecretsToPortal sends secrets results to the portal, including a minimal IDE scan.
func sendSecretsToPortal(result *secrets.SecretsResult) {
	_, client, err := portalClient()
	if err != nil {
		colorRed.Printf("Portal error: %v\n", err)
		return
	}

	// Portal expects scan data with IDEs as the top level.
	scanData := map[string]any{
		"ides":             []any{},
		"total_ides":       0,
		"total_extensions": 0,
		"secrets":          toMap(result),
	}

	submitToPortal(client, scanData)
}

// sendDepsToPortal sends dependency results to the portal.
func sendDepsToPortal(result *dependencies.DependencyResult) {
	_, client, err := portalClient()
	if err != nil {
		colorRed.Printf("Portal error: %v\n", err)
		return
	}

	scanData := map[string]any{
		"ides":             []any{},
		"total_ides":       0,
		"total_extensions": 0,
		"dependencies":     toMap(result),
	}

	submitToPortal(client, scanData)
}

func portalClient() (*config.Config, *api.Client, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, fmt.Errorf("no portal configuration found. Run 'ideviewer register' first")
	}
	client := api.NewClient(cfg.PortalURL, cfg.CustomerKey)
	return cfg, client, nil
}

func submitToPortal(client *api.Client, scanData map[string]any) {
	resp, err := client.SubmitReport(scanData)
	if err != nil {
		colorRed.Printf("Portal error: %v\n", err)
		return
	}

	if success, ok := resp["success"].(bool); ok && success {
		stats, _ := resp["stats"].(map[string]any)
		colorGreen.Println("Report sent to portal")
		if stats != nil {
			colorDim.Printf("  IDEs: %v, Extensions: %v, Secrets: %v, Packages: %v\n",
				stats["total_ides"], stats["total_extensions"],
				stats["secrets_found"], stats["packages_found"])
		}
	} else {
		errMsg, _ := resp["error"].(string)
		colorRed.Printf("Portal rejected report: %s\n", errMsg)
	}
}

// toMap converts a struct to map[string]any via JSON round-trip.
func toMap(v any) map[string]any {
	if v == nil {
		return nil
	}
	data, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	return m
}
