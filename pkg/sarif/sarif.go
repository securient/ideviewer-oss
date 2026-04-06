// Package sarif implements SARIF v2.1.0 output formatting for IDEViewer scan results.
//
// Generates Static Analysis Results Interchange Format (SARIF) output
// compatible with GitHub Security tab, CodeQL, and other SARIF consumers.
package sarif

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/securient/ideviewer-oss/pkg/scanner"
	"github.com/securient/ideviewer-oss/pkg/secrets"
)

const (
	sarifSchema        = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
	sarifVersion       = "2.1.0"
	toolName           = "ideviewer"
	toolInformationURI = "https://github.com/securient/ideviewer-oss"
)

// severityToSARIFLevel maps IDEViewer severity to SARIF result level.
func severityToSARIFLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "note"
	}
}

// buildToolComponent creates the SARIF tool component with an empty rules slice.
func buildToolComponent(version string) map[string]any {
	return map[string]any{
		"driver": map[string]any{
			"name":           toolName,
			"version":        version,
			"informationUri": toolInformationURI,
			"rules":          []any{},
		},
	}
}

// FormatScanResult converts an IDE scan result to a SARIF v2.1.0 map.
// It maps dangerous extension permissions to SARIF rules and results.
func FormatScanResult(result *scanner.ScanResult, version string) map[string]any {
	rules := map[string]map[string]any{}
	ruleOrder := []string{}
	results := []any{}

	for _, ide := range result.IDEs {
		ideName := ide.Name
		for _, ext := range ide.Extensions {
			var dangerousPerms []scanner.Permission
			for _, p := range ext.Permissions {
				if p.IsDangerous {
					dangerousPerms = append(dangerousPerms, p)
				}
			}
			if len(dangerousPerms) == 0 {
				continue
			}

			extID := ext.ID
			if extID == "" {
				extID = ext.Name
			}
			if extID == "" {
				extID = "unknown"
			}
			extName := ext.Name
			if extName == "" {
				extName = "unknown"
			}
			publisher := ext.Publisher
			if publisher == "" {
				publisher = "unknown"
			}

			for _, perm := range dangerousPerms {
				ruleID := "dangerous-permission/" + strings.ToLower(strings.ReplaceAll(perm.Name, " ", "-"))

				if _, exists := rules[ruleID]; !exists {
					description := perm.Description
					if description == "" {
						description = fmt.Sprintf("Extension requests dangerous permission: %s", perm.Name)
					}
					rules[ruleID] = map[string]any{
						"id":   ruleID,
						"name": "DangerousPermission_" + strings.ReplaceAll(perm.Name, " ", "_"),
						"shortDescription": map[string]any{
							"text": fmt.Sprintf("Dangerous permission: %s", perm.Name),
						},
						"fullDescription": map[string]any{
							"text": description,
						},
						"defaultConfiguration": map[string]any{
							"level": "error",
						},
						"properties": map[string]any{
							"tags": []string{"security", "extensions", "permissions"},
						},
					}
					ruleOrder = append(ruleOrder, ruleID)
				}

				resultEntry := map[string]any{
					"ruleId": ruleID,
					"level":  "error",
					"message": map[string]any{
						"text": fmt.Sprintf("Extension '%s' by %s in %s has dangerous permission: %s",
							extName, publisher, ideName, perm.Name),
					},
					"locations": []any{},
				}

				if ext.InstallPath != "" {
					extVersion := ext.Version
					if extVersion == "" {
						extVersion = "unknown"
					}
					locations := []any{
						map[string]any{
							"physicalLocation": map[string]any{
								"artifactLocation": map[string]any{
									"uri": ext.InstallPath,
								},
							},
							"message": map[string]any{
								"text": fmt.Sprintf("%s extension: %s v%s", ideName, extName, extVersion),
							},
						},
					}
					resultEntry["locations"] = locations
				}

				results = append(results, resultEntry)
			}
		}
	}

	// Build ordered rules list.
	rulesList := make([]any, 0, len(ruleOrder))
	for _, id := range ruleOrder {
		rulesList = append(rulesList, rules[id])
	}

	tool := buildToolComponent(version)
	driver := tool["driver"].(map[string]any)
	driver["rules"] = rulesList

	timestamp := result.Timestamp
	if timestamp == "" {
		timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	return map[string]any{
		"$schema": sarifSchema,
		"version": sarifVersion,
		"runs": []any{
			map[string]any{
				"tool":    tool,
				"results": results,
				"invocations": []any{
					map[string]any{
						"executionSuccessful": true,
						"endTimeUtc":         timestamp,
					},
				},
			},
		},
	}
}

// FormatSecretsResult converts a secrets scan result to a SARIF v2.1.0 map.
// It maps secret findings to SARIF rules and results.
func FormatSecretsResult(result *secrets.SecretsResult, version string) map[string]any {
	rules := map[string]map[string]any{}
	ruleOrder := []string{}
	results := []any{}

	for _, finding := range result.Findings {
		secretType := finding.SecretType
		if secretType == "" {
			secretType = "unknown"
		}
		ruleID := "secret/" + secretType

		if _, exists := rules[ruleID]; !exists {
			severity := finding.Severity
			if severity == "" {
				severity = "critical"
			}
			description := finding.Description
			if description == "" {
				description = fmt.Sprintf("Detected exposed %s in configuration file", secretType)
			}
			recommendation := finding.Recommendation
			if recommendation == "" {
				recommendation = "Remove the secret from the file and use a secrets manager instead."
			}

			rules[ruleID] = map[string]any{
				"id":   ruleID,
				"name": "ExposedSecret_" + strings.ReplaceAll(secretType, "-", "_"),
				"shortDescription": map[string]any{
					"text": fmt.Sprintf("Exposed secret: %s",
						strings.Title(strings.ReplaceAll(secretType, "_", " "))), //nolint:staticcheck
				},
				"fullDescription": map[string]any{
					"text": description,
				},
				"defaultConfiguration": map[string]any{
					"level": severityToSARIFLevel(severity),
				},
				"help": map[string]any{
					"text": recommendation,
				},
				"properties": map[string]any{
					"tags": []string{"security", "secrets", secretType},
				},
			}
			ruleOrder = append(ruleOrder, ruleID)
		}

		variableName := finding.VariableName
		if variableName == "" {
			variableName = "unknown"
		}
		findingSeverity := finding.Severity
		if findingSeverity == "" {
			findingSeverity = "critical"
		}

		resultEntry := map[string]any{
			"ruleId": ruleID,
			"level":  severityToSARIFLevel(findingSeverity),
			"message": map[string]any{
				"text": fmt.Sprintf("Potential %s detected in variable '%s'",
					strings.ReplaceAll(secretType, "_", " "), variableName),
			},
			"locations": []any{},
		}

		if finding.FilePath != "" {
			location := map[string]any{
				"physicalLocation": map[string]any{
					"artifactLocation": map[string]any{
						"uri": finding.FilePath,
					},
				},
			}
			if finding.LineNumber > 0 {
				physLoc := location["physicalLocation"].(map[string]any)
				physLoc["region"] = map[string]any{
					"startLine": finding.LineNumber,
				}
			}
			resultEntry["locations"] = []any{location}
		}

		results = append(results, resultEntry)
	}

	// Build ordered rules list.
	rulesList := make([]any, 0, len(ruleOrder))
	for _, id := range ruleOrder {
		rulesList = append(rulesList, rules[id])
	}

	tool := buildToolComponent(version)
	driver := tool["driver"].(map[string]any)
	driver["rules"] = rulesList

	timestamp := result.Timestamp
	if timestamp == "" {
		timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	return map[string]any{
		"$schema": sarifSchema,
		"version": sarifVersion,
		"runs": []any{
			map[string]any{
				"tool":    tool,
				"results": results,
				"invocations": []any{
					map[string]any{
						"executionSuccessful": true,
						"endTimeUtc":         timestamp,
					},
				},
			},
		},
	}
}

// ToJSON serializes a SARIF map to pretty-printed JSON bytes.
func ToJSON(sarif map[string]any) ([]byte, error) {
	return json.MarshalIndent(sarif, "", "  ")
}
