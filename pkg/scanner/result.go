package scanner

import (
	"time"
)

// IDEType represents the type of IDE detected.
type IDEType string

const (
	IDETypeVSCode         IDEType = "vscode"
	IDETypeCursor         IDEType = "cursor"
	IDETypeVSCodium       IDEType = "vscodium"
	IDETypeJetBrainsIDEA  IDEType = "intellij-idea"
	IDETypeJetBrainsPyCharm IDEType = "pycharm"
	IDETypeJetBrainsWebStorm IDEType = "webstorm"
	IDETypeJetBrainsGoLand  IDEType = "goland"
	IDETypeJetBrainsCLion   IDEType = "clion"
	IDETypeJetBrainsRider   IDEType = "rider"
	IDETypeJetBrainsPhpStorm IDEType = "phpstorm"
	IDETypeJetBrainsRubyMine IDEType = "rubymine"
	IDETypeJetBrainsDataGrip IDEType = "datagrip"
	IDETypeSublimeText    IDEType = "sublime-text"
	IDETypeAtom           IDEType = "atom"
	IDETypeVim            IDEType = "vim"
	IDETypeNeovim         IDEType = "neovim"
	IDETypeEmacs          IDEType = "emacs"
	IDETypeEclipse        IDEType = "eclipse"
	IDETypeAndroidStudio  IDEType = "android-studio"
	IDETypeXcode          IDEType = "xcode"
	IDETypeUnknown        IDEType = "unknown"
)

// Permission represents an extension permission or capability.
type Permission struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	IsDangerous bool   `json:"is_dangerous"`
}

// Extension represents an IDE extension or plugin.
type Extension struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Version          string            `json:"version"`
	Publisher        string            `json:"publisher,omitempty"`
	Maintainer       string            `json:"maintainer,omitempty"`
	Description      string            `json:"description,omitempty"`
	Homepage         string            `json:"homepage,omitempty"`
	Repository       string            `json:"repository,omitempty"`
	License          string            `json:"license,omitempty"`
	InstallPath      string            `json:"install_path,omitempty"`
	Permissions      []Permission      `json:"permissions"`
	Contributes      map[string]any    `json:"contributes"`
	Dependencies     []string          `json:"dependencies"`
	Enabled          bool              `json:"enabled"`
	Builtin          bool              `json:"builtin"`
	LastUpdated      *time.Time        `json:"last_updated,omitempty"`
	MarketplaceURL   string            `json:"marketplace_url,omitempty"`
	ActivationEvents []string          `json:"activation_events"`
	Capabilities     map[string]any    `json:"capabilities"`
}

// MarshalLastUpdated returns ISO8601 string or nil for JSON.
func (e Extension) MarshalJSON() ([]byte, error) {
	type Alias Extension
	aux := struct {
		Alias
		LastUpdated *string `json:"last_updated,omitempty"`
	}{
		Alias: Alias(e),
	}
	if e.LastUpdated != nil {
		s := e.LastUpdated.Format(time.RFC3339)
		aux.LastUpdated = &s
	}
	// Use encoding/json to avoid import cycle
	return marshalJSON(aux)
}

// IDE represents a detected IDE installation.
type IDE struct {
	IDEType        IDEType     `json:"ide_type"`
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InstallPath    string      `json:"install_path,omitempty"`
	ConfigPath     string      `json:"config_path,omitempty"`
	ExtensionsPath string      `json:"extensions_path,omitempty"`
	Extensions     []Extension `json:"extensions"`
	ExtensionCount int         `json:"extension_count"`
	IsRunning      bool        `json:"is_running"`
}

// ScanResult holds the complete result of an IDE scan.
type ScanResult struct {
	Timestamp       string   `json:"timestamp"`
	Platform        string   `json:"platform"`
	IDEs            []IDE    `json:"ides"`
	TotalIDEs       int      `json:"total_ides"`
	TotalExtensions int      `json:"total_extensions"`
	Errors          []string `json:"errors"`
}

// NewScanResult creates a ScanResult with computed totals.
func NewScanResult(ides []IDE, errors []string) *ScanResult {
	totalExts := 0
	for i := range ides {
		ides[i].ExtensionCount = len(ides[i].Extensions)
		totalExts += ides[i].ExtensionCount
	}
	return &ScanResult{
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		Platform:        platformString(),
		IDEs:            ides,
		TotalIDEs:       len(ides),
		TotalExtensions: totalExts,
		Errors:          errors,
	}
}
