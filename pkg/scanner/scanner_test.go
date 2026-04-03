package scanner

import (
	"context"
	"fmt"
	"testing"
)

// mockDetector implements the Detector interface for testing.
type mockDetector struct {
	name string
	ides []IDE
	err  error
}

func (m *mockDetector) Name() string         { return m.name }
func (m *mockDetector) Detect() ([]IDE, error) { return m.ides, m.err }

// mockScanModule implements ScanModule for testing the registry.
type mockScanModule struct {
	name string
}

func (m *mockScanModule) Name() string                        { return m.name }
func (m *mockScanModule) Scan(ctx context.Context) (any, error) { return nil, nil }

func TestNewScanResult_ComputesTotals(t *testing.T) {
	ides := []IDE{
		{
			IDEType: IDETypeVSCode,
			Name:    "VS Code",
			Extensions: []Extension{
				{ID: "ext1", Name: "Extension 1"},
				{ID: "ext2", Name: "Extension 2"},
			},
		},
		{
			IDEType: IDETypeVim,
			Name:    "Vim",
			Extensions: []Extension{
				{ID: "ext3", Name: "Extension 3"},
			},
		},
	}

	result := NewScanResult(ides, nil)

	if result.TotalIDEs != 2 {
		t.Errorf("TotalIDEs = %d, want 2", result.TotalIDEs)
	}
	if result.TotalExtensions != 3 {
		t.Errorf("TotalExtensions = %d, want 3", result.TotalExtensions)
	}
	if result.IDEs[0].ExtensionCount != 2 {
		t.Errorf("IDEs[0].ExtensionCount = %d, want 2", result.IDEs[0].ExtensionCount)
	}
	if result.IDEs[1].ExtensionCount != 1 {
		t.Errorf("IDEs[1].ExtensionCount = %d, want 1", result.IDEs[1].ExtensionCount)
	}
	if result.Timestamp == "" {
		t.Error("Timestamp should not be empty")
	}
	if result.Platform == "" {
		t.Error("Platform should not be empty")
	}
}

func TestNewScanResult_EmptyIDEs(t *testing.T) {
	result := NewScanResult(nil, []string{"some error"})

	if result.TotalIDEs != 0 {
		t.Errorf("TotalIDEs = %d, want 0", result.TotalIDEs)
	}
	if result.TotalExtensions != 0 {
		t.Errorf("TotalExtensions = %d, want 0", result.TotalExtensions)
	}
	if len(result.Errors) != 1 {
		t.Errorf("Errors length = %d, want 1", len(result.Errors))
	}
}

func TestScanner_WithMockDetector(t *testing.T) {
	det := &mockDetector{
		name: "test-detector",
		ides: []IDE{
			{
				IDEType: IDETypeVSCode,
				Name:    "VS Code",
				Extensions: []Extension{
					{ID: "ext1", Name: "Ext 1"},
				},
			},
		},
	}

	s := New(det)
	result, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if result.TotalIDEs != 1 {
		t.Errorf("TotalIDEs = %d, want 1", result.TotalIDEs)
	}
	if result.TotalExtensions != 1 {
		t.Errorf("TotalExtensions = %d, want 1", result.TotalExtensions)
	}
}

func TestScanner_DetectorError(t *testing.T) {
	det := &mockDetector{
		name: "failing-detector",
		err:  fmt.Errorf("detection failed"),
	}

	s := New(det)
	result, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(result.Errors) != 1 {
		t.Errorf("Errors length = %d, want 1", len(result.Errors))
	}
	if result.TotalIDEs != 0 {
		t.Errorf("TotalIDEs = %d, want 0", result.TotalIDEs)
	}
}

func TestScanner_MultipleDetectors(t *testing.T) {
	det1 := &mockDetector{
		name: "det1",
		ides: []IDE{{IDEType: IDETypeVSCode, Name: "VS Code"}},
	}
	det2 := &mockDetector{
		name: "det2",
		ides: []IDE{{IDEType: IDETypeVim, Name: "Vim"}},
	}

	s := New(det1, det2)
	result, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if result.TotalIDEs != 2 {
		t.Errorf("TotalIDEs = %d, want 2", result.TotalIDEs)
	}
}

func TestGetExtensionStats(t *testing.T) {
	result := &ScanResult{
		TotalIDEs:       1,
		TotalExtensions: 2,
		IDEs: []IDE{
			{
				Name: "VS Code",
				Extensions: []Extension{
					{
						ID:   "ext1",
						Name: "Ext 1",
						Permissions: []Permission{
							{Name: "filesystem", IsDangerous: true},
							{Name: "network", IsDangerous: false},
						},
					},
					{
						ID:   "ext2",
						Name: "Ext 2",
						Permissions: []Permission{
							{Name: "filesystem", IsDangerous: true},
						},
					},
				},
			},
		},
	}

	stats := GetExtensionStats(result)

	if stats["total_ides"] != 1 {
		t.Errorf("total_ides = %v, want 1", stats["total_ides"])
	}
	if stats["total_extensions"] != 2 {
		t.Errorf("total_extensions = %v, want 2", stats["total_extensions"])
	}
	if stats["extensions_with_dangerous_permissions"] != 2 {
		t.Errorf("extensions_with_dangerous_permissions = %v, want 2", stats["extensions_with_dangerous_permissions"])
	}

	extsByIDE := stats["extensions_by_ide"].(map[string]int)
	if extsByIDE["VS Code"] != 2 {
		t.Errorf("extsByIDE[VS Code] = %d, want 2", extsByIDE["VS Code"])
	}

	permCounts := stats["permission_counts"].(map[string]map[string]any)
	if permCounts["filesystem"]["count"].(int) != 2 {
		t.Errorf("filesystem count = %v, want 2", permCounts["filesystem"]["count"])
	}
	if permCounts["filesystem"]["is_dangerous"].(bool) != true {
		t.Error("filesystem should be dangerous")
	}
}

func TestRegistry_RegisterAndList(t *testing.T) {
	// Save and restore global state.
	origModules := modules
	modules = nil
	defer func() { modules = origModules }()

	mod1 := &mockScanModule{name: "mod1"}
	mod2 := &mockScanModule{name: "mod2"}

	Register(mod1)
	Register(mod2)

	registered := RegisteredModules()
	if len(registered) != 2 {
		t.Fatalf("RegisteredModules() length = %d, want 2", len(registered))
	}
	if registered[0].Name() != "mod1" {
		t.Errorf("registered[0].Name() = %q, want %q", registered[0].Name(), "mod1")
	}
	if registered[1].Name() != "mod2" {
		t.Errorf("registered[1].Name() = %q, want %q", registered[1].Name(), "mod2")
	}

	// Verify returned slice is a copy (modifying it doesn't affect the registry).
	registered[0] = nil
	afterModify := RegisteredModules()
	if afterModify[0] == nil {
		t.Error("RegisteredModules() should return a copy")
	}
}

func TestScanQuick(t *testing.T) {
	det := &mockDetector{
		name: "test",
		ides: []IDE{
			{
				IDEType:    IDETypeVSCode,
				Name:       "VS Code",
				Extensions: []Extension{{ID: "ext1"}},
			},
		},
	}

	s := New(det)
	result, err := s.ScanQuick()
	if err != nil {
		t.Fatalf("ScanQuick() error: %v", err)
	}
	if result.TotalExtensions != 0 {
		t.Errorf("TotalExtensions = %d, want 0", result.TotalExtensions)
	}
	if result.IDEs[0].ExtensionCount != 0 {
		t.Errorf("ExtensionCount = %d, want 0", result.IDEs[0].ExtensionCount)
	}
	if result.IDEs[0].Extensions != nil {
		t.Error("Extensions should be nil after ScanQuick")
	}
}
