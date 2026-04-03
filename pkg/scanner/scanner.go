package scanner

import (
	"context"
	"sync"
)

// Detector is the interface that all IDE detectors must implement.
type Detector interface {
	Name() string
	Detect() ([]IDE, error)
}

// ScanModule is the interface for extensible scan modules.
// Enterprise features can register additional modules.
type ScanModule interface {
	Name() string
	Scan(ctx context.Context) (any, error)
}

// Scanner orchestrates IDE detection across all registered detectors.
type Scanner struct {
	detectors []Detector
}

// New creates a Scanner with the given detectors.
func New(detectors ...Detector) *Scanner {
	return &Scanner{detectors: detectors}
}

// Scan runs all detectors and returns a combined ScanResult.
func (s *Scanner) Scan() (*ScanResult, error) {
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		allIDEs []IDE
		allErrs []string
	)

	for _, d := range s.detectors {
		wg.Add(1)
		go func(det Detector) {
			defer wg.Done()
			ides, err := det.Detect()
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				allErrs = append(allErrs, det.Name()+": "+err.Error())
				return
			}
			allIDEs = append(allIDEs, ides...)
		}(d)
	}

	wg.Wait()
	return NewScanResult(allIDEs, allErrs), nil
}

// ScanQuick runs detection without parsing extensions.
func (s *Scanner) ScanQuick() (*ScanResult, error) {
	result, err := s.Scan()
	if err != nil {
		return nil, err
	}
	for i := range result.IDEs {
		result.IDEs[i].Extensions = nil
		result.IDEs[i].ExtensionCount = 0
	}
	result.TotalExtensions = 0
	return result, nil
}

// GetExtensionStats returns aggregated statistics from a scan result.
func GetExtensionStats(result *ScanResult) map[string]any {
	extsByIDE := make(map[string]int)
	permCounts := make(map[string]map[string]any)
	dangerousCount := 0

	for _, ide := range result.IDEs {
		extsByIDE[ide.Name] = len(ide.Extensions)
		for _, ext := range ide.Extensions {
			for _, perm := range ext.Permissions {
				if _, ok := permCounts[perm.Name]; !ok {
					permCounts[perm.Name] = map[string]any{
						"count":        0,
						"is_dangerous": perm.IsDangerous,
					}
				}
				permCounts[perm.Name]["count"] = permCounts[perm.Name]["count"].(int) + 1
			}
			for _, perm := range ext.Permissions {
				if perm.IsDangerous {
					dangerousCount++
					break
				}
			}
		}
	}

	return map[string]any{
		"total_ides":                           result.TotalIDEs,
		"total_extensions":                     result.TotalExtensions,
		"extensions_with_dangerous_permissions": dangerousCount,
		"extensions_by_ide":                    extsByIDE,
		"permission_counts":                    permCounts,
	}
}
