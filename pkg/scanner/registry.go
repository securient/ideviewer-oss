package scanner

import "sync"

var (
	registryMu sync.RWMutex
	modules    []ScanModule
)

// Register adds a scan module to the global registry.
// This is the extensibility point for the enterprise repo.
func Register(module ScanModule) {
	registryMu.Lock()
	defer registryMu.Unlock()
	modules = append(modules, module)
}

// RegisteredModules returns all registered scan modules.
func RegisteredModules() []ScanModule {
	registryMu.RLock()
	defer registryMu.RUnlock()
	result := make([]ScanModule, len(modules))
	copy(result, modules)
	return result
}
