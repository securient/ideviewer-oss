package watcher

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// ChangeEvent represents a detected filesystem change.
type ChangeEvent struct {
	Path      string    `json:"path"`
	EventType string    `json:"event_type"` // "created", "modified", "deleted"
	Timestamp time.Time `json:"timestamp"`
}

// Watcher monitors IDE extension directories for changes.
type Watcher struct {
	fsWatcher    *fsnotify.Watcher
	debounceTime time.Duration
	callback     func([]ChangeEvent)
	shutdown     chan struct{}
	mu           sync.Mutex
	pending      []ChangeEvent
	timer        *time.Timer
}

// New creates a Watcher with the given debounce duration and callback.
func New(debounce time.Duration, callback func([]ChangeEvent)) (*Watcher, error) {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	return &Watcher{
		fsWatcher:    fsw,
		debounceTime: debounce,
		callback:     callback,
		shutdown:     make(chan struct{}),
	}, nil
}

// Start begins watching IDE extension directories.
func (w *Watcher) Start() error {
	dirs := extensionDirs()
	watched := 0
	for _, dir := range dirs {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			if err := w.fsWatcher.Add(dir); err != nil {
				log.Printf("Watcher: could not watch %s: %v", dir, err)
			} else {
				watched++
				log.Printf("Watcher: monitoring %s", dir)
			}
		}
	}
	if watched == 0 {
		log.Println("Watcher: no extension directories found to monitor")
	}

	go w.loop()
	return nil
}

// Stop shuts down the watcher.
func (w *Watcher) Stop() {
	select {
	case <-w.shutdown:
	default:
		close(w.shutdown)
	}
	w.fsWatcher.Close()
}

func (w *Watcher) loop() {
	for {
		select {
		case <-w.shutdown:
			return
		case event, ok := <-w.fsWatcher.Events:
			if !ok {
				return
			}
			w.handleEvent(event)
		case err, ok := <-w.fsWatcher.Errors:
			if !ok {
				return
			}
			log.Printf("Watcher error: %v", err)
		}
	}
}

func (w *Watcher) handleEvent(event fsnotify.Event) {
	// Map fsnotify operations to our event types
	var eventType string
	switch {
	case event.Op&fsnotify.Create != 0:
		eventType = "created"
	case event.Op&fsnotify.Write != 0:
		eventType = "modified"
	case event.Op&fsnotify.Remove != 0:
		eventType = "deleted"
	case event.Op&fsnotify.Rename != 0:
		eventType = "deleted"
	default:
		return // Ignore chmod-only events
	}

	ce := ChangeEvent{
		Path:      event.Name,
		EventType: eventType,
		Timestamp: time.Now().UTC(),
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	w.pending = append(w.pending, ce)

	// Reset/start debounce timer
	if w.timer != nil {
		w.timer.Stop()
	}
	w.timer = time.AfterFunc(w.debounceTime, w.flush)
}

func (w *Watcher) flush() {
	w.mu.Lock()
	events := w.pending
	w.pending = nil
	w.mu.Unlock()

	if len(events) > 0 && w.callback != nil {
		log.Printf("Watcher: %d change(s) detected, triggering callback", len(events))
		w.callback(events)
	}
}

// extensionDirs returns all known IDE extension directories for the current platform.
func extensionDirs() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	var dirs []string
	plat := runtime.GOOS

	// VS Code family
	vscodeExts := map[string][]string{
		"darwin": {
			filepath.Join(home, ".vscode", "extensions"),
			filepath.Join(home, ".cursor", "extensions"),
			filepath.Join(home, ".vscode-oss", "extensions"),
		},
		"linux": {
			filepath.Join(home, ".vscode", "extensions"),
			filepath.Join(home, ".cursor", "extensions"),
			filepath.Join(home, ".vscode-oss", "extensions"),
		},
		"windows": {
			filepath.Join(home, ".vscode", "extensions"),
			filepath.Join(home, ".cursor", "extensions"),
			filepath.Join(home, ".vscode-oss", "extensions"),
		},
	}
	dirs = append(dirs, vscodeExts[plat]...)

	// JetBrains plugin directories
	var jbBases []string
	switch plat {
	case "darwin":
		jbBases = []string{filepath.Join(home, "Library", "Application Support", "JetBrains")}
	case "linux":
		jbBases = []string{
			filepath.Join(home, ".config", "JetBrains"),
			filepath.Join(home, ".local", "share", "JetBrains"),
		}
	case "windows":
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			jbBases = []string{filepath.Join(appdata, "JetBrains")}
		}
	}
	for _, base := range jbBases {
		entries, err := os.ReadDir(base)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			pluginsDir := filepath.Join(base, entry.Name(), "plugins")
			if info, err := os.Stat(pluginsDir); err == nil && info.IsDir() {
				dirs = append(dirs, pluginsDir)
			}
		}
	}

	// Filter to only directories that exist
	var existing []string
	for _, d := range dirs {
		if info, err := os.Stat(d); err == nil && info.IsDir() {
			existing = append(existing, d)
		}
	}

	// Deduplicate (in case of symlinks, etc.)
	seen := make(map[string]bool)
	var unique []string
	for _, d := range existing {
		resolved, err := filepath.EvalSymlinks(d)
		if err != nil {
			resolved = d
		}
		if !seen[resolved] {
			seen[resolved] = true
			unique = append(unique, d)
		}
	}

	return unique
}
