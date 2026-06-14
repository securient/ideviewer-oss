package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/securient/ideviewer-oss/internal/config"
	"github.com/securient/ideviewer-oss/pkg/aitools"
	"github.com/securient/ideviewer-oss/pkg/api"
	"github.com/securient/ideviewer-oss/pkg/dependencies"
	"github.com/securient/ideviewer-oss/pkg/scanner"
	"github.com/securient/ideviewer-oss/pkg/secrets"
	"github.com/securient/ideviewer-oss/pkg/watcher"
)

// Daemon runs continuous IDE, secrets, dependency, and AI tool monitoring.
type Daemon struct {
	config       *config.Config
	apiClient    *api.Client
	scanner      *scanner.Scanner
	secrets      *secrets.Scanner
	dependencies *dependencies.Scanner
	aitools      *aitools.Scanner
	watcher      *watcher.Watcher
	scanInterval time.Duration
	shutdown     chan struct{}
	resultMu     sync.RWMutex // guards lastResult
	lastResult   *scanner.ScanResult
	hashes       *scanHashes
	nonceCache   *api.NonceCache // rejects replayed signed-command nonces
}

// setResult stores the latest scan result under the result lock.
func (d *Daemon) setResult(r *scanner.ScanResult) {
	d.resultMu.Lock()
	d.lastResult = r
	d.resultMu.Unlock()
}

// snapshotResult returns the most recent scan result (may be nil) under a
// read lock. Callers must not mutate the returned value.
func (d *Daemon) snapshotResult() *scanner.ScanResult {
	d.resultMu.RLock()
	defer d.resultMu.RUnlock()
	return d.lastResult
}

// New creates a Daemon from the given config. The scanner must be provided
// with its detectors already registered.
func New(cfg *config.Config, ideScanner *scanner.Scanner) (*Daemon, error) {
	if cfg.PortalURL == "" || cfg.CustomerKey == "" {
		return nil, fmt.Errorf("portal_url and customer_key are required in config")
	}

	interval := cfg.ScanIntervalMinutes
	if interval <= 0 {
		interval = 60
	}

	return &Daemon{
		config:       cfg,
		apiClient:    api.NewClientWithToken(cfg.PortalURL, cfg.CustomerKey, cfg.HostToken),
		scanner:      ideScanner,
		secrets:      secrets.NewScanner(),
		dependencies: dependencies.NewScanner(),
		aitools:      aitools.NewScanner(),
		scanInterval: time.Duration(interval) * time.Minute,
		shutdown:     make(chan struct{}),
		hashes:       &scanHashes{},
		nonceCache:   api.NewNonceCache(),
	}, nil
}

// pinCommandKeyFromResponse persists the portal's command-signing public key
// from an enroll/register response, if present and not already pinned.
func (d *Daemon) pinCommandKeyFromResponse(resp map[string]any) {
	if d.config == nil {
		return
	}
	pub, _ := resp["command_public_key"].(string)
	if pub == "" || slices.Contains(d.config.CommandPublicKeys, pub) {
		return
	}
	d.config.CommandPublicKeys = append(d.config.CommandPublicKeys, pub)
}

// Start runs the daemon loop. If runOnce is true it performs a single scan
// and returns immediately.
func (d *Daemon) Start(runOnce bool) error {
	log.Println("IDEViewer daemon starting...")
	log.Printf("Scan interval: %v", d.scanInterval)

	// Setup signal handling -- send tamper alert on shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("Received %s, shutting down...", sig)
		d.sendTamperAlert("daemon_stopping",
			fmt.Sprintf("Daemon received %s and is shutting down. "+
				"This may indicate an uninstall or manual stop.", sig))
		d.Stop()
	}()

	// Initialise tamper detection baselines.
	d.initTamperDetection()

	// Start filesystem watcher for real-time extension monitoring.
	w, err := watcher.New(30*time.Second, func(events []watcher.ChangeEvent) {
		log.Printf("Extension changes detected (%d events), running targeted scan...", len(events))
		d.handleRealtimeEvents(events)
	})
	if err != nil {
		log.Printf("Could not start filesystem watcher: %v", err)
	} else {
		d.watcher = w
		if err := w.Start(); err != nil {
			log.Printf("Filesystem watcher start failed: %v", err)
		}
	}

	// Send immediate heartbeat so the portal knows we're alive
	d.sendHeartbeat()

	// Run initial scan.
	d.runScan()

	if runOnce {
		log.Println("Single scan completed, exiting.")
		return nil
	}

	scanTicker := time.NewTicker(d.scanInterval)
	heartbeatTicker := time.NewTicker(2 * time.Minute)
	tamperTicker := time.NewTicker(1 * time.Minute)
	bypassTicker := time.NewTicker(30 * time.Second)
	pollTicker := time.NewTicker(5 * time.Second)
	enforcementTicker := time.NewTicker(10 * time.Second)

	defer scanTicker.Stop()
	defer heartbeatTicker.Stop()
	defer tamperTicker.Stop()
	defer bypassTicker.Stop()
	defer pollTicker.Stop()
	defer enforcementTicker.Stop()

	for {
		select {
		case <-d.shutdown:
			log.Println("Daemon stopped.")
			return nil

		case <-scanTicker.C:
			log.Println("Periodic scan triggered")
			d.runScan()

		case <-heartbeatTicker.C:
			d.sendHeartbeat()

		case <-tamperTicker.C:
			d.checkTamper()

		case <-bypassTicker.C:
			d.checkHookBypasses()

		case <-pollTicker.C:
			d.checkOnDemandScans()

		case <-enforcementTicker.C:
			d.checkEnforcementActions()
		}
	}
}

// Stop signals the daemon to shut down gracefully.
func (d *Daemon) Stop() {
	if d.watcher != nil {
		d.watcher.Stop()
	}
	select {
	case <-d.shutdown:
		// already closed
	default:
		close(d.shutdown)
	}
}

// runScan executes IDE, secrets, and dependency scans concurrently, then
// submits a combined report to the portal.
func (d *Daemon) runScan() {
	log.Println("Starting scan...")

	var (
		wg     sync.WaitGroup
		ideRes *scanner.ScanResult
		secRes *secrets.SecretsResult
		depRes *dependencies.DependencyResult
		aiRes  *aitools.AIToolResult
		ideErr error
		secErr error
		depErr error
		aiErr  error
	)

	wg.Add(4)

	go func() {
		defer wg.Done()
		ideRes, ideErr = d.scanner.Scan()
	}()

	go func() {
		defer wg.Done()
		secRes, secErr = d.secrets.Scan()
	}()

	go func() {
		defer wg.Done()
		depRes, depErr = d.dependencies.Scan()
	}()

	go func() {
		defer wg.Done()
		aiRes, aiErr = d.aitools.Scan()
	}()

	wg.Wait()

	if ideErr != nil {
		log.Printf("IDE scan error: %v", ideErr)
	}
	if secErr != nil {
		log.Printf("Secrets scan error: %v", secErr)
	}
	if depErr != nil {
		log.Printf("Dependency scan error: %v", depErr)
	}
	if aiErr != nil {
		log.Printf("AI tools scan error: %v", aiErr)
	}

	if ideRes != nil {
		d.setResult(ideRes)
		totalExts := 0
		for _, ide := range ideRes.IDEs {
			totalExts += len(ide.Extensions)
		}
		log.Printf("Scan completed: %d IDEs, %d extensions", len(ideRes.IDEs), totalExts)
	}

	if secRes != nil && len(secRes.Findings) > 0 {
		log.Printf("WARNING: Found %d plaintext secret(s)!", len(secRes.Findings))
	}

	if depRes != nil {
		log.Printf("Found %d packages across %d package managers",
			len(depRes.Packages), len(depRes.PackageManagersFound))
	}
	if aiRes != nil && len(aiRes.Tools) > 0 {
		log.Printf("Found %d AI tool(s)", len(aiRes.Tools))
	}

	// Check what changed since last scan
	ideHash := computeHash(ideRes)
	secHash := computeHash(secRes)
	depHash := computeHash(depRes)
	aiHash := computeHash(aiRes)

	ideChanged := d.hashes.hasChanged("ide", ideHash)
	secChanged := d.hashes.hasChanged("secrets", secHash)
	depChanged := d.hashes.hasChanged("deps", depHash)
	aiChanged := d.hashes.hasChanged("aitools", aiHash)

	if !ideChanged && !secChanged && !depChanged && !aiChanged {
		log.Println("No changes detected since last scan, skipping portal report")
		return
	}

	log.Printf("Changes detected — IDE:%v Secrets:%v Deps:%v AI:%v", ideChanged, secChanged, depChanged, aiChanged)

	d.sendToPortal(ideRes, secRes, depRes, aiRes)
}

// sendToPortal submits the combined scan data to the portal API.
func (d *Daemon) sendToPortal(ideRes *scanner.ScanResult, secRes *secrets.SecretsResult, depRes *dependencies.DependencyResult, aiRes *aitools.AIToolResult) {
	if d.apiClient == nil {
		return
	}

	scanData := structToMap(ideRes)

	if secRes != nil {
		scanData["secrets"] = structToMap(secRes)
	}
	if depRes != nil {
		scanData["dependencies"] = structToMap(depRes)
	}
	if aiRes != nil {
		scanData["ai_tools"] = structToMap(aiRes)
	}

	var resp map[string]any
	err := d.withReauth(func() error {
		var callErr error
		resp, callErr = d.apiClient.SubmitReport(scanData)
		return callErr
	})
	if err != nil {
		log.Printf("Failed to submit report to portal: %v", err)
		return
	}
	log.Printf("Report submitted to portal: %v", resp["stats"])
}

// withReauth runs the given API call and, if it fails with
// api.ErrTokenRevoked, clears the saved token, re-registers the host to
// obtain a fresh one, persists the new token to disk, and retries the
// original call once. Errors from re-enrollment are returned wrapped.
func (d *Daemon) withReauth(call func() error) error {
	err := call()
	if !errors.Is(err, api.ErrTokenRevoked) {
		return err
	}

	log.Println("host token revoked; re-enrolling")
	d.apiClient.SetHostToken("")

	regResult, regErr := d.apiClient.RegisterHost()
	if regErr != nil {
		return fmt.Errorf("re-enrollment after revoked token failed: %w", regErr)
	}

	if tokRaw, ok := regResult["host_token"]; ok {
		if tok, ok := tokRaw.(string); ok && tok != "" {
			d.apiClient.SetHostToken(tok)
			if d.config != nil {
				d.config.HostToken = tok
				// Refresh the pinned command-signing key on re-enroll too.
				d.pinCommandKeyFromResponse(regResult)
				if saveErr := config.Save(d.config); saveErr != nil {
					log.Printf("warn: could not persist new host token: %v", saveErr)
				}
			}
		}
	}

	return call()
}

// structToMap converts a struct to map[string]any via JSON round-trip.
func structToMap(v any) map[string]any {
	if v == nil {
		return nil
	}
	data, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	return m
}
