package main

import (
	"errors"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/securient/ideviewer-oss/internal/config"
)

// TestWaitForConfig_ReturnsOnceConfigAppears covers the enrollment gap: an
// installed but unregistered daemon must park in one process and pick the
// config up when `ideviewer register` writes it, rather than exiting and
// letting launchd's KeepAlive respawn it every 10 seconds.
func TestWaitForConfig_ReturnsOnceConfigAppears(t *testing.T) {
	want := &config.Config{
		PortalURL:           "https://portal.example.com",
		CustomerKey:         "key-123",
		ScanIntervalMinutes: 2,
	}

	var calls atomic.Int32
	load := func() (*config.Config, error) {
		// Fail the first two polls, then succeed — as if register ran.
		if calls.Add(1) < 3 {
			return nil, errors.New("no readable config found")
		}
		return want, nil
	}

	done := make(chan *config.Config, 1)
	go func() { done <- waitForConfig(5*time.Millisecond, load) }()

	select {
	case got := <-done:
		if got == nil {
			t.Fatal("waitForConfig returned nil, want the config")
		}
		if got.CustomerKey != want.CustomerKey {
			t.Errorf("CustomerKey = %q, want %q", got.CustomerKey, want.CustomerKey)
		}
		if calls.Load() < 3 {
			t.Errorf("load called %d times, expected it to keep polling until success", calls.Load())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waitForConfig did not return after the config became available")
	}
}

// TestWaitForConfig_ReturnsNilOnSignal ensures a parked daemon exits promptly on
// SIGTERM. launchctl bootout sends SIGTERM then SIGKILLs shortly after, so
// blocking here would lose the caller's deferred PID-file cleanup.
func TestWaitForConfig_ReturnsNilOnSignal(t *testing.T) {
	// Register our own handler first so the test binary does not take the
	// default terminating action in the window before waitForConfig arms its.
	guard := make(chan os.Signal, 1)
	signal.Notify(guard, syscall.SIGTERM)
	defer signal.Stop(guard)

	load := func() (*config.Config, error) {
		return nil, errors.New("still unregistered")
	}

	done := make(chan *config.Config, 1)
	go func() { done <- waitForConfig(10*time.Millisecond, load) }()

	// Give waitForConfig time to install its signal handler.
	time.Sleep(200 * time.Millisecond)
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("Kill: %v", err)
	}

	select {
	case got := <-done:
		if got != nil {
			t.Errorf("waitForConfig = %v, want nil after SIGTERM", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waitForConfig did not return after SIGTERM — a parked daemon would be SIGKILLed")
	}
}

// TestWaitForConfig_DoesNotReturnWhileUnconfigured is the anti-regression for
// the bug being fixed: it must not give up and return after a failed poll.
func TestWaitForConfig_DoesNotReturnWhileUnconfigured(t *testing.T) {
	load := func() (*config.Config, error) {
		return nil, errors.New("still unregistered")
	}

	done := make(chan *config.Config, 1)
	go func() { done <- waitForConfig(5*time.Millisecond, load) }()

	select {
	case got := <-done:
		t.Fatalf("waitForConfig returned %v while still unconfigured; it must keep waiting", got)
	case <-time.After(300 * time.Millisecond):
		// Still waiting after many poll intervals — correct.
	}
}
