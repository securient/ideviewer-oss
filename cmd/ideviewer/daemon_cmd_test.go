package main

import (
	"errors"
	"sync/atomic"
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

// The SIGTERM case lives in daemon_cmd_signal_test.go — syscall.Kill does not
// exist on Windows, so it cannot even compile here.

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
