//go:build !windows

package main

import (
	"errors"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/securient/ideviewer-oss/internal/config"
)

// TestWaitForConfig_ReturnsNilOnSignal ensures a parked daemon exits promptly on
// SIGTERM. launchctl bootout sends SIGTERM then SIGKILLs shortly after, so
// blocking here would lose the caller's deferred PID-file cleanup.
//
// Unix-only: syscall.Kill is not defined on Windows, so this will not compile
// there. The behaviour it guards is launchd/systemd-specific anyway.
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
