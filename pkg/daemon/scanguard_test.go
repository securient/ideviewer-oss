package daemon

import (
	"sync"
	"testing"
)

// On-demand scans used to run inline on the daemon's select loop. A full scan
// takes minutes on a large Windows profile, and for that whole window the
// daemon sent no heartbeats (so the portal marked the host silent), polled no
// enforcement actions, and could not notice a cancellation. Scans now run in a
// goroutine behind this reservation, which also keeps a periodic scan from
// overlapping an on-demand one — they share d.scanner, d.secrets and
// d.dependencies.

func TestTryBeginScan_IsExclusive(t *testing.T) {
	d := &Daemon{}

	if !d.tryBeginScan() {
		t.Fatal("first tryBeginScan = false, want true")
	}
	if d.tryBeginScan() {
		t.Fatal("second tryBeginScan = true; two scans could run concurrently")
	}

	d.endScan()
	if !d.tryBeginScan() {
		t.Fatal("tryBeginScan after endScan = false; the reservation was not released")
	}
	d.endScan()
}

func TestTryBeginScan_ExactlyOneWinnerUnderContention(t *testing.T) {
	d := &Daemon{}

	const goroutines = 64
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners int
	)
	start := make(chan struct{})

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			if d.tryBeginScan() {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	if winners != 1 {
		t.Fatalf("%d goroutines acquired the scan reservation, want exactly 1", winners)
	}
}

func TestRunScan_SkippedWhileAnotherScanHoldsTheReservation(t *testing.T) {
	// A daemon with no API client and no scanner would panic if runScan got
	// past the guard, so reaching the end proves it returned early.
	d := &Daemon{}
	if !d.tryBeginScan() {
		t.Fatal("could not take the reservation")
	}
	defer d.endScan()

	d.runScan() // must be a no-op, not a nil-pointer dereference
}

func TestCheckOnDemandScans_NilClientIsSafe(t *testing.T) {
	d := &Daemon{}
	d.checkOnDemandScans()

	// The guard must not have been left held by the early return.
	if !d.tryBeginScan() {
		t.Fatal("checkOnDemandScans leaked the scan reservation on the nil-client path")
	}
	d.endScan()
}
