package daemon

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

// The Windows report behind these: IsRunning probed liveness with signal 0,
// which os.Process.Signal rejects outright on Windows. Every live daemon
// therefore looked dead — CreatePIDFile's duplicate guard never fired, and a
// machine could accumulate daemons, each holding whichever config it started
// with. processAlive is now platform-specific; these tests pin the contract
// both implementations must satisfy.

func TestProcessAlive_TrueForThisProcess(t *testing.T) {
	if !processAlive(os.Getpid()) {
		t.Fatal("processAlive reported the running test process as dead")
	}
}

func TestProcessAlive_FalseForImpossiblePIDs(t *testing.T) {
	for _, pid := range []int{0, -1} {
		if processAlive(pid) {
			t.Errorf("processAlive(%d) = true, want false", pid)
		}
	}
}

func TestIsRunning_TrueWhenPIDFileNamesThisProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ideviewer.pid")
	if err := os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if !IsRunning(path) {
		t.Fatal("IsRunning = false for a PID file naming this very process")
	}
}

func TestIsRunning_FalseForMissingOrGarbageFile(t *testing.T) {
	dir := t.TempDir()

	if IsRunning(filepath.Join(dir, "absent.pid")) {
		t.Error("IsRunning = true for a missing PID file")
	}

	garbage := filepath.Join(dir, "garbage.pid")
	if err := os.WriteFile(garbage, []byte("not-a-number"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if IsRunning(garbage) {
		t.Error("IsRunning = true for a PID file holding non-numeric content")
	}
}

func TestCreatePIDFile_RefusesASecondDaemon(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ideviewer.pid")

	if err := CreatePIDFile(path); err != nil {
		t.Fatalf("first CreatePIDFile: %v", err)
	}
	// The file now names this process, which is alive — a second daemon must
	// be refused rather than silently starting alongside the first.
	if err := CreatePIDFile(path); err == nil {
		t.Fatal("second CreatePIDFile succeeded; duplicate daemons are possible")
	}

	RemovePIDFile(path)
	if err := CreatePIDFile(path); err != nil {
		t.Fatalf("CreatePIDFile after removal: %v", err)
	}
}

// deadPID returns the PID of a process that has run and been reaped.
//
// Picking a large "surely unused" number instead would be wrong on Linux,
// where pid_t is int32: a value above 2^31 wraps negative and kill(2) reads a
// negative pid as a *process group*, so the liveness probe could succeed
// against an unrelated group.
func deadPID(t *testing.T) int {
	t.Helper()
	// The test binary itself, with a filter that matches no test: it exits
	// immediately and needs no external program, so this works on every OS.
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper process: %v", err)
	}
	pid := cmd.Process.Pid
	_ = cmd.Wait()
	return pid
}

func TestProcessAlive_FalseForAReapedProcess(t *testing.T) {
	if processAlive(deadPID(t)) {
		t.Fatal("processAlive reported an exited, reaped process as alive")
	}
}

func TestCreatePIDFile_ReplacesAStalePIDFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ideviewer.pid")

	stale := deadPID(t)
	if err := os.WriteFile(path, []byte(strconv.Itoa(stale)), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := CreatePIDFile(path); err != nil {
		t.Fatalf("CreatePIDFile over a stale file: %v", err)
	}

	pid, err := ReadPIDFile(path)
	if err != nil {
		t.Fatalf("ReadPIDFile: %v", err)
	}
	if pid != os.Getpid() {
		t.Errorf("PID file holds %d, want %d", pid, os.Getpid())
	}
}

func TestReadPIDFile(t *testing.T) {
	dir := t.TempDir()

	path := filepath.Join(dir, "ideviewer.pid")
	if err := os.WriteFile(path, []byte(" 1234 \n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	pid, err := ReadPIDFile(path)
	if err != nil {
		t.Fatalf("ReadPIDFile: %v", err)
	}
	if pid != 1234 {
		t.Errorf("pid = %d, want 1234", pid)
	}

	// os.IsNotExist must still match, because 'ideviewer stop' and
	// 'ideviewer status' distinguish "never started" from "unreadable".
	if _, err := ReadPIDFile(filepath.Join(dir, "absent.pid")); !os.IsNotExist(err) {
		t.Errorf("error for a missing file = %v, want an os.IsNotExist error", err)
	}
}
