// Package behavior is an experimental, single-OS SPIKE of runtime/behavioral
// telemetry (Phase 3 B6) — deliberately NOT the full platform.
//
// The full B6 (macOS Endpoint Security Framework, Windows ETW, Linux eBPF)
// needs a notarized system extension + an Apple-granted entitlement, kernel
// integration, and per-OS test labs — months of work that can't be validated in
// local docker. This spike proves the core idea cheaply and safely from
// userspace: enumerate the process tree and flag a process that (a) runs a
// known-suspicious command (reverse shell, pipe-to-shell, raw socket one-liner)
// AND (b) has an IDE / extension-host process as an ancestor — i.e. an
// extension spawning a shell home. The detection logic is pure and unit-tested;
// the kernel-grade, tamper-proof collection is the follow-up.
package behavior

import (
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// Process is one node of the process tree.
type Process struct {
	PID  int
	PPID int
	Comm string // executable name
	Args string // full command line
}

// Finding is a suspicious process whose ancestor is an IDE/extension host.
type Finding struct {
	PID       int
	Comm      string
	Args      string
	Reason    string // which suspicious pattern matched
	AncestorPID  int
	AncestorComm string // the IDE/extension-host ancestor
}

// suspiciousPatterns are substrings that strongly indicate a shell/exfil
// payload rather than normal dev tooling.
var suspiciousPatterns = []struct{ frag, reason string }{
	{"/dev/tcp/", "bash /dev/tcp reverse shell"},
	{"bash -i", "interactive bash (reverse shell)"},
	{"sh -i", "interactive sh (reverse shell)"},
	{"nc -e", "netcat -e command execution"},
	{"ncat -e", "ncat -e command execution"},
	{"| sh", "pipe to shell"},
	{"|sh", "pipe to shell"},
	{"| bash", "pipe to bash"},
	{"|bash", "pipe to bash"},
	{"socket.socket", "python raw socket payload"},
	{"pty.spawn", "python pty.spawn shell"},
}

// ideAncestorMarkers identify an IDE or extension-host process.
var ideAncestorMarkers = []string{
	"Code Helper", "code", "codium", "cursor",
	"extensionhost", "--type=extensionhost",
	".vscode/extensions", ".vscode-server",
}

func matchSuspicious(args string) string {
	low := strings.ToLower(args)
	for _, p := range suspiciousPatterns {
		if strings.Contains(low, p.frag) {
			return p.reason
		}
	}
	return ""
}

func isIDEAncestor(p Process) bool {
	hay := strings.ToLower(p.Comm + " " + p.Args)
	for _, m := range ideAncestorMarkers {
		if strings.Contains(hay, strings.ToLower(m)) {
			return true
		}
	}
	return false
}

// DetectSuspicious flags processes that run a suspicious command and descend
// from an IDE/extension-host process. Pure — feed it any process list.
func DetectSuspicious(procs []Process) []Finding {
	byPID := make(map[int]Process, len(procs))
	for _, p := range procs {
		byPID[p.PID] = p
	}

	var findings []Finding
	for _, p := range procs {
		reason := matchSuspicious(p.Args)
		if reason == "" {
			continue
		}
		// Walk ancestors looking for an IDE / extension host.
		seen := map[int]bool{}
		cur := p
		for cur.PPID != 0 && !seen[cur.PPID] {
			seen[cur.PPID] = true
			parent, ok := byPID[cur.PPID]
			if !ok {
				break
			}
			if isIDEAncestor(parent) {
				findings = append(findings, Finding{
					PID: p.PID, Comm: p.Comm, Args: p.Args, Reason: reason,
					AncestorPID: parent.PID, AncestorComm: parent.Comm,
				})
				break
			}
			cur = parent
		}
	}
	return findings
}

// EnumerateProcesses lists processes via `ps` (darwin/linux). Best-effort; the
// kernel-grade collector is the B6 follow-up. Returns nil on unsupported OS.
func EnumerateProcesses() ([]Process, error) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return nil, nil
	}
	out, err := exec.Command("ps", "-axo", "pid=,ppid=,comm=,args=").Output()
	if err != nil {
		return nil, err
	}
	return parsePS(string(out)), nil
}

// parsePS parses `ps -axo pid=,ppid=,comm=,args=` output. Exposed for tests.
func parsePS(out string) []Process {
	var procs []Process
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		pid, err1 := strconv.Atoi(fields[0])
		ppid, err2 := strconv.Atoi(fields[1])
		if err1 != nil || err2 != nil {
			continue
		}
		comm := fields[2]
		// args is everything from field 3 on (the comm column may repeat in args).
		args := ""
		if len(fields) > 3 {
			args = strings.Join(fields[3:], " ")
		}
		procs = append(procs, Process{PID: pid, PPID: ppid, Comm: comm, Args: args})
	}
	return procs
}
