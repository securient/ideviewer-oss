package aitools

import (
	"context"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// aiProcessNames are process names associated with AI tools and MCP server runtimes.
var aiProcessNames = map[string]bool{
	"claude":   true,
	"cursor":   true,
	"openclaw": true,
	"clawdbot": true,
	"node":     true,
	"npx":      true,
	"deno":     true,
	"bun":      true,
}

// scanOpenPorts discovers listening ports from AI-related processes.
func scanOpenPorts() []OpenPort {
	if runtime.GOOS == "windows" {
		return scanOpenPortsWindows()
	}
	return scanOpenPortsUnix()
}

func scanOpenPortsUnix() []OpenPort {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "lsof", "-i", "-P", "-n", "-sTCP:LISTEN").Output()
	if err != nil {
		return nil
	}

	var ports []OpenPort
	// lsof output: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
	// NAME is like: *:3000 or 127.0.0.1:8080
	portRegex := regexp.MustCompile(`:(\d+)$`)

	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}

		processName := strings.ToLower(fields[0])
		if !aiProcessNames[processName] {
			continue
		}

		name := fields[len(fields)-1] // Last field is the address:port
		matches := portRegex.FindStringSubmatch(name)
		if len(matches) < 2 {
			continue
		}

		port, err := strconv.Atoi(matches[1])
		if err != nil {
			continue
		}

		// Determine protocol from NODE field (field 7)
		proto := "tcp"
		if len(fields) > 7 && strings.ToLower(fields[7]) == "udp" {
			proto = "udp"
		}

		ports = append(ports, OpenPort{
			Port:    port,
			Process: fields[0], // Original case
			Proto:   proto,
		})
	}

	return deduplicatePorts(ports)
}

func scanOpenPortsWindows() []OpenPort {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get listening ports with PIDs
	netstatOut, err := exec.CommandContext(ctx, "netstat", "-ano").Output()
	if err != nil {
		return nil
	}

	// Get process list to map PID -> process name
	tasklistOut, _ := exec.CommandContext(ctx, "tasklist", "/FO", "CSV", "/NH").Output()
	pidToName := make(map[string]string)
	for _, line := range strings.Split(string(tasklistOut), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Format: "process.exe","PID","Session Name","Session#","Mem Usage"
		fields := strings.Split(line, ",")
		if len(fields) >= 2 {
			name := strings.Trim(fields[0], "\"")
			pid := strings.Trim(fields[1], "\"")
			pidToName[pid] = name
		}
	}

	var ports []OpenPort
	for _, line := range strings.Split(string(netstatOut), "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "LISTENING") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		// Fields: Proto, Local Address, Foreign Address, State, PID
		localAddr := fields[1]
		pid := fields[4]

		// Extract port from address (e.g., "0.0.0.0:3000" or "[::]:3000")
		lastColon := strings.LastIndex(localAddr, ":")
		if lastColon == -1 {
			continue
		}
		portStr := localAddr[lastColon+1:]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}

		processName := pidToName[pid]
		if processName == "" {
			continue
		}

		// Filter to AI-related processes
		nameLower := strings.ToLower(strings.TrimSuffix(processName, ".exe"))
		if !aiProcessNames[nameLower] {
			continue
		}

		proto := strings.ToLower(fields[0])
		ports = append(ports, OpenPort{
			Port:    port,
			Process: processName,
			Proto:   proto,
		})
	}

	return deduplicatePorts(ports)
}

func deduplicatePorts(ports []OpenPort) []OpenPort {
	seen := make(map[string]bool)
	var result []OpenPort
	for _, p := range ports {
		key := p.Process + ":" + strconv.Itoa(p.Port) + ":" + p.Proto
		if !seen[key] {
			seen[key] = true
			result = append(result, p)
		}
	}
	return result
}
