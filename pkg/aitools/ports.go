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
	// On Windows, use netstat as fallback
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "netstat", "-ano").Output()
	if err != nil {
		return nil
	}

	// This is a simplified implementation; Windows port scanning
	// would need tasklist correlation for process names
	_ = out
	return nil
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
