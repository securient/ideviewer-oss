package secrets

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// targetFiles are the filenames to scan for secrets.
var targetFiles = []string{
	".env",
	".env.local",
	".env.development",
	".env.production",
	".env.test",
	".envrc",
	"config.env",
	".secrets",
	"secrets.env",
}

// searchDirs are subdirectories of home to search (empty string = home itself).
var searchDirs = []string{
	"",
	"Documents",
	"Projects",
	"Development",
	"dev",
	"projects",
	"code",
	"src",
	"work",
	"workspace",
	"repos",
	"git",
	"github",
}

// Scanner scans for plaintext secrets in configuration files.
type Scanner struct {
	MaxDepth   int
	ScanHidden bool
	HomeDir    string
}

// NewScanner creates a Scanner with sensible defaults.
func NewScanner() *Scanner {
	home, _ := os.UserHomeDir()
	return &Scanner{
		MaxDepth:   5,
		ScanHidden: false,
		HomeDir:    home,
	}
}

// Scan scans the home directory and additional paths for secrets.
func (s *Scanner) Scan(additionalPaths ...string) (*SecretsResult, error) {
	result := &SecretsResult{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	// Build list of directories to scan.
	var scanDirs []string
	for _, subdir := range searchDirs {
		var dir string
		if subdir == "" {
			dir = s.HomeDir
		} else {
			dir = filepath.Join(s.HomeDir, subdir)
		}
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			scanDirs = append(scanDirs, dir)
		}
	}

	for _, p := range additionalPaths {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			scanDirs = append(scanDirs, p)
		}
	}

	// Scan each directory for .env files.
	for _, dir := range scanDirs {
		s.scanDirectory(dir, result, 0)
	}

	// Scan git history for secrets.
	for _, dir := range scanDirs {
		s.scanGitRepos(dir, result, 0)
	}

	// Fill computed fields.
	result.TotalFindings = len(result.Findings)
	for _, f := range result.Findings {
		if f.Severity == "critical" {
			result.CriticalCount++
		}
	}

	return result, nil
}

// ScanStaged scans git staged files for secrets (for pre-commit hook).
func (s *Scanner) ScanStaged() (*SecretsResult, error) {
	result := &SecretsResult{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", "diff", "--cached", "--diff-filter=ACMR", "-p")
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.Output()
	if err != nil {
		return result, nil // Not in a git repo or no staged files.
	}

	s.parseStagedDiff(string(out), result)

	result.TotalFindings = len(result.Findings)
	for _, f := range result.Findings {
		if f.Severity == "critical" {
			result.CriticalCount++
		}
	}

	return result, nil
}

// parseStagedDiff parses git diff --cached output for secrets.
func (s *Scanner) parseStagedDiff(output string, result *SecretsResult) {
	var currentFile string

	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "+++ b/") {
			currentFile = line[6:]
			continue
		}

		if !strings.HasPrefix(line, "+") || strings.HasPrefix(line, "+++") {
			continue
		}
		if currentFile == "" {
			continue
		}

		// Only scan target files.
		base := filepath.Base(currentFile)
		isTarget := false
		for _, tf := range targetFiles {
			if base == tf {
				isTarget = true
				break
			}
		}
		if !isTarget {
			continue
		}

		addedLine := strings.TrimSpace(line[1:])
		if addedLine == "" || strings.HasPrefix(addedLine, "#") || !strings.Contains(addedLine, "=") {
			continue
		}

		key, value := parseEnvLine(addedLine)
		if value == "" {
			continue
		}

		finding := checkEthPrivateKey(currentFile, key, value, 0)
		if finding == nil {
			finding = checkMnemonic(currentFile, key, value, 0)
		}
		if finding == nil {
			finding = checkAWSCredentials(currentFile, key, value, 0)
		}
		if finding != nil {
			finding.Source = "staged"
			result.Findings = append(result.Findings, *finding)
		}
	}
}

// scanDirectory recursively scans a directory for .env files.
func (s *Scanner) scanDirectory(directory string, result *SecretsResult, depth int) {
	if depth > s.MaxDepth {
		return
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		return
	}

	for _, entry := range entries {
		name := entry.Name()
		fullPath := filepath.Join(directory, name)

		if entry.IsDir() {
			if strings.HasPrefix(name, ".") && !s.ScanHidden {
				continue
			}
			if isSkipDir(name) {
				continue
			}
			s.scanDirectory(fullPath, result, depth+1)
			continue
		}

		if entry.Type().IsRegular() {
			for _, tf := range targetFiles {
				if name == tf {
					s.scanEnvFile(fullPath, result)
					break
				}
			}
		}
	}
}

// scanEnvFile scans a single .env file for secrets.
func (s *Scanner) scanEnvFile(filePath string, result *SecretsResult) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		result.Errors = append(result.Errors, "Error scanning "+filePath+": "+err.Error())
		return
	}

	result.ScannedPaths = append(result.ScannedPaths, filePath)

	lines := strings.Split(string(data), "\n")
	for lineNum, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}

		key, value := parseEnvLine(line)
		if value == "" {
			continue
		}

		finding := checkEthPrivateKey(filePath, key, value, lineNum+1)
		if finding != nil {
			result.Findings = append(result.Findings, *finding)
			continue
		}

		finding = checkMnemonic(filePath, key, value, lineNum+1)
		if finding != nil {
			result.Findings = append(result.Findings, *finding)
			continue
		}

		finding = checkAWSCredentials(filePath, key, value, lineNum+1)
		if finding != nil {
			result.Findings = append(result.Findings, *finding)
		}
	}
}
