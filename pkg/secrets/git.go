package secrets

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// scanGitRepos finds git repos under a directory and scans their history.
func (s *Scanner) scanGitRepos(directory string, result *SecretsResult, depth int) {
	if depth > s.MaxDepth {
		return
	}

	gitDir := filepath.Join(directory, ".git")
	if info, err := os.Stat(gitDir); err == nil && info.IsDir() {
		s.scanGitHistory(directory, result)
		return // Don't recurse into subdirs of a git repo.
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".") || isSkipDir(name) {
			continue
		}
		s.scanGitRepos(filepath.Join(directory, name), result, depth+1)
	}
}

// isSkipDir returns true for directories that should be skipped during scanning.
func isSkipDir(name string) bool {
	switch name {
	case "node_modules", "venv", ".venv", "__pycache__", "vendor",
		"dist", "build", ".cache", "Library", "Applications", ".Trash":
		return true
	}
	return false
}

// scanGitHistory scans a git repo's history for secrets in .env files.
func (s *Scanner) scanGitHistory(repoPath string, result *SecretsResult) {
	result.ScannedPaths = append(result.ScannedPaths, "git:"+repoPath)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	args := []string{
		"-C", repoPath,
		"log", "--all", "--diff-filter=ACMR",
		"-p", "--max-count=500",
		"--format=COMMIT:%H|%an|%aI",
		"--",
	}
	args = append(args, targetFiles...)

	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")

	out, err := cmd.Output()
	if err != nil {
		return
	}

	s.parseGitDiff(string(out), repoPath, result)
}

// parseGitDiff parses git log -p output and checks added lines for secrets.
func (s *Scanner) parseGitDiff(output, repoPath string, result *SecretsResult) {
	var currentCommit, currentAuthor, currentDate, currentFile string
	seen := make(map[string]bool)

	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "COMMIT:") {
			parts := strings.SplitN(line[7:], "|", 3)
			if len(parts) == 3 {
				currentCommit = parts[0]
				currentAuthor = parts[1]
				currentDate = parts[2]
			}
			continue
		}

		if strings.HasPrefix(line, "+++ b/") {
			currentFile = line[6:]
			continue
		}

		if !strings.HasPrefix(line, "+") || strings.HasPrefix(line, "+++") {
			continue
		}
		if currentCommit == "" || currentFile == "" {
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
		if finding == nil {
			continue
		}

		dedupKey := currentCommit + ":" + currentFile + ":" + key
		if seen[dedupKey] {
			continue
		}
		seen[dedupKey] = true

		finding.Source = "git_history"
		finding.FilePath = currentFile
		finding.RepoPath = repoPath
		finding.CommitHash = currentCommit
		finding.CommitAuthor = currentAuthor
		finding.CommitDate = currentDate
		finding.Description = fmt.Sprintf(
			"[Git History] %s Found in commit %s by %s.",
			finding.Description, currentCommit[:min(8, len(currentCommit))], currentAuthor,
		)
		finding.Recommendation = fmt.Sprintf(
			"%s This secret was committed to git history and may still be accessible "+
				"even if the file has been deleted. Consider rotating this credential "+
				"and using 'git filter-branch' or BFG Repo-Cleaner to purge it from history.",
			finding.Recommendation,
		)

		result.Findings = append(result.Findings, *finding)
	}
}

// parseEnvLine parses a KEY=VALUE line from an env file.
func parseEnvLine(line string) (key, value string) {
	idx := strings.Index(line, "=")
	if idx < 0 {
		return "", ""
	}
	key = strings.TrimSpace(line[:idx])
	value = strings.TrimSpace(line[idx+1:])
	value = strings.Trim(value, `"'`)
	return key, value
}
