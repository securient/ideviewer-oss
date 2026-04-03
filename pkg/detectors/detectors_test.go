package detectors

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindExecutable_NonexistentBinary(t *testing.T) {
	result := FindExecutable("this-binary-definitely-does-not-exist-xyz123")
	if result != "" {
		t.Errorf("FindExecutable returned %q for nonexistent binary, want empty", result)
	}
}

func TestFindExecutable_KnownBinary(t *testing.T) {
	// "ls" should exist on any unix system.
	result := FindExecutable("ls")
	if result == "" {
		t.Error("FindExecutable returned empty for 'ls', expected a path")
	}
}

func TestFindExecutable_AdditionalPaths(t *testing.T) {
	// Create a temp file to use as additional path.
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "fake-binary")
	os.WriteFile(tmpFile, []byte("#!/bin/sh"), 0755)

	result := FindExecutable("nonexistent-xyz", tmpFile)
	if result != tmpFile {
		t.Errorf("FindExecutable = %q, want %q", result, tmpFile)
	}
}

func TestGetVersion_Echo(t *testing.T) {
	// Use echo as a known command that produces output.
	result := GetVersion("echo", "hello-version-test")
	if result != "hello-version-test" {
		t.Errorf("GetVersion = %q, want %q", result, "hello-version-test")
	}
}

func TestGetVersion_NonexistentBinary(t *testing.T) {
	result := GetVersion("nonexistent-binary-xyz123")
	if result != "" {
		t.Errorf("GetVersion = %q for nonexistent binary, want empty", result)
	}
}

func TestPathExists_ExistingPath(t *testing.T) {
	tmpDir := t.TempDir()
	if !PathExists(tmpDir) {
		t.Errorf("PathExists(%q) = false, want true", tmpDir)
	}
}

func TestPathExists_NonexistentPath(t *testing.T) {
	if PathExists("/this/path/does/not/exist/xyz123") {
		t.Error("PathExists returned true for nonexistent path")
	}
}

func TestExpandPath_Tilde(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home dir")
	}

	expanded := ExpandPath("~/test-path")
	expected := filepath.Join(home, "test-path")
	if expanded != expected {
		t.Errorf("ExpandPath(~/test-path) = %q, want %q", expanded, expected)
	}
}

func TestExpandPath_NoTilde(t *testing.T) {
	expanded := ExpandPath("/absolute/path")
	if expanded != "/absolute/path" {
		t.Errorf("ExpandPath(/absolute/path) = %q, want /absolute/path", expanded)
	}
}

func TestHomeDir(t *testing.T) {
	home := HomeDir()
	if home == "" {
		t.Error("HomeDir() returned empty string")
	}
}

func TestPlatformKey(t *testing.T) {
	key := PlatformKey()
	if key == "" {
		t.Error("PlatformKey() returned empty string")
	}
	// On macOS where this test runs.
	validKeys := map[string]bool{"darwin": true, "linux": true, "windows": true}
	if !validKeys[key] {
		t.Errorf("PlatformKey() = %q, expected darwin/linux/windows", key)
	}
}
