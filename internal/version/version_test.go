package version

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetVersion_DefaultsToDevWhenNoVersionSet(t *testing.T) {
	// Save and clear the package variable
	origVersion := Version
	Version = ""
	defer func() { Version = origVersion }()

	// Change to a temp directory where there's no VERSION file
	origDir, _ := os.Getwd()
	tmpDir := t.TempDir()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	v := GetVersion()
	if v != "dev" {
		t.Errorf("Expected 'dev', got '%s'", v)
	}
}

func TestGetVersion_UsesBuildTimeVersion(t *testing.T) {
	// Save and set the package variable
	origVersion := Version
	Version = "v1.2.3"
	defer func() { Version = origVersion }()

	v := GetVersion()
	if v != "v1.2.3" {
		t.Errorf("Expected 'v1.2.3', got '%s'", v)
	}
}

func TestGetVersion_ReadsVersionFile(t *testing.T) {
	// Save and clear the package variable
	origVersion := Version
	Version = ""
	defer func() { Version = origVersion }()

	// Change to temp directory and create VERSION file
	origDir, _ := os.Getwd()
	tmpDir := t.TempDir()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	// Create VERSION file
	versionFile := filepath.Join(tmpDir, "VERSION")
	err := os.WriteFile(versionFile, []byte("v2.0.0\n"), 0644)
	if err != nil {
		t.Fatalf("Failed to write VERSION file: %v", err)
	}

	v := GetVersion()
	if v != "v2.0.0" {
		t.Errorf("Expected 'v2.0.0', got '%s'", v)
	}
}

func TestGetFullVersion_WithCommitHash(t *testing.T) {
	// Save and set the package variables
	origVersion := Version
	origCommit := CommitHash
	Version = "v1.0.0"
	CommitHash = "abc1234"
	defer func() {
		Version = origVersion
		CommitHash = origCommit
	}()

	v := GetFullVersion()
	if v != "v1.0.0+abc1234" {
		t.Errorf("Expected 'v1.0.0+abc1234', got '%s'", v)
	}
}

func TestGetFullVersion_WithoutCommitHash(t *testing.T) {
	// Save and set the package variables
	origVersion := Version
	origCommit := CommitHash
	Version = "v1.0.0"
	CommitHash = ""
	defer func() {
		Version = origVersion
		CommitHash = origCommit
	}()

	v := GetFullVersion()
	if v != "v1.0.0" {
		t.Errorf("Expected 'v1.0.0', got '%s'", v)
	}
}

func TestGetBuildInfo(t *testing.T) {
	// Save and set the package variables
	origVersion := Version
	origCommit := CommitHash
	origBuildTime := BuildTime
	Version = "v3.0.0"
	CommitHash = "def5678"
	BuildTime = "2024-01-01T00:00:00Z"
	defer func() {
		Version = origVersion
		CommitHash = origCommit
		BuildTime = origBuildTime
	}()

	info := GetBuildInfo()
	if info["version"] != "v3.0.0" {
		t.Errorf("Expected version 'v3.0.0', got '%s'", info["version"])
	}
	if info["commitHash"] != "def5678" {
		t.Errorf("Expected commitHash 'def5678', got '%s'", info["commitHash"])
	}
	if info["buildTime"] != "2024-01-01T00:00:00Z" {
		t.Errorf("Expected buildTime '2024-01-01T00:00:00Z', got '%s'", info["buildTime"])
	}
}
