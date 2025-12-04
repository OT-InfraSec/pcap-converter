// Package version provides application version information.
// The version can be set at build time using ldflags:
//
//	go build -ldflags "-X github.com/InfraSecConsult/pcap-importer-go/internal/version.Version=v1.0.0" ./cmd/importer
//
// If not set at build time, it falls back to reading a VERSION file at the repository root,
// or defaults to "dev" if neither is available.
package version

import (
	"os"
	"strings"
)

// Version is the application version. Set at build time via ldflags.
// Example: go build -ldflags "-X github.com/InfraSecConsult/pcap-importer-go/internal/version.Version=v1.0.0"
var Version = ""

// CommitHash is the git commit hash. Set at build time via ldflags.
// Example: go build -ldflags "-X github.com/InfraSecConsult/pcap-importer-go/internal/version.CommitHash=$(git rev-parse --short HEAD)"
var CommitHash = ""

// BuildTime is the build timestamp. Set at build time via ldflags.
// Example: go build -ldflags "-X github.com/InfraSecConsult/pcap-importer-go/internal/version.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
var BuildTime = ""

// GetVersion returns the application version.
// Priority:
// 1. Build-time embedded version (ldflags)
// 2. VERSION file in current directory or parent directories
// 3. "dev" as fallback
func GetVersion() string {
	if Version != "" {
		return Version
	}

	// Try to read VERSION file from current directory or parent
	for _, path := range []string{"VERSION", "../VERSION", "../../VERSION"} {
		if content, err := os.ReadFile(path); err == nil {
			v := strings.TrimSpace(string(content))
			if v != "" {
				return v
			}
		}
	}

	return "dev"
}

// GetFullVersion returns version with commit hash if available
func GetFullVersion() string {
	v := GetVersion()
	if CommitHash != "" {
		v += "+" + CommitHash
	}
	return v
}

// GetBuildInfo returns a map with all build information
func GetBuildInfo() map[string]string {
	return map[string]string{
		"version":    GetVersion(),
		"commitHash": CommitHash,
		"buildTime":  BuildTime,
	}
}
