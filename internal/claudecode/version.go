package claudecode

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// VersionStatus represents the comparison result between CLI and plugin versions.
type VersionStatus int

const (
	VersionMatch VersionStatus = iota
	CLIOlder
	CLINewer
	CLIUnknown
)

// CompareVersions compares CLI and plugin versions.
// It strips leading 'v', compares major.minor.patch numerically.
// Go pseudo-versions and prereleases are treated as older than their base.
// Development versions (devel*) or unparsable versions return CLIUnknown.
func CompareVersions(cliVersion, pluginVersion string) VersionStatus {
	// Strip leading 'v'
	cliVersion = strings.TrimPrefix(cliVersion, "v")
	pluginVersion = strings.TrimPrefix(pluginVersion, "v")

	// Check for devel versions
	if strings.HasPrefix(cliVersion, "devel") {
		return CLIUnknown
	}

	// Parse versions
	cliParts, cliPrerelease := parseVersion(cliVersion)
	pluginParts, pluginPrerelease := parseVersion(pluginVersion)

	// If either version is unparsable, return unknown
	if cliParts == nil || pluginParts == nil {
		return CLIUnknown
	}

	// Compare major.minor.patch
	for i := 0; i < 3; i++ {
		if cliParts[i] < pluginParts[i] {
			return CLIOlder
		}
		if cliParts[i] > pluginParts[i] {
			return CLINewer
		}
	}

	// Versions are equal in major.minor.patch
	// If CLI has prerelease/pseudo-version but plugin doesn't, CLI is older
	if cliPrerelease && !pluginPrerelease {
		return CLIOlder
	}
	if !cliPrerelease && pluginPrerelease {
		return CLINewer
	}

	return VersionMatch
}

// parseVersion parses a version string into [major, minor, patch] and a prerelease flag.
// Returns nil if the version cannot be parsed.
func parseVersion(version string) ([]int, bool) {
	// Handle pseudo-versions like "0.1.1-0.20261111-abcdef"
	// and prereleases like "0.2.0-rc.1"
	hasPrerelease := false
	if idx := strings.IndexAny(version, "-+"); idx != -1 {
		hasPrerelease = true
		version = version[:idx]
	}

	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return nil, false
	}

	result := make([]int, 3)
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, false
		}
		result[i] = n
	}

	return result, hasPrerelease
}

// PluginVersion reads the version from <pluginRoot>/.claude-plugin/plugin.json.
func PluginVersion(pluginRoot string) (string, error) {
	pluginJSONPath := filepath.Join(pluginRoot, ".claude-plugin", "plugin.json")
	data, err := os.ReadFile(pluginJSONPath)
	if err != nil {
		return "", fmt.Errorf("reading plugin.json: %w", err)
	}

	var plugin struct {
		Version string `json:"version"`
	}

	if err := json.Unmarshal(data, &plugin); err != nil {
		return "", fmt.Errorf("parsing plugin.json: %w", err)
	}

	if plugin.Version == "" {
		return "", fmt.Errorf("plugin.json missing version field")
	}

	return plugin.Version, nil
}

// versionWarning returns a warning message if CLI and plugin versions differ.
// Returns empty string if PluginRoot is empty or versions match.
func versionWarning(cfg Config) string {
	if cfg.PluginRoot == "" {
		return ""
	}

	pluginVersion, err := PluginVersion(cfg.PluginRoot)
	if err != nil {
		return fmt.Sprintf("cannot read plugin version: %v", err)
	}

	status := CompareVersions(cfg.CLIVersion, pluginVersion)

	switch status {
	case CLIOlder:
		return fmt.Sprintf("skill-trust CLI %s is older than the Claude Code plugin (%s); update with: go install github.com/redhat-et/skill-trust/cmd/skill-trust@v%s",
			cfg.CLIVersion, pluginVersion, pluginVersion)
	case CLINewer:
		return fmt.Sprintf("skill-trust CLI %s is newer than the Claude Code plugin (%s); update the plugin with /plugin update skill-trust",
			cfg.CLIVersion, pluginVersion)
	case CLIUnknown:
		return fmt.Sprintf("skill-trust CLI version %s is unknown (development build); expected v%s",
			cfg.CLIVersion, pluginVersion)
	case VersionMatch:
		return ""
	}

	return ""
}
