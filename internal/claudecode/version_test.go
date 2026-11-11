package claudecode

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name          string
		cliVersion    string
		pluginVersion string
		want          VersionStatus
	}{
		{
			name:          "exact match with v prefix",
			cliVersion:    "v0.2.0",
			pluginVersion: "0.2.0",
			want:          VersionMatch,
		},
		{
			name:          "exact match without v prefix",
			cliVersion:    "0.2.0",
			pluginVersion: "0.2.0",
			want:          VersionMatch,
		},
		{
			name:          "CLI older major",
			cliVersion:    "v0.1.0",
			pluginVersion: "0.2.0",
			want:          CLIOlder,
		},
		{
			name:          "CLI newer major",
			cliVersion:    "v0.3.0",
			pluginVersion: "0.2.0",
			want:          CLINewer,
		},
		{
			name:          "CLI older minor",
			cliVersion:    "v0.1.5",
			pluginVersion: "0.2.0",
			want:          CLIOlder,
		},
		{
			name:          "CLI newer minor",
			cliVersion:    "v0.3.1",
			pluginVersion: "0.2.0",
			want:          CLINewer,
		},
		{
			name:          "CLI older patch",
			cliVersion:    "v0.2.0",
			pluginVersion: "0.2.1",
			want:          CLIOlder,
		},
		{
			name:          "CLI newer patch",
			cliVersion:    "v0.2.2",
			pluginVersion: "0.2.1",
			want:          CLINewer,
		},
		{
			name:          "prerelease counts as older",
			cliVersion:    "v0.2.0-rc.1",
			pluginVersion: "0.2.0",
			want:          CLIOlder,
		},
		{
			name:          "pseudo-version counts as older than base",
			cliVersion:    "v0.1.1-0.20261111-abcdef",
			pluginVersion: "0.2.0",
			want:          CLIOlder,
		},
		{
			name:          "pseudo-version with matching base counts as older",
			cliVersion:    "v0.2.0-0.20261111-abcdef",
			pluginVersion: "0.2.0",
			want:          CLIOlder,
		},
		{
			name:          "devel is unknown",
			cliVersion:    "devel",
			pluginVersion: "0.2.0",
			want:          CLIUnknown,
		},
		{
			name:          "devel+abc is unknown",
			cliVersion:    "devel+abc",
			pluginVersion: "0.2.0",
			want:          CLIUnknown,
		},
		{
			name:          "devel+abc1234-dirty is unknown",
			cliVersion:    "devel+abc1234-dirty",
			pluginVersion: "0.2.0",
			want:          CLIUnknown,
		},
		{
			name:          "unparsable CLI version is unknown",
			cliVersion:    "not-a-version",
			pluginVersion: "0.2.0",
			want:          CLIUnknown,
		},
		{
			name:          "unparsable plugin version is unknown",
			cliVersion:    "v0.2.0",
			pluginVersion: "not-a-version",
			want:          CLIUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CompareVersions(tt.cliVersion, tt.pluginVersion)
			if got != tt.want {
				t.Errorf("CompareVersions(%q, %q) = %v, want %v",
					tt.cliVersion, tt.pluginVersion, got, tt.want)
			}
		})
	}
}

func TestPluginVersion(t *testing.T) {
	t.Run("reads plugin.json", func(t *testing.T) {
		tmpDir := t.TempDir()
		pluginDir := filepath.Join(tmpDir, ".claude-plugin")
		if err := os.Mkdir(pluginDir, 0o755); err != nil {
			t.Fatal(err)
		}

		pluginJSON := `{
  "name": "test-plugin",
  "version": "1.2.3",
  "description": "Test plugin"
}`
		if err := os.WriteFile(filepath.Join(pluginDir, "plugin.json"), []byte(pluginJSON), 0o644); err != nil {
			t.Fatal(err)
		}

		version, err := PluginVersion(tmpDir)
		if err != nil {
			t.Fatalf("PluginVersion() error = %v", err)
		}
		if version != "1.2.3" {
			t.Errorf("PluginVersion() = %q, want %q", version, "1.2.3")
		}
	})

	t.Run("returns error for missing file", func(t *testing.T) {
		tmpDir := t.TempDir()
		_, err := PluginVersion(tmpDir)
		if err == nil {
			t.Fatal("PluginVersion() expected error, got nil")
		}
	})

	t.Run("returns error for malformed JSON", func(t *testing.T) {
		tmpDir := t.TempDir()
		pluginDir := filepath.Join(tmpDir, ".claude-plugin")
		if err := os.Mkdir(pluginDir, 0o755); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(pluginDir, "plugin.json"), []byte("{not valid json"), 0o644); err != nil {
			t.Fatal(err)
		}

		_, err := PluginVersion(tmpDir)
		if err == nil {
			t.Fatal("PluginVersion() expected error for malformed JSON, got nil")
		}
	})
}

func TestSessionStartVersionWarning(t *testing.T) {
	t.Run("warns when CLI is older", func(t *testing.T) {
		tmpDir := t.TempDir()
		pluginDir := filepath.Join(tmpDir, ".claude-plugin")
		if err := os.Mkdir(pluginDir, 0o755); err != nil {
			t.Fatal(err)
		}

		pluginJSON := `{
  "name": "skill-trust",
  "version": "0.2.0",
  "description": "Test"
}`
		if err := os.WriteFile(filepath.Join(pluginDir, "plugin.json"), []byte(pluginJSON), 0o644); err != nil {
			t.Fatal(err)
		}

		cfg := Config{
			PluginRoot: tmpDir,
			CLIVersion: "v0.1.0",
			Locations:  Locations{},
		}

		input := HookInput{
			SessionID:     "test",
			HookEventName: "SessionStart",
		}

		result := SessionStart(cfg, input)
		if result == nil {
			t.Fatal("SessionStart() returned nil")
		}

		var response map[string]interface{}
		if err := json.Unmarshal(result, &response); err != nil {
			t.Fatal(err)
		}

		systemMessage, ok := response["systemMessage"].(string)
		if !ok {
			t.Fatal("systemMessage not found in response")
		}

		if !strings.Contains(systemMessage, "is older than") {
			t.Errorf("systemMessage should contain version warning, got: %q", systemMessage)
		}
	})

	t.Run("warns when CLI is newer", func(t *testing.T) {
		tmpDir := t.TempDir()
		pluginDir := filepath.Join(tmpDir, ".claude-plugin")
		if err := os.Mkdir(pluginDir, 0o755); err != nil {
			t.Fatal(err)
		}

		pluginJSON := `{
  "name": "skill-trust",
  "version": "0.2.0",
  "description": "Test"
}`
		if err := os.WriteFile(filepath.Join(pluginDir, "plugin.json"), []byte(pluginJSON), 0o644); err != nil {
			t.Fatal(err)
		}

		cfg := Config{
			PluginRoot: tmpDir,
			CLIVersion: "v0.3.0",
			Locations:  Locations{},
		}

		input := HookInput{
			SessionID:     "test",
			HookEventName: "SessionStart",
		}

		result := SessionStart(cfg, input)
		if result == nil {
			t.Fatal("SessionStart() returned nil")
		}

		var response map[string]interface{}
		if err := json.Unmarshal(result, &response); err != nil {
			t.Fatal(err)
		}

		systemMessage, ok := response["systemMessage"].(string)
		if !ok {
			t.Fatal("systemMessage not found in response")
		}

		if !strings.Contains(systemMessage, "is newer than") {
			t.Errorf("systemMessage should contain version warning, got: %q", systemMessage)
		}
	})

	t.Run("warns when CLI is unknown", func(t *testing.T) {
		tmpDir := t.TempDir()
		pluginDir := filepath.Join(tmpDir, ".claude-plugin")
		if err := os.Mkdir(pluginDir, 0o755); err != nil {
			t.Fatal(err)
		}

		pluginJSON := `{
  "name": "skill-trust",
  "version": "0.2.0",
  "description": "Test"
}`
		if err := os.WriteFile(filepath.Join(pluginDir, "plugin.json"), []byte(pluginJSON), 0o644); err != nil {
			t.Fatal(err)
		}

		cfg := Config{
			PluginRoot: tmpDir,
			CLIVersion: "devel+abc1234",
			Locations:  Locations{},
		}

		input := HookInput{
			SessionID:     "test",
			HookEventName: "SessionStart",
		}

		result := SessionStart(cfg, input)
		if result == nil {
			t.Fatal("SessionStart() returned nil")
		}

		var response map[string]interface{}
		if err := json.Unmarshal(result, &response); err != nil {
			t.Fatal(err)
		}

		systemMessage, ok := response["systemMessage"].(string)
		if !ok {
			t.Fatal("systemMessage not found in response")
		}

		if !strings.Contains(systemMessage, "is unknown") {
			t.Errorf("systemMessage should contain unknown version warning, got: %q", systemMessage)
		}
	})

	t.Run("no warning when versions match", func(t *testing.T) {
		tmpDir := t.TempDir()
		pluginDir := filepath.Join(tmpDir, ".claude-plugin")
		if err := os.Mkdir(pluginDir, 0o755); err != nil {
			t.Fatal(err)
		}

		pluginJSON := `{
  "name": "skill-trust",
  "version": "0.2.0",
  "description": "Test"
}`
		if err := os.WriteFile(filepath.Join(pluginDir, "plugin.json"), []byte(pluginJSON), 0o644); err != nil {
			t.Fatal(err)
		}

		cfg := Config{
			PluginRoot: tmpDir,
			CLIVersion: "v0.2.0",
			Locations:  Locations{},
		}

		input := HookInput{
			SessionID:     "test",
			HookEventName: "SessionStart",
		}

		result := SessionStart(cfg, input)
		if result == nil {
			t.Fatal("SessionStart() returned nil")
		}

		var response map[string]interface{}
		if err := json.Unmarshal(result, &response); err != nil {
			t.Fatal(err)
		}

		systemMessage, ok := response["systemMessage"].(string)
		if !ok {
			t.Fatal("systemMessage not found in response")
		}

		// Should not contain version-related warnings
		if strings.Contains(systemMessage, "older than") || strings.Contains(systemMessage, "newer than") || strings.Contains(systemMessage, "is unknown") {
			t.Errorf("systemMessage should not contain version warning when versions match, got: %q", systemMessage)
		}
	})

	t.Run("no warning when PluginRoot is empty", func(t *testing.T) {
		cfg := Config{
			PluginRoot: "",
			CLIVersion: "v0.1.0",
			Locations:  Locations{},
		}

		input := HookInput{
			SessionID:     "test",
			HookEventName: "SessionStart",
		}

		result := SessionStart(cfg, input)
		if result == nil {
			t.Fatal("SessionStart() returned nil")
		}

		var response map[string]interface{}
		if err := json.Unmarshal(result, &response); err != nil {
			t.Fatal(err)
		}

		systemMessage, ok := response["systemMessage"].(string)
		if !ok {
			t.Fatal("systemMessage not found in response")
		}

		// Should not contain version-related warnings
		if strings.Contains(systemMessage, "older than") || strings.Contains(systemMessage, "newer than") || strings.Contains(systemMessage, "is unknown") {
			t.Errorf("systemMessage should not contain version warning when PluginRoot is empty, got: %q", systemMessage)
		}
	})

	t.Run("short warning for unreadable plugin.json", func(t *testing.T) {
		cfg := Config{
			PluginRoot: "/nonexistent/path",
			CLIVersion: "v0.2.0",
			Locations:  Locations{},
		}

		input := HookInput{
			SessionID:     "test",
			HookEventName: "SessionStart",
		}

		result := SessionStart(cfg, input)
		if result == nil {
			t.Fatal("SessionStart() returned nil")
		}

		var response map[string]interface{}
		if err := json.Unmarshal(result, &response); err != nil {
			t.Fatal(err)
		}

		systemMessage, ok := response["systemMessage"].(string)
		if !ok {
			t.Fatal("systemMessage not found in response")
		}

		if !strings.Contains(systemMessage, "cannot read plugin version") {
			t.Errorf("systemMessage should contain error message for unreadable plugin.json, got: %q", systemMessage)
		}
	})
}
