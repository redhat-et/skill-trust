package claudecode

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// TestPluginFiles verifies that the Claude Code plugin files are well-formed
// and reference the correct hook events.
func TestPluginFiles(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	pluginDir := filepath.Join(repoRoot, "adapters", "claude-code")
	pluginJSONPath := filepath.Join(pluginDir, ".claude-plugin", "plugin.json")
	hooksJSONPath := filepath.Join(pluginDir, "hooks", "hooks.json")
	marketplaceJSONPath := filepath.Join(repoRoot, ".claude-plugin", "marketplace.json")

	// Expected hook events that the CLI registers
	validEvents := map[string]bool{
		"session-start":      true,
		"pre-tool-use":       true,
		"user-prompt-submit": true,
	}

	// Test plugin.json
	t.Run("PluginJSON", func(t *testing.T) {
		data, err := os.ReadFile(pluginJSONPath)
		if err != nil {
			t.Fatalf("failed to read plugin.json: %v", err)
		}

		var plugin struct {
			Name        string                 `json:"name"`
			Version     string                 `json:"version"`
			Description string                 `json:"description"`
			Repository  string                 `json:"repository"`
			Hooks       string                 `json:"hooks"`
			UserConfig  map[string]interface{} `json:"userConfig"`
		}

		if err := json.Unmarshal(data, &plugin); err != nil {
			t.Fatalf("failed to parse plugin.json: %v", err)
		}

		if plugin.Name != "skill-trust" {
			t.Errorf("expected name 'skill-trust', got %q", plugin.Name)
		}
		if plugin.Version != "0.2.0" {
			t.Errorf("expected version '0.2.0', got %q", plugin.Version)
		}
		if plugin.Hooks != "./hooks/hooks.json" {
			t.Errorf("expected hooks path './hooks/hooks.json', got %q", plugin.Hooks)
		}
		if plugin.Repository != "https://github.com/redhat-et/skill-trust" {
			t.Errorf("expected repository 'https://github.com/redhat-et/skill-trust', got %q", plugin.Repository)
		}
	})

	// Test hooks.json
	t.Run("HooksJSON", func(t *testing.T) {
		data, err := os.ReadFile(hooksJSONPath)
		if err != nil {
			t.Fatalf("failed to read hooks.json: %v", err)
		}

		var hooks struct {
			Hooks struct {
				SessionStart []struct {
					Matcher string `json:"matcher"`
					Hooks   []struct {
						Type    string `json:"type"`
						Command string `json:"command"`
					} `json:"hooks"`
				} `json:"SessionStart"`
				PreToolUse []struct {
					Matcher string `json:"matcher"`
					Hooks   []struct {
						Type    string `json:"type"`
						Command string `json:"command"`
					} `json:"hooks"`
				} `json:"PreToolUse"`
				UserPromptSubmit []struct {
					Hooks []struct {
						Type    string `json:"type"`
						Command string `json:"command"`
					} `json:"hooks"`
				} `json:"UserPromptSubmit"`
			} `json:"hooks"`
		}

		if err := json.Unmarshal(data, &hooks); err != nil {
			t.Fatalf("failed to parse hooks.json: %v", err)
		}

		// Collect all hook commands
		var commands []string
		for _, group := range hooks.Hooks.SessionStart {
			for _, h := range group.Hooks {
				commands = append(commands, h.Command)
			}
		}
		for _, group := range hooks.Hooks.PreToolUse {
			for _, h := range group.Hooks {
				commands = append(commands, h.Command)
			}
		}
		for _, group := range hooks.Hooks.UserPromptSubmit {
			for _, h := range group.Hooks {
				commands = append(commands, h.Command)
			}
		}

		// Verify each command starts with the quoted binary expansion
		expectedPrefix := `"${CLAUDE_PLUGIN_OPTION_BINARY:-skill-trust}" `
		hookEventRE := regexp.MustCompile(`hook claude-code (\S+)`)

		for _, cmd := range commands {
			// Assert command starts with the quoted binary expansion
			if !strings.HasPrefix(cmd, expectedPrefix) {
				t.Errorf("hook command does not start with %q: %q", expectedPrefix, cmd)
				continue
			}

			// Extract the event name using regex
			matches := hookEventRE.FindStringSubmatch(cmd)
			if len(matches) < 2 {
				t.Errorf("failed to extract event from hook command: %q", cmd)
				continue
			}
			event := matches[1]

			if !validEvents[event] {
				t.Errorf("hook command references unknown event %q (command: %q)", event, cmd)
			}
		}

		// Real shell check: verify the command works with a path containing spaces
		if runtime.GOOS != "windows" {
			t.Run("ShellCheck", func(t *testing.T) {
				// Create a temp script with a space in its path
				tmpDir := t.TempDir()
				scriptDir := filepath.Join(tmpDir, "path with spaces")
				if err := os.Mkdir(scriptDir, 0o755); err != nil {
					t.Fatal(err)
				}
				scriptPath := filepath.Join(scriptDir, "skill-trust")

				// Write a script that echoes its arguments
				script := "#!/bin/sh\necho \"$@\"\n"
				if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
					t.Fatal(err)
				}

				// Test each command
				for _, cmd := range commands {
					// Extract the expected event
					matches := hookEventRE.FindStringSubmatch(cmd)
					if len(matches) < 2 {
						continue // Already reported above
					}
					event := matches[1]

					// Run the command via sh -c with CLAUDE_PLUGIN_OPTION_BINARY set
					shellCmd := exec.Command("sh", "-c", cmd)
					shellCmd.Env = append(os.Environ(), "CLAUDE_PLUGIN_OPTION_BINARY="+scriptPath)
					output, err := shellCmd.CombinedOutput()
					if err != nil {
						t.Errorf("command failed: %v\nCommand: %s\nOutput: %s", err, cmd, output)
						continue
					}

					expectedOutput := "hook claude-code " + event + "\n"
					if string(output) != expectedOutput {
						t.Errorf("unexpected output for command %q\nExpected: %q\nGot: %q", cmd, expectedOutput, string(output))
					}
				}
			})
		}
	})

	// Test marketplace.json
	t.Run("MarketplaceJSON", func(t *testing.T) {
		data, err := os.ReadFile(marketplaceJSONPath)
		if err != nil {
			t.Fatalf("failed to read marketplace.json: %v", err)
		}

		var marketplace struct {
			Plugins []struct {
				Name   string `json:"name"`
				Source string `json:"source"`
			} `json:"plugins"`
		}

		if err := json.Unmarshal(data, &marketplace); err != nil {
			t.Fatalf("failed to parse marketplace.json: %v", err)
		}

		found := false
		for _, p := range marketplace.Plugins {
			if p.Name == "skill-trust" {
				found = true
				source := filepath.Join(repoRoot, p.Source)
				pluginJSON := filepath.Join(source, ".claude-plugin", "plugin.json")
				if _, err := os.Stat(pluginJSON); err != nil {
					t.Errorf("marketplace entry source %q does not contain .claude-plugin/plugin.json: %v", p.Source, err)
				}
				break
			}
		}

		if !found {
			t.Error("marketplace.json does not contain a 'skill-trust' plugin entry")
		}
	})
}

// TestPluginVersionMatchesTag asserts that, on a v* tag build, plugin.json
// carries the tag version. The release workflow runs it by exact name with
// SKILL_TRUST_REQUIRE_TAG_CHECK=1, which turns a missing tag environment
// into a failure instead of a skip.
func TestPluginVersionMatchesTag(t *testing.T) {
	pluginJSONPath := filepath.Join("..", "..", "adapters", "claude-code", ".claude-plugin", "plugin.json")
	refType := os.Getenv("GITHUB_REF_TYPE")
	refName := os.Getenv("GITHUB_REF_NAME")

	if refType != "tag" || !strings.HasPrefix(refName, "v") {
		if os.Getenv("SKILL_TRUST_REQUIRE_TAG_CHECK") == "1" {
			t.Fatalf("SKILL_TRUST_REQUIRE_TAG_CHECK=1 but not a v* tag build (GITHUB_REF_TYPE=%q, GITHUB_REF_NAME=%q)", refType, refName)
		}
		t.Skip("skipping: not a tag build")
	}

	// Tag should be like "v0.2.0", plugin version should be "0.2.0"
	expectedVersion := strings.TrimPrefix(refName, "v")

	data, err := os.ReadFile(pluginJSONPath)
	if err != nil {
		t.Fatalf("failed to read plugin.json: %v", err)
	}

	var plugin struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &plugin); err != nil {
		t.Fatalf("failed to parse plugin.json: %v", err)
	}

	if plugin.Version != expectedVersion {
		t.Errorf("plugin.json version %q does not match tag %q (expected %q)",
			plugin.Version, refName, expectedVersion)
	}
}
