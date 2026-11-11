package claudecode

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/redhat-et/skill-trust/pkg/preflight"
)

// testVerifier is a test double that returns a fixed result.
type testVerifier struct {
	result preflight.Result
	err    error
}

func (f testVerifier) VerifySkill(root string) (preflight.Result, error) {
	return f.result, f.err
}

func TestPreToolUseNoSkillPathNoVerifier(t *testing.T) {
	// Verify that NewVerifier is not called when no skill paths are candidates
	verifierCalled := false
	cfg := Config{
		Locations: Locations{Home: "/fake", Cwd: "/tmp"},
		NewVerifier: func(policyPath string) (preflight.Verifier, error) {
			verifierCalled = true
			t.Fatal("NewVerifier should not be called when no skill paths exist")
			return nil, nil
		},
	}

	in := HookInput{
		SessionID:     "test",
		Cwd:           "/tmp",
		HookEventName: "PreToolUse",
		ToolName:      "Read",
		ToolInput:     map[string]any{"file_path": "/tmp/file.txt"},
	}

	result := PreToolUse(cfg, in)
	if result != nil {
		t.Errorf("expected nil result for non-skill path, got: %s", result)
	}
	if verifierCalled {
		t.Error("NewVerifier was called despite no skill paths")
	}
}

func TestPreToolUseSkillToolOutput(t *testing.T) {
	home := t.TempDir()
	skillRoot := filepath.Join(home, ".claude", "skills", "test-skill")
	os.MkdirAll(skillRoot, 0o755)
	os.WriteFile(filepath.Join(skillRoot, "SKILL.md"), []byte("# Test"), 0o644)

	cfg := Config{
		Policy:    "/fake/policy.json",
		Strict:    true,
		StateDir:  t.TempDir(),
		Locations: Locations{Home: home, Cwd: "/tmp"},
		NewVerifier: func(policyPath string) (preflight.Verifier, error) {
			return testVerifier{
				result: preflight.Result{
					Decision: preflight.Block,
					Findings: []preflight.Finding{{
						Code:    "ST-TEST-BLOCKED",
						Message: "test block",
					}},
				},
			}, nil
		},
	}

	in := HookInput{
		SessionID:     "test",
		Cwd:           "/tmp",
		HookEventName: "PreToolUse",
		ToolName:      "Skill",
		ToolInput:     map[string]any{"skill": "test-skill"},
	}

	result := PreToolUse(cfg, in)
	if result == nil {
		t.Fatal("expected non-nil result for blocked skill")
	}

	var output map[string]any
	if err := json.Unmarshal(result, &output); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, result)
	}

	hookOutput, ok := output["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("missing or invalid hookSpecificOutput: %v", output)
	}

	if hookOutput["hookEventName"] != "PreToolUse" {
		t.Errorf("hookEventName = %v, want PreToolUse", hookOutput["hookEventName"])
	}

	if hookOutput["permissionDecision"] != "deny" {
		t.Errorf("permissionDecision = %v, want deny", hookOutput["permissionDecision"])
	}

	reason, ok := hookOutput["permissionDecisionReason"].(string)
	if !ok || reason == "" {
		t.Errorf("missing or empty permissionDecisionReason: %v", hookOutput)
	}
}

func TestPreToolUseWarningOnlyOutput(t *testing.T) {
	home := t.TempDir()
	skillRoot := filepath.Join(home, ".claude", "skills", "test-skill")
	os.MkdirAll(skillRoot, 0o755)
	os.WriteFile(filepath.Join(skillRoot, "SKILL.md"), []byte("# Test"), 0o644)

	cfg := Config{
		Policy:    "/fake/policy.json",
		Strict:    false,
		StateDir:  t.TempDir(),
		Locations: Locations{Home: home, Cwd: "/tmp"},
		NewVerifier: func(policyPath string) (preflight.Verifier, error) {
			return testVerifier{
				result: preflight.Result{
					Decision: preflight.Block,
					Findings: []preflight.Finding{{
						Code:    "ST-TEST-UNSIGNED",
						Message: "unsigned skill",
					}},
				},
			}, nil
		},
	}

	in := HookInput{
		SessionID:     "test",
		Cwd:           "/tmp",
		HookEventName: "PreToolUse",
		ToolName:      "Skill",
		ToolInput:     map[string]any{"skill": "test-skill"},
	}

	result := PreToolUse(cfg, in)
	if result == nil {
		t.Fatal("expected non-nil result for warning-only outcome")
	}

	var output map[string]any
	if err := json.Unmarshal(result, &output); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, result)
	}

	hookOutput, ok := output["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("missing or invalid hookSpecificOutput: %v", output)
	}

	if hookOutput["hookEventName"] != "PreToolUse" {
		t.Errorf("hookEventName = %v, want PreToolUse", hookOutput["hookEventName"])
	}

	if _, hasDeny := hookOutput["permissionDecision"]; hasDeny {
		t.Errorf("report-only warning should not have permissionDecision, got: %v", hookOutput)
	}

	context, ok := hookOutput["additionalContext"].(string)
	if !ok || context == "" {
		t.Errorf("missing or empty additionalContext for warning: %v", hookOutput)
	}
}

func TestUserPromptSubmitBlocksSlashCommand(t *testing.T) {
	home := t.TempDir()
	skillRoot := filepath.Join(home, ".claude", "skills", "test-skill")
	os.MkdirAll(skillRoot, 0o755)
	os.WriteFile(filepath.Join(skillRoot, "SKILL.md"), []byte("# Test"), 0o644)

	cfg := Config{
		Policy:    "/fake/policy.json",
		Strict:    true,
		StateDir:  t.TempDir(),
		Locations: Locations{Home: home, Cwd: "/tmp"},
		NewVerifier: func(policyPath string) (preflight.Verifier, error) {
			return testVerifier{
				result: preflight.Result{
					Decision: preflight.Block,
					Findings: []preflight.Finding{{
						Code:    "ST-TEST-BLOCKED",
						Message: "test block",
					}},
				},
			}, nil
		},
	}

	in := HookInput{
		SessionID:     "test",
		Cwd:           "/tmp",
		HookEventName: "UserPromptSubmit",
		Prompt:        "/test-skill do something",
	}

	result := UserPromptSubmit(cfg, in)
	if result == nil {
		t.Fatal("expected non-nil result for blocked slash command")
	}

	var output map[string]any
	if err := json.Unmarshal(result, &output); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, result)
	}

	if output["decision"] != "block" {
		t.Errorf("decision = %v, want block", output["decision"])
	}

	reason, ok := output["reason"].(string)
	if !ok || reason == "" {
		t.Errorf("missing or empty reason: %v", output)
	}
}

func TestUserPromptSubmitIgnoresNonSlashPrompts(t *testing.T) {
	cfg := Config{
		Policy:    "/fake/policy.json",
		Strict:    true,
		Locations: Locations{Home: "/home/test", Cwd: "/tmp"},
		NewVerifier: func(policyPath string) (preflight.Verifier, error) {
			t.Fatal("NewVerifier should not be called for non-slash prompts")
			return nil, nil
		},
	}

	testCases := []string{
		"hello world",
		"use /test-skill to do something",
	}

	for _, prompt := range testCases {
		in := HookInput{
			SessionID:     "test",
			Cwd:           "/tmp",
			HookEventName: "UserPromptSubmit",
			Prompt:        prompt,
		}

		result := UserPromptSubmit(cfg, in)
		if result != nil {
			t.Errorf("prompt %q: expected nil, got: %s", prompt, result)
		}
	}
}

func TestUserPromptSubmitTrimsLeadingWhitespace(t *testing.T) {
	home := t.TempDir()
	skillRoot := filepath.Join(home, ".claude", "skills", "test-skill")
	os.MkdirAll(skillRoot, 0o755)
	os.WriteFile(filepath.Join(skillRoot, "SKILL.md"), []byte("# Test"), 0o644)

	cfg := Config{
		Policy:    "/fake/policy.json",
		Strict:    true,
		StateDir:  t.TempDir(),
		Locations: Locations{Home: home, Cwd: "/tmp"},
		NewVerifier: func(policyPath string) (preflight.Verifier, error) {
			return testVerifier{
				result: preflight.Result{
					Decision: preflight.Block,
					Findings: []preflight.Finding{{
						Code:    "ST-TEST-BLOCKED",
						Message: "test block",
					}},
				},
			}, nil
		},
	}

	in := HookInput{
		SessionID:     "test",
		Cwd:           "/tmp",
		HookEventName: "UserPromptSubmit",
		Prompt:        "  /test-skill do something",
	}

	result := UserPromptSubmit(cfg, in)
	if result == nil {
		t.Fatal("expected non-nil result for slash command with leading whitespace")
	}

	var output map[string]any
	if err := json.Unmarshal(result, &output); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, result)
	}

	if output["decision"] != "block" {
		t.Errorf("decision = %v, want block", output["decision"])
	}
}

func TestSessionStartSummaryAndPruning(t *testing.T) {
	stateDir := t.TempDir()
	// Home reached through a symlink, as on macOS (/var -> /private/var).
	home := symlinkedTempDir(t)

	// Create good and bad skills
	goodRoot := filepath.Join(home, ".claude", "skills", "good-skill")
	badRoot := filepath.Join(home, ".claude", "skills", "bad-skill")
	os.MkdirAll(goodRoot, 0o755)
	os.MkdirAll(badRoot, 0o755)
	os.WriteFile(filepath.Join(goodRoot, "SKILL.md"), []byte("# Good"), 0o644)
	os.WriteFile(filepath.Join(badRoot, "SKILL.md"), []byte("# Bad"), 0o644)

	// Discovery reports symlink-free roots, so the fake verifier is keyed
	// by the resolved paths.
	goodRoot, badRoot = NormalizePath(goodRoot), NormalizePath(badRoot)

	// Fake verifier: good-skill passes, bad-skill fails
	fakeVer := fakeVerifier{
		goodRoot: preflight.Result{
			Decision:       preflight.Allow,
			ManifestDigest: "sha256:abc123",
		},
		badRoot: preflight.Result{
			Decision: preflight.Block,
			Findings: []preflight.Finding{{
				Code:    preflight.CodeVerifierFailure,
				Message: "test failure",
			}},
		},
	}

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Create old state file (>7 days old)
	oldStateFile := filepath.Join(stateDir, "state-old.json")
	os.WriteFile(oldStateFile, []byte("{}"), 0o600)
	oldTime := now.Add(-8 * 24 * time.Hour)
	os.Chtimes(oldStateFile, oldTime, oldTime)

	// Create fresh state file (<7 days old)
	freshStateFile := filepath.Join(stateDir, "state-fresh.json")
	os.WriteFile(freshStateFile, []byte("{}"), 0o600)
	freshTime := now.Add(-1 * 24 * time.Hour)
	os.Chtimes(freshStateFile, freshTime, freshTime)

	cfg := Config{
		Policy:    "/fake/policy.json",
		Strict:    true,
		StateDir:  stateDir,
		Locations: Locations{Home: home, Cwd: "/tmp"},
		Now: func() time.Time {
			return now
		},
		NewVerifier: func(policyPath string) (preflight.Verifier, error) {
			return fakeVer, nil
		},
	}

	in := HookInput{
		SessionID:     "test-session",
		Cwd:           "/tmp",
		HookEventName: "SessionStart",
	}

	result := SessionStart(cfg, in)
	if result == nil {
		t.Fatal("expected non-nil result from SessionStart")
	}

	var output map[string]any
	if err := json.Unmarshal(result, &output); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, result)
	}

	systemMsg, ok := output["systemMessage"].(string)
	if !ok || systemMsg == "" {
		t.Fatalf("missing or empty systemMessage: %v", output)
	}

	// Check exact summary counts
	if !strings.Contains(systemMsg, "1 skills verified, 1 blocked") {
		t.Errorf("systemMessage should say '1 skills verified, 1 blocked', got: %s", systemMsg)
	}

	if !strings.Contains(systemMsg, "bad-skill") {
		t.Errorf("systemMessage should name bad-skill, got: %s", systemMsg)
	}

	hookOutput, ok := output["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("missing or invalid hookSpecificOutput: %v", output)
	}

	if hookOutput["hookEventName"] != "SessionStart" {
		t.Errorf("hookEventName = %v, want SessionStart", hookOutput["hookEventName"])
	}

	additionalContext, ok := hookOutput["additionalContext"].(string)
	if !ok || additionalContext == "" {
		t.Fatalf("missing additionalContext for blocked skill: %v", hookOutput)
	}

	if !strings.Contains(additionalContext, "bad-skill") {
		t.Errorf("additionalContext should name bad-skill, got: %s", additionalContext)
	}

	// Check pruning: old file should be gone, fresh file should remain
	if _, err := os.Stat(oldStateFile); !os.IsNotExist(err) {
		t.Errorf("old state file should have been pruned")
	}

	if _, err := os.Stat(freshStateFile); err != nil {
		t.Errorf("fresh state file should not have been pruned: %v", err)
	}
}
