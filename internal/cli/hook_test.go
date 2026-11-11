package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/redhat-et/skill-trust/internal/claudecode"
	"github.com/redhat-et/skill-trust/pkg/manifest"
)

// setupHookTest creates a home directory with a skill and returns the skill root.
func setupHookTest(t *testing.T, home, skillName string, tamper bool) string {
	t.Helper()

	// Create skill directory
	skillRoot := filepath.Join(home, ".claude", "skills", skillName)
	if err := os.MkdirAll(filepath.Join(skillRoot, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Write skill files
	write := func(rel, content string, mode os.FileMode) {
		full := filepath.Join(skillRoot, rel)
		if err := os.WriteFile(full, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}

	write("SKILL.md", "---\nname: "+skillName+"\n---\nTest skill.\n", 0o644)
	write("scripts/run.sh", "#!/usr/bin/env bash\necho hi\n", 0o755)
	write("scripts/util.py", "print('hi')\n", 0o644)

	// Sign the skill
	keyPath, pubPath := newKey(t)
	policyPath := keyPolicy(t, pubPath)

	// Copy policy to home for tests
	policyDest := filepath.Join(home, "policy.json")
	policyData, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyDest, policyData, 0o644); err != nil {
		t.Fatal(err)
	}

	// Sign
	code, out := runCLI(t, "sign", skillRoot, "--key", keyPath)
	if code != ExitSuccess {
		t.Fatalf("sign exit = %d, output:\n%s", code, out)
	}

	// Tamper if requested
	if tamper {
		write("SKILL.md", "---\nname: "+skillName+"\n---\nTampered!\n", 0o644)
	}

	return skillRoot
}

// runHook executes the hook command with JSON input and returns exit code and output.
func runHook(t *testing.T, subcommand string, input []byte, extraArgs ...string) (int, string) {
	t.Helper()

	args := append([]string{"hook", "claude-code", subcommand}, extraArgs...)

	// Reset global command state
	exitCode = ExitSuccess
	jsonOutput = false
	manifestWrite = false
	verifyPolicy = ""
	verifyReport = false
	signKey, signIDToken, signServices = "", "", ""
	hookPolicyPath = ""
	hookStrict = true

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs(args)
	rootCmd.SetIn(bytes.NewReader(input))

	err := rootCmd.Execute()
	code := exitCode
	if err != nil && code == ExitSuccess {
		code = ExitError
	}
	return code, buf.String()
}

// copyDirPreservingModes copies a directory tree, preserving file modes.
func copyDirPreservingModes(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		dstPath := filepath.Join(dst, relPath)

		if info.IsDir() {
			return os.MkdirAll(dstPath, info.Mode())
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		return os.WriteFile(dstPath, data, info.Mode())
	})
	if err != nil {
		t.Fatalf("copyDirPreservingModes: %v", err)
	}
}

// loadProbeFixture loads a probe fixture JSON, allowing field overwrites.
func loadProbeFixture(t *testing.T, name string, overwrites map[string]any) []byte {
	t.Helper()

	fixturePath := filepath.Join("testdata", "claudecode", name+".json")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("reading probe fixture %s: %v", name, err)
	}

	var input map[string]any
	if err := json.Unmarshal(data, &input); err != nil {
		t.Fatalf("parsing probe fixture %s: %v", name, err)
	}

	// Apply overwrites
	for k, v := range overwrites {
		input[k] = v
	}

	result, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshaling probe fixture: %v", err)
	}

	return result
}

func TestPreToolUseAllowsVerifiedSkill(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_PLUGIN_DATA", filepath.Join(home, ".claude"))
	t.Setenv("CLAUDE_PROJECT_DIR", "")

	setupHookTest(t, home, "cli-test", false)
	policyPath := filepath.Join(home, "policy.json")

	input := `{
		"session_id": "test-session",
		"cwd": "/tmp",
		"hook_event_name": "PreToolUse",
		"tool_name": "Read",
		"tool_input": {
			"file_path": "` + filepath.Join(home, ".claude/skills/cli-test/SKILL.md") + `"
		},
		"permission_mode": "default"
	}`

	code, out := runHook(t, "pre-tool-use", []byte(input), "--policy", policyPath)
	if code != ExitSuccess {
		t.Fatalf("exit = %d, expected 0, output:\n%s", code, out)
	}
	if strings.TrimSpace(out) != "" {
		t.Errorf("expected empty output for allowed skill, got: %s", out)
	}
}

func TestPreToolUseDeniesTamperedRead(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_PLUGIN_DATA", filepath.Join(home, ".claude"))
	t.Setenv("CLAUDE_PROJECT_DIR", "")

	skillRoot := setupHookTest(t, home, "cli-test", true)
	policyPath := filepath.Join(home, "policy.json")

	// Compute observed digest of tampered skill
	m, err := manifest.Create(skillRoot)
	if err != nil {
		t.Fatalf("computing manifest: %v", err)
	}
	observedDigest, err := m.Digest()
	if err != nil {
		t.Fatalf("computing digest: %v", err)
	}

	input := loadProbeFixture(t, "pretooluse-read", map[string]any{
		"session_id": "test-session",
		"cwd":        "/tmp",
		"tool_input": map[string]any{
			"file_path": filepath.Join(skillRoot, "SKILL.md"),
		},
	})

	code, out := runHook(t, "pre-tool-use", input, "--policy", policyPath)
	if code != ExitSuccess {
		t.Fatalf("exit = %d, expected 0 (hooks don't error on deny), output:\n%s", code, out)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}

	hookOutput, ok := result["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("missing hookSpecificOutput: %v", result)
	}

	if hookOutput["permissionDecision"] != "deny" {
		t.Errorf("permissionDecision = %v, want deny", hookOutput["permissionDecision"])
	}

	reason := hookOutput["permissionDecisionReason"].(string)
	if !strings.Contains(reason, "ST-") {
		t.Errorf("reason should contain ST- code, got: %s", reason)
	}
	if !strings.Contains(reason, observedDigest) {
		t.Errorf("reason should contain observed digest %s, got: %s", observedDigest, reason)
	}
}

func TestPreToolUseDeniesTamperedBash(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_PLUGIN_DATA", filepath.Join(home, ".claude"))
	t.Setenv("CLAUDE_PROJECT_DIR", "")

	skillRoot := setupHookTest(t, home, "cli-test", true)
	policyPath := filepath.Join(home, "policy.json")

	// Compute observed digest
	m, err := manifest.Create(skillRoot)
	if err != nil {
		t.Fatalf("computing manifest: %v", err)
	}
	observedDigest, err := m.Digest()
	if err != nil {
		t.Fatalf("computing digest: %v", err)
	}

	input := loadProbeFixture(t, "pretooluse-bash", map[string]any{
		"session_id": "test-session",
		"cwd":        "/tmp",
		"tool_input": map[string]any{
			"command": "bash " + filepath.Join(skillRoot, "scripts/run.sh"),
		},
	})

	code, out := runHook(t, "pre-tool-use", input, "--policy", policyPath)
	if code != ExitSuccess {
		t.Fatalf("exit = %d, expected 0, output:\n%s", code, out)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}

	hookOutput := result["hookSpecificOutput"].(map[string]any)
	if hookOutput["permissionDecision"] != "deny" {
		t.Errorf("permissionDecision = %v, want deny", hookOutput["permissionDecision"])
	}

	reason := hookOutput["permissionDecisionReason"].(string)
	if !strings.Contains(reason, "ST-") {
		t.Errorf("reason should contain ST- code, got: %s", reason)
	}
	if !strings.Contains(reason, observedDigest) {
		t.Errorf("reason should contain observed digest %s, got: %s", observedDigest, reason)
	}
}

func TestPreToolUseDeniesTamperedPython(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_PLUGIN_DATA", filepath.Join(home, ".claude"))
	t.Setenv("CLAUDE_PROJECT_DIR", "")

	skillRoot := setupHookTest(t, home, "cli-test", true)
	policyPath := filepath.Join(home, "policy.json")

	// Compute observed digest
	m, err := manifest.Create(skillRoot)
	if err != nil {
		t.Fatalf("computing manifest: %v", err)
	}
	observedDigest, err := m.Digest()
	if err != nil {
		t.Fatalf("computing digest: %v", err)
	}

	input := loadProbeFixture(t, "pretooluse-bash", map[string]any{
		"session_id": "test-session",
		"cwd":        skillRoot,
		"tool_input": map[string]any{
			"command": "python3 scripts/util.py",
		},
	})

	code, out := runHook(t, "pre-tool-use", input, "--policy", policyPath)
	if code != ExitSuccess {
		t.Fatalf("exit = %d, expected 0, output:\n%s", code, out)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}

	hookOutput := result["hookSpecificOutput"].(map[string]any)
	if hookOutput["permissionDecision"] != "deny" {
		t.Errorf("permissionDecision = %v, want deny", hookOutput["permissionDecision"])
	}

	reason := hookOutput["permissionDecisionReason"].(string)
	if !strings.Contains(reason, "ST-") {
		t.Errorf("reason should contain ST- code, got: %s", reason)
	}
	if !strings.Contains(reason, observedDigest) {
		t.Errorf("reason should contain observed digest %s, got: %s", observedDigest, reason)
	}
}

func TestPreToolUseDeniesTamperedSkillTool(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_PLUGIN_DATA", filepath.Join(home, ".claude"))
	t.Setenv("CLAUDE_PROJECT_DIR", "")

	skillRoot := setupHookTest(t, home, "cli-test", true)
	policyPath := filepath.Join(home, "policy.json")

	// Compute observed digest
	m, err := manifest.Create(skillRoot)
	if err != nil {
		t.Fatalf("computing manifest: %v", err)
	}
	observedDigest, err := m.Digest()
	if err != nil {
		t.Fatalf("computing digest: %v", err)
	}

	input := loadProbeFixture(t, "pretooluse-skill", map[string]any{
		"session_id": "test-session",
		"cwd":        "/tmp",
		"tool_input": map[string]any{
			"skill": "cli-test",
		},
	})

	code, out := runHook(t, "pre-tool-use", input, "--policy", policyPath)
	if code != ExitSuccess {
		t.Fatalf("exit = %d, expected 0, output:\n%s", code, out)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}

	hookOutput := result["hookSpecificOutput"].(map[string]any)
	if hookOutput["permissionDecision"] != "deny" {
		t.Errorf("permissionDecision = %v, want deny", hookOutput["permissionDecision"])
	}

	reason := hookOutput["permissionDecisionReason"].(string)
	if !strings.Contains(reason, "ST-") {
		t.Errorf("reason should contain ST- code, got: %s", reason)
	}
	if !strings.Contains(reason, observedDigest) {
		t.Errorf("reason should contain observed digest %s, got: %s", observedDigest, reason)
	}
}

func TestPreToolUseChangedAfterVerifyIsSticky(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_PLUGIN_DATA", filepath.Join(home, ".claude"))
	t.Setenv("CLAUDE_PROJECT_DIR", "")

	// Create skill and key
	skillRoot := filepath.Join(home, ".claude", "skills", "cli-test")
	if err := os.MkdirAll(filepath.Join(skillRoot, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(skillRoot, "SKILL.md"), []byte("---\nname: cli-test\n---\nOriginal.\n"), 0o644)
	os.WriteFile(filepath.Join(skillRoot, "scripts/run.sh"), []byte("#!/usr/bin/env bash\necho hi\n"), 0o755)

	keyPath, pubPath := newKey(t)
	policyPath := keyPolicy(t, pubPath)
	policyDest := filepath.Join(home, "policy.json")
	policyData, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyDest, policyData, 0o644); err != nil {
		t.Fatal(err)
	}

	code, out := runCLI(t, "sign", skillRoot, "--key", keyPath)
	if code != ExitSuccess {
		t.Fatalf("sign exit = %d, output:\n%s", code, out)
	}

	// Session start to record the verified state
	sessionInput := `{
		"session_id": "test-session",
		"cwd": "/tmp",
		"hook_event_name": "SessionStart"
	}`
	code, out = runHook(t, "session-start", []byte(sessionInput), "--policy", policyDest)
	if code != ExitSuccess {
		t.Fatalf("session-start exit = %d, output:\n%s", code, out)
	}

	// Tamper with the skill
	os.WriteFile(filepath.Join(skillRoot, "SKILL.md"), []byte("---\nname: cli-test\n---\nTampered!\n"), 0o644)

	// Re-sign with SAME key but different content
	code, out = runCLI(t, "sign", skillRoot, "--key", keyPath)
	if code != ExitSuccess {
		t.Fatalf("re-sign exit = %d, output:\n%s", code, out)
	}

	// Verification should pass (valid signature), but Decide should deny (digest changed)
	input := `{
		"session_id": "test-session",
		"cwd": "/tmp",
		"hook_event_name": "PreToolUse",
		"tool_name": "Skill",
		"tool_input": {
			"skill": "cli-test"
		},
		"permission_mode": "default"
	}`

	code, out = runHook(t, "pre-tool-use", []byte(input), "--policy", policyDest)
	if code != ExitSuccess {
		t.Fatalf("pre-tool-use exit = %d, output:\n%s", code, out)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}

	hookOutput := result["hookSpecificOutput"].(map[string]any)
	reason := hookOutput["permissionDecisionReason"].(string)
	if !strings.Contains(reason, "ST-PREFLIGHT-CHANGED-AFTER-VERIFY") {
		t.Errorf("expected ST-PREFLIGHT-CHANGED-AFTER-VERIFY after valid re-sign, got: %s", reason)
	}

	// The deny is sticky: retrying in the same session is still denied.
	code, out = runHook(t, "pre-tool-use", []byte(input), "--policy", policyDest)
	if code != ExitSuccess {
		t.Fatalf("second pre-tool-use exit = %d, output:\n%s", code, out)
	}
	if reason := requireDeny(t, out); !strings.Contains(reason, "ST-PREFLIGHT-CHANGED-AFTER-VERIFY") {
		t.Errorf("retry should still be ST-PREFLIGHT-CHANGED-AFTER-VERIFY, got: %s", reason)
	}

	// New session should clear the sticky state
	code, out = runHook(t, "session-start", []byte(sessionInput), "--policy", policyDest)
	if code != ExitSuccess {
		t.Fatalf("new session-start exit = %d, output:\n%s", code, out)
	}

	// After new session, the re-signed skill should be allowed
	code, out = runHook(t, "pre-tool-use", []byte(input), "--policy", policyDest)
	if code != ExitSuccess {
		t.Fatalf("pre-tool-use after new session exit = %d, output:\n%s", code, out)
	}
	if strings.TrimSpace(out) != "" {
		t.Errorf("expected empty output after new session (allowed), got: %s", out)
	}
}

func TestPreToolUseUnsignedStrictAndReportOnly(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_PLUGIN_DATA", filepath.Join(home, ".claude"))
	t.Setenv("CLAUDE_PROJECT_DIR", "")

	// Create unsigned skill
	skillRoot := filepath.Join(home, ".claude", "skills", "unsigned-skill")
	if err := os.MkdirAll(skillRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillRoot, "SKILL.md"), []byte("# Unsigned"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create a minimal policy (won't match unsigned skill)
	_, pubPath := newKey(t)
	policyPath := keyPolicy(t, pubPath)

	input := `{
		"session_id": "test-session",
		"cwd": "/tmp",
		"hook_event_name": "PreToolUse",
		"tool_name": "Skill",
		"tool_input": {
			"skill": "unsigned-skill"
		},
		"permission_mode": "default"
	}`

	// Strict mode (default) - should deny
	code, out := runHook(t, "pre-tool-use", []byte(input), "--policy", policyPath)
	if code != ExitSuccess {
		t.Fatalf("exit = %d, output:\n%s", code, out)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}

	hookOutput := result["hookSpecificOutput"].(map[string]any)
	if hookOutput["permissionDecision"] != "deny" {
		t.Errorf("strict mode should deny unsigned skill, got: %v", hookOutput)
	}

	reason := hookOutput["permissionDecisionReason"].(string)
	if !strings.Contains(reason, "ST-PREFLIGHT-NOT-VERIFIED") {
		t.Errorf("expected ST-PREFLIGHT-NOT-VERIFIED, got: %s", reason)
	}

	// Non-strict mode - should allow with warning
	code, out = runHook(t, "pre-tool-use", []byte(input), "--policy", policyPath, "--strict=false")
	if code != ExitSuccess {
		t.Fatalf("exit = %d, output:\n%s", code, out)
	}

	if strings.TrimSpace(out) == "" {
		t.Fatal("expected warning output in non-strict mode")
	}

	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}

	hookOutput = result["hookSpecificOutput"].(map[string]any)
	if _, hasDeny := hookOutput["permissionDecision"]; hasDeny {
		t.Errorf("non-strict mode should not deny, got: %v", hookOutput)
	}

	context, ok := hookOutput["additionalContext"].(string)
	if !ok || context == "" {
		t.Errorf("expected additionalContext warning, got: %v", hookOutput)
	}
}

func TestPreToolUseMissingPolicy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_PLUGIN_DATA", filepath.Join(home, ".claude"))
	t.Setenv("CLAUDE_PROJECT_DIR", "")

	setupHookTest(t, home, "cli-test", false)

	input := `{
		"session_id": "test-session",
		"cwd": "/tmp",
		"hook_event_name": "PreToolUse",
		"tool_name": "Skill",
		"tool_input": {
			"skill": "cli-test"
		},
		"permission_mode": "default"
	}`

	// Missing policy in strict mode should deny skill paths
	code, out := runHook(t, "pre-tool-use", []byte(input), "--policy", "/nonexistent/policy.json")
	if code != ExitSuccess {
		t.Fatalf("exit = %d, output:\n%s", code, out)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}

	hookOutput := result["hookSpecificOutput"].(map[string]any)
	if hookOutput["permissionDecision"] != "deny" {
		t.Errorf("missing policy should deny in strict mode, got: %v", hookOutput)
	}

	// Report-only mode must not turn a missing or malformed policy into an
	// allow: the verifier cannot be built, so every skill root is denied.
	malformed := filepath.Join(home, "malformed-policy.json")
	if err := os.WriteFile(malformed, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, policy := range []string{"/nonexistent/policy.json", malformed} {
		code, out = runHook(t, "pre-tool-use", []byte(input), "--policy", policy, "--strict=false")
		if code != ExitSuccess {
			t.Fatalf("policy %s strict=false: exit = %d, output:\n%s", policy, code, out)
		}
		reason := requireDeny(t, out)
		if !strings.Contains(reason, "[ST-PREFLIGHT-VERIFIER-FAILURE]") || !strings.Contains(reason, "root: ") {
			t.Errorf("policy %s strict=false: reason should carry verifier-failure code and root, got: %s", policy, reason)
		}
	}
}

func TestUserPromptSubmitMissingPolicy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_PLUGIN_DATA", filepath.Join(home, ".claude"))
	t.Setenv("CLAUDE_PROJECT_DIR", "")

	setupHookTest(t, home, "cli-test", false)

	input := `{"session_id":"s","cwd":"/tmp","hook_event_name":"UserPromptSubmit","prompt":"/cli-test go"}`
	for _, strict := range []string{"--strict=true", "--strict=false"} {
		code, out := runHook(t, "user-prompt-submit", []byte(input), "--policy", "/nonexistent/policy.json", strict)
		if code != ExitSuccess {
			t.Fatalf("%s: exit = %d, output:\n%s", strict, code, out)
		}
		reason := requireBlockPrompt(t, out)
		if !strings.Contains(reason, "[ST-PREFLIGHT-VERIFIER-FAILURE]") || !strings.Contains(reason, "root: ") {
			t.Errorf("%s: reason should carry verifier-failure code and root, got: %s", strict, reason)
		}
	}
}

func TestPreToolUseRelativePolicyPaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_PLUGIN_DATA", filepath.Join(home, ".claude"))
	t.Setenv("CLAUDE_PROJECT_DIR", "")

	// Copy valid-complete skill to HOME/.claude/skills/valid-complete
	skillDst := filepath.Join(home, ".claude", "skills", "valid-complete")
	skillSrc := filepath.Join("..", "..", "testdata", "fixtures", "valid-complete")
	copyDirPreservingModes(t, skillSrc, skillDst)

	// Copy policy.json and fixtures.pub to a separate temp policy dir
	policyDir := t.TempDir()
	policySrc := filepath.Join("..", "..", "testdata", "fixtures", "policy.json")
	pubSrc := filepath.Join("..", "..", "testdata", "fixtures", "fixtures.pub")
	policyDst := filepath.Join(policyDir, "policy.json")
	pubDst := filepath.Join(policyDir, "fixtures.pub")

	policyData, err := os.ReadFile(policySrc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyDst, policyData, 0o644); err != nil {
		t.Fatal(err)
	}

	pubData, err := os.ReadFile(pubSrc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubDst, pubData, 0o644); err != nil {
		t.Fatal(err)
	}

	// Load probe fixture BEFORE changing cwd
	origCwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	// Set hook-input cwd to yet another temp dir (do this before chdir)
	hookCwd := t.TempDir()

	// Positive test: Read SKILL.md from valid-complete
	input := loadProbeFixture(t, "pretooluse-read", map[string]any{
		"session_id": "test-session",
		"cwd":        hookCwd,
		"tool_input": map[string]any{
			"file_path": filepath.Join(skillDst, "SKILL.md"),
		},
	})

	// Set process cwd to a third temp dir
	processCwd := t.TempDir()
	if err := os.Chdir(processCwd); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(origCwd) })

	// Set policy via env (absolute path)
	t.Setenv("CLAUDE_PLUGIN_OPTION_POLICY", policyDst)

	code, out := runHook(t, "pre-tool-use", input)
	if code != ExitSuccess {
		t.Fatalf("exit = %d, expected 0, output:\n%s", code, out)
	}
	if strings.TrimSpace(out) != "" {
		t.Errorf("expected empty output (allowed), got: %s", out)
	}

	// Negative control: tamper one file
	tamperedContent := "# Tampered!"
	if err := os.WriteFile(filepath.Join(skillDst, "SKILL.md"), []byte(tamperedContent), 0o644); err != nil {
		t.Fatal(err)
	}

	code, out = runHook(t, "pre-tool-use", input)
	if code != ExitSuccess {
		t.Fatalf("exit = %d, expected 0, output:\n%s", code, out)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}

	hookOutput := result["hookSpecificOutput"].(map[string]any)
	if hookOutput["permissionDecision"] != "deny" {
		t.Errorf("tampered skill should be denied, got: %v", hookOutput)
	}
}

func TestHookMalformedInput(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Garbage input
	code, out := runHook(t, "pre-tool-use", []byte("not json"), "--policy", "/fake/policy.json")
	if code != ExitError {
		t.Errorf("malformed JSON should exit %d, got %d, output:\n%s", ExitError, code, out)
	}
	if !strings.Contains(out, "skill-trust:") {
		t.Errorf("expected error message on stderr, got: %s", out)
	}

	// Invalid tool_input type (should not error, just return empty)
	input := `{
		"session_id": "test",
		"cwd": "/tmp",
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": 42
	}`
	code, out = runHook(t, "pre-tool-use", []byte(input), "--policy", "/fake/policy.json")
	if code != ExitSuccess {
		t.Fatalf("numeric tool_input should not error, got exit %d, output:\n%s", code, out)
	}
	if strings.TrimSpace(out) != "" {
		t.Errorf("expected empty output for non-map tool_input, got: %s", out)
	}
}

func TestUserPromptSubmitBlocksTamperedSlashSkill(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_PLUGIN_DATA", filepath.Join(home, ".claude"))
	t.Setenv("CLAUDE_PROJECT_DIR", "")

	setupHookTest(t, home, "cli-test", true)
	policyPath := filepath.Join(home, "policy.json")

	// Slash command should be blocked
	input := loadProbeFixture(t, "userpromptsubmit", map[string]any{
		"session_id": "test-session",
		"cwd":        "/tmp",
		"prompt":     "/cli-test do something",
	})

	code, out := runHook(t, "user-prompt-submit", input, "--policy", policyPath)
	if code != ExitSuccess {
		t.Fatalf("exit = %d, output:\n%s", code, out)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}

	if result["decision"] != "block" {
		t.Errorf("decision = %v, want block", result["decision"])
	}

	reason := result["reason"].(string)
	if !strings.Contains(reason, "ST-") {
		t.Errorf("reason should contain ST- code, got: %s", reason)
	}

	// Non-slash prompts should be ignored
	testCases := []struct {
		prompt string
	}{
		{"hello /cli-test"},
		{"/unknown-skill"},
	}

	for _, tc := range testCases {
		input := loadProbeFixture(t, "userpromptsubmit", map[string]any{
			"session_id": "test",
			"cwd":        "/tmp",
			"prompt":     tc.prompt,
		})
		code, out := runHook(t, "user-prompt-submit", input, "--policy", policyPath)
		if code != ExitSuccess {
			t.Fatalf("exit = %d, output:\n%s", code, out)
		}
		if strings.TrimSpace(out) != "" {
			t.Errorf("expected empty output for prompt %q, got: %s", tc.prompt, out)
		}
	}
}

func TestSessionStartSummary(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_PLUGIN_DATA", filepath.Join(home, ".claude"))
	t.Setenv("CLAUDE_PROJECT_DIR", "")

	// Create a shared key for both skills
	keyPath, pubPath := newKey(t)
	policyPath := keyPolicy(t, pubPath)
	policyDest := filepath.Join(home, "policy.json")
	policyData, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyDest, policyData, 0o644); err != nil {
		t.Fatal(err)
	}

	// Create good-skill (signed, not tampered)
	goodRoot := filepath.Join(home, ".claude", "skills", "good-skill")
	if err := os.MkdirAll(filepath.Join(goodRoot, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(goodRoot, "SKILL.md"), []byte("---\nname: good-skill\n---\nGood.\n"), 0o644)
	os.WriteFile(filepath.Join(goodRoot, "scripts/run.sh"), []byte("#!/usr/bin/env bash\necho hi\n"), 0o755)
	code, out := runCLI(t, "sign", goodRoot, "--key", keyPath)
	if code != ExitSuccess {
		t.Fatalf("sign good-skill exit = %d, output:\n%s", code, out)
	}

	// Create bad-skill (signed but tampered)
	badRoot := filepath.Join(home, ".claude", "skills", "bad-skill")
	if err := os.MkdirAll(filepath.Join(badRoot, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(badRoot, "SKILL.md"), []byte("---\nname: bad-skill\n---\nBad.\n"), 0o644)
	os.WriteFile(filepath.Join(badRoot, "scripts/run.sh"), []byte("#!/usr/bin/env bash\necho hi\n"), 0o755)
	code2, out2 := runCLI(t, "sign", badRoot, "--key", keyPath)
	if code2 != ExitSuccess {
		t.Fatalf("sign bad-skill exit = %d, output:\n%s", code2, out2)
	}
	// Tamper after signing
	os.WriteFile(filepath.Join(badRoot, "SKILL.md"), []byte("---\nname: bad-skill\n---\nTampered!\n"), 0o644)

	policyPath = policyDest

	input := loadProbeFixture(t, "sessionstart", map[string]any{
		"session_id": "test-session",
		"cwd":        "/tmp",
	})

	exitCode, output := runHook(t, "session-start", input, "--policy", policyPath)
	if exitCode != ExitSuccess {
		t.Fatalf("exit = %d, output:\n%s", exitCode, output)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, output)
	}

	systemMsg, ok := result["systemMessage"].(string)
	if !ok || systemMsg == "" {
		t.Fatalf("missing systemMessage: %v", result)
	}

	// Should mention verified and blocked counts
	if !strings.Contains(systemMsg, "1 skills verified") {
		t.Errorf("systemMessage should mention 1 verified, got: %s", systemMsg)
	}
	if !strings.Contains(systemMsg, "1 blocked") {
		t.Errorf("systemMessage should mention 1 blocked, got: %s", systemMsg)
	}
	if !strings.Contains(systemMsg, "bad-skill") {
		t.Errorf("systemMessage should name blocked skill, got: %s", systemMsg)
	}

	hookOutput := result["hookSpecificOutput"].(map[string]any)
	additionalContext, ok := hookOutput["additionalContext"].(string)
	if !ok || additionalContext == "" {
		t.Fatalf("missing additionalContext: %v", hookOutput)
	}
	if !strings.Contains(additionalContext, "bad-skill") {
		t.Errorf("additionalContext should name blocked skill, got: %s", additionalContext)
	}
}

func TestExitCodeConstants(t *testing.T) {
	// Verify ExitError is 2 (required by the spec)
	if ExitError != 2 {
		t.Errorf("ExitError = %d, must be 2", ExitError)
	}
}

func TestPluginOptionsFromEnvironment(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_PLUGIN_DATA", filepath.Join(home, ".claude"))
	t.Setenv("CLAUDE_PROJECT_DIR", "")

	setupHookTest(t, home, "cli-test", false)
	policyPath := filepath.Join(home, "policy.json")

	// Set plugin options via environment
	t.Setenv("CLAUDE_PLUGIN_OPTION_POLICY", policyPath)
	t.Setenv("CLAUDE_PLUGIN_OPTION_STRICT", "false")

	input := `{
		"session_id": "test-session",
		"cwd": "/tmp",
		"hook_event_name": "PreToolUse",
		"tool_name": "Skill",
		"tool_input": {
			"skill": "cli-test"
		},
		"permission_mode": "default"
	}`

	// No --policy flag, should use env
	code, out := runHook(t, "pre-tool-use", []byte(input))
	if code != ExitSuccess {
		t.Fatalf("exit = %d, output:\n%s", code, out)
	}
	if strings.TrimSpace(out) != "" {
		t.Errorf("expected empty output for allowed skill, got: %s", out)
	}
}

func TestPluginOptionsFlagOverridesEnv(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_PLUGIN_DATA", filepath.Join(home, ".claude"))
	t.Setenv("CLAUDE_PROJECT_DIR", "")

	setupHookTest(t, home, "cli-test", true) // tampered
	policyPath := filepath.Join(home, "policy.json")

	// Set wrong policy in env
	t.Setenv("CLAUDE_PLUGIN_OPTION_POLICY", "/fake/wrong.json")
	t.Setenv("CLAUDE_PLUGIN_OPTION_STRICT", "false")

	input := `{
		"session_id": "test-session",
		"cwd": "/tmp",
		"hook_event_name": "PreToolUse",
		"tool_name": "Skill",
		"tool_input": {
			"skill": "cli-test"
		},
		"permission_mode": "default"
	}`

	// Flag overrides env
	code, out := runHook(t, "pre-tool-use", []byte(input), "--policy", policyPath, "--strict=true")
	if code != ExitSuccess {
		t.Fatalf("exit = %d, output:\n%s", code, out)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}

	hookOutput := result["hookSpecificOutput"].(map[string]any)
	if hookOutput["permissionDecision"] != "deny" {
		t.Errorf("strict flag should enforce deny, got: %v", hookOutput)
	}
}

func TestStateDirWithCLAUDE_PLUGIN_DATA(t *testing.T) {
	home := t.TempDir()
	pluginData := filepath.Join(home, ".claude")
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_PLUGIN_DATA", pluginData)

	stateDir := claudecode.StateDir()
	expected := filepath.Join(pluginData, "sessions")
	if stateDir != expected {
		t.Errorf("StateDir() = %s, want %s", stateDir, expected)
	}
}

func TestStateDirWithoutCLAUDE_PLUGIN_DATA(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_PLUGIN_DATA", "")

	stateDir := claudecode.StateDir()
	if !strings.Contains(stateDir, "skill-trust") || !strings.Contains(stateDir, "claude-code") || !strings.Contains(stateDir, "sessions") {
		t.Errorf("StateDir() = %s, should contain skill-trust/claude-code/sessions", stateDir)
	}
}

func TestPreToolUseSymlinkedSkillTampered(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_PLUGIN_DATA", filepath.Join(home, ".claude"))
	t.Setenv("CLAUDE_PROJECT_DIR", "")

	// Create skill in a temp src directory
	srcDir := t.TempDir()
	skillSrc := filepath.Join(srcDir, "foo")
	if err := os.MkdirAll(filepath.Join(skillSrc, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(skillSrc, "SKILL.md"), []byte("---\nname: foo\n---\nTest.\n"), 0o644)
	os.WriteFile(filepath.Join(skillSrc, "scripts/run.sh"), []byte("#!/usr/bin/env bash\necho hi\n"), 0o755)

	// Sign it
	keyPath, pubPath := newKey(t)
	policyPath := keyPolicy(t, pubPath)
	policyDest := filepath.Join(home, "policy.json")
	policyData, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyDest, policyData, 0o644); err != nil {
		t.Fatal(err)
	}
	code, out := runCLI(t, "sign", skillSrc, "--key", keyPath)
	if code != ExitSuccess {
		t.Fatalf("sign exit = %d, output:\n%s", code, out)
	}

	// Tamper
	os.WriteFile(filepath.Join(skillSrc, "SKILL.md"), []byte("---\nname: foo\n---\nTampered!\n"), 0o644)

	// Symlink as ~/.claude/skills/foo
	skillsDir := filepath.Join(home, ".claude", "skills")
	if err := os.MkdirAll(skillsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	skillLink := filepath.Join(skillsDir, "foo")
	if err := os.Symlink(skillSrc, skillLink); err != nil {
		t.Fatal(err)
	}

	// Test via link path
	inputLink := `{
		"session_id": "test-session",
		"cwd": "/tmp",
		"hook_event_name": "PreToolUse",
		"tool_name": "Read",
		"tool_input": {
			"file_path": "` + filepath.Join(skillLink, "SKILL.md") + `"
		},
		"permission_mode": "default"
	}`

	code, out = runHook(t, "pre-tool-use", []byte(inputLink), "--policy", policyDest)
	if code != ExitSuccess {
		t.Fatalf("exit = %d, output:\n%s", code, out)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}

	hookOutput := result["hookSpecificOutput"].(map[string]any)
	if hookOutput["permissionDecision"] != "deny" {
		t.Errorf("symlinked path should deny, got: %v", hookOutput)
	}

	// Test via real path
	inputReal := `{
		"session_id": "test-session",
		"cwd": "/tmp",
		"hook_event_name": "PreToolUse",
		"tool_name": "Read",
		"tool_input": {
			"file_path": "` + filepath.Join(skillSrc, "SKILL.md") + `"
		},
		"permission_mode": "default"
	}`

	code, out = runHook(t, "pre-tool-use", []byte(inputReal), "--policy", policyDest)
	if code != ExitSuccess {
		t.Fatalf("exit = %d, output:\n%s", code, out)
	}

	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}

	hookOutput = result["hookSpecificOutput"].(map[string]any)
	if hookOutput["permissionDecision"] != "deny" {
		t.Errorf("real path should also deny, got: %v", hookOutput)
	}
}

// requireDeny asserts that out is a PreToolUse deny and returns its reason.
func requireDeny(t *testing.T, out string) string {
	t.Helper()
	var result struct {
		HookSpecificOutput struct {
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("expected deny JSON, got %q: %v", out, err)
	}
	if result.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("expected deny, got: %s", out)
	}
	return result.HookSpecificOutput.PermissionDecisionReason
}

// requireBlockPrompt asserts that out is a UserPromptSubmit block and
// returns its reason.
func requireBlockPrompt(t *testing.T, out string) string {
	t.Helper()
	var result struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("expected block JSON, got %q: %v", out, err)
	}
	if result.Decision != "block" {
		t.Fatalf("expected block, got: %s", out)
	}
	return result.Reason
}

// writeUnsignedSkill creates <dir>/SKILL.md (an unsigned skill root).
func writeUnsignedSkill(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# Unsigned\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// isolatedHookEnv points HOME, plugin data and project dir at a temp home
// and returns it with a valid (fixtures key) policy path.
func isolatedHookEnv(t *testing.T) (home, policy string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_PLUGIN_DATA", filepath.Join(home, ".plugin-data"))
	t.Setenv("CLAUDE_PROJECT_DIR", "")
	_, pubPath := newKey(t)
	return home, keyPolicy(t, pubPath)
}

func TestAmbiguousSkillNameChecksEveryMatch(t *testing.T) {
	home, policy := isolatedHookEnv(t)

	// Two plugins each ship an unsigned "deploy" skill.
	installs := map[string]any{}
	for _, plugin := range []string{"a", "b"} {
		installPath := filepath.Join(home, "plugin-installs", plugin)
		writeUnsignedSkill(t, filepath.Join(installPath, "skills", "deploy"))
		installs[plugin+"@market"] = []map[string]string{{"installPath": installPath}}
	}
	data, _ := json.Marshal(map[string]any{"version": 2, "plugins": installs})
	pluginsDir := filepath.Join(home, ".claude", "plugins")
	if err := os.MkdirAll(pluginsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginsDir, "installed_plugins.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	skill := `{"session_id":"s","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Skill","tool_input":{"skill":"deploy"}}`
	code, out := runHook(t, "pre-tool-use", []byte(skill), "--policy", policy)
	if code != ExitSuccess {
		t.Fatalf("exit = %d, output:\n%s", code, out)
	}
	requireDeny(t, out)

	prompt := `{"session_id":"s","cwd":"/tmp","hook_event_name":"UserPromptSubmit","prompt":"/deploy now"}`
	code, out = runHook(t, "user-prompt-submit", []byte(prompt), "--policy", policy)
	if code != ExitSuccess {
		t.Fatalf("exit = %d, output:\n%s", code, out)
	}
	requireBlockPrompt(t, out)
}

func TestDirectoryScopedSkillName(t *testing.T) {
	home, policy := isolatedHookEnv(t)
	project := filepath.Join(home, "project")
	writeUnsignedSkill(t, filepath.Join(project, "apps", "web", ".claude", "skills", "deploy"))

	// Found relative to cwd.
	skill := `{"session_id":"s","cwd":"` + project + `","hook_event_name":"PreToolUse","tool_name":"Skill","tool_input":{"skill":"apps/web:deploy"}}`
	code, out := runHook(t, "pre-tool-use", []byte(skill), "--policy", policy)
	if code != ExitSuccess {
		t.Fatalf("exit = %d, output:\n%s", code, out)
	}
	if reason := requireDeny(t, out); !strings.Contains(reason, filepath.Join("apps", "web", ".claude", "skills", "deploy")) {
		t.Errorf("reason should name the nested root, got: %s", reason)
	}

	// Found relative to CLAUDE_PROJECT_DIR when cwd is elsewhere.
	t.Setenv("CLAUDE_PROJECT_DIR", project)
	skill = `{"session_id":"s","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Skill","tool_input":{"skill":"apps/web:deploy"}}`
	code, out = runHook(t, "pre-tool-use", []byte(skill), "--policy", policy)
	if code != ExitSuccess {
		t.Fatalf("exit = %d, output:\n%s", code, out)
	}
	requireDeny(t, out)

	// Traversal prefixes are rejected (resolve to nothing, so allowed as
	// an unknown name rather than probing arbitrary directories).
	writeUnsignedSkill(t, filepath.Join(home, "outside", ".claude", "skills", "deploy"))
	for _, name := range []string{"../outside:deploy", "apps/../../outside:deploy"} {
		skill = `{"session_id":"s","cwd":"` + project + `","hook_event_name":"PreToolUse","tool_name":"Skill","tool_input":{"skill":"` + name + `"}}`
		code, out = runHook(t, "pre-tool-use", []byte(skill), "--policy", policy)
		if code != ExitSuccess {
			t.Fatalf("%s: exit = %d, output:\n%s", name, code, out)
		}
		if strings.Contains(out, filepath.Join("outside", ".claude")) {
			t.Errorf("%s: traversal prefix must not resolve outside the project, got: %s", name, out)
		}
	}
}

func TestHookDispatchFromSubcommand(t *testing.T) {
	home, policy := isolatedHookEnv(t)
	writeUnsignedSkill(t, filepath.Join(home, ".claude", "skills", "uns"))

	// No hook_event_name: the subcommand decides the event.
	in := `{"session_id":"s","cwd":"/tmp","tool_name":"Skill","tool_input":{"skill":"uns"}}`
	code, out := runHook(t, "pre-tool-use", []byte(in), "--policy", policy)
	if code != ExitSuccess {
		t.Fatalf("exit = %d, output:\n%s", code, out)
	}
	requireDeny(t, out)

	// Event in stdin disagrees with the subcommand: blocking error.
	in = `{"session_id":"s","cwd":"/tmp","hook_event_name":"SessionStart","tool_name":"Skill","tool_input":{"skill":"uns"}}`
	code, out = runHook(t, "pre-tool-use", []byte(in), "--policy", policy)
	if code != ExitError {
		t.Errorf("mismatched event: exit = %d, want %d, output:\n%s", code, ExitError, out)
	}
	if !strings.Contains(out, "skill-trust:") {
		t.Errorf("mismatched event: expected stderr message, got: %s", out)
	}

	// Non-object JSON: blocking error.
	for _, raw := range []string{"null", " null\n", `"text"`, "42", "[]"} {
		code, out = runHook(t, "pre-tool-use", []byte(raw), "--policy", policy)
		if code != ExitError {
			t.Errorf("stdin %q: exit = %d, want %d, output:\n%s", raw, code, ExitError, out)
		}
	}
}

func TestPreToolUseExpandsHomeInCommands(t *testing.T) {
	home, policy := isolatedHookEnv(t)
	writeUnsignedSkill(t, filepath.Join(home, ".claude", "skills", "uns"))

	for _, command := range []string{
		"cat ~/.claude/skills/uns/SKILL.md",
		"cat $HOME/.claude/skills/uns/SKILL.md",
		"cat \"${HOME}/.claude/skills/uns/SKILL.md\"",
	} {
		input, _ := json.Marshal(map[string]any{
			"session_id": "s", "cwd": "/tmp", "hook_event_name": "PreToolUse",
			"tool_name": "Bash", "tool_input": map[string]any{"command": command},
		})
		code, out := runHook(t, "pre-tool-use", input, "--policy", policy)
		if code != ExitSuccess {
			t.Fatalf("%s: exit = %d, output:\n%s", command, code, out)
		}
		requireDeny(t, out)
	}
}

func TestSessionStartReportOnlyCountsUnverified(t *testing.T) {
	home, policy := isolatedHookEnv(t)
	writeUnsignedSkill(t, filepath.Join(home, ".claude", "skills", "uns"))
	setupHookTest(t, home, "good", false)
	policy = filepath.Join(home, "policy.json") // policy matching the signed skill

	in := `{"session_id":"s","cwd":"/tmp","hook_event_name":"SessionStart","source":"startup"}`
	code, out := runHook(t, "session-start", []byte(in), "--policy", policy, "--strict=false")
	if code != ExitSuccess {
		t.Fatalf("exit = %d, output:\n%s", code, out)
	}
	var result struct {
		SystemMessage string `json:"systemMessage"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("bad JSON %q: %v", out, err)
	}
	want := "skill-trust: 1 skills verified, 0 blocked, 1 unverified (report-only)"
	if result.SystemMessage != want {
		t.Errorf("systemMessage = %q, want %q", result.SystemMessage, want)
	}

	// Strict mode keeps the existing format (no unverified part).
	code, out = runHook(t, "session-start", []byte(in), "--policy", policy)
	if code != ExitSuccess {
		t.Fatalf("exit = %d, output:\n%s", code, out)
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("bad JSON %q: %v", out, err)
	}
	if !strings.HasPrefix(result.SystemMessage, "skill-trust: 1 skills verified, 1 blocked (uns: ST-PREFLIGHT-NOT-VERIFIED)") {
		t.Errorf("strict systemMessage = %q", result.SystemMessage)
	}

	// Missing policy in report-only: every skill is reported blocked.
	code, out = runHook(t, "session-start", []byte(in), "--policy", "/nonexistent/policy.json", "--strict=false")
	if code != ExitSuccess {
		t.Fatalf("exit = %d, output:\n%s", code, out)
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("bad JSON %q: %v", out, err)
	}
	if !strings.HasPrefix(result.SystemMessage, "skill-trust: 0 skills verified, 2 blocked") {
		t.Errorf("missing-policy report-only systemMessage = %q", result.SystemMessage)
	}
}
