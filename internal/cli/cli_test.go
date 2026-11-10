package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runCLI executes the CLI in-process and returns the exit code and
// combined output.
func runCLI(t *testing.T, args ...string) (int, string) {
	t.Helper()

	// Reset global command state between runs.
	exitCode = ExitSuccess
	jsonOutput = false
	manifestWrite = false
	verifyPolicy = ""
	verifyReport = false
	signKey, signIDToken, signServices = "", "", ""

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs(args)
	err := rootCmd.Execute()
	code := exitCode
	if err != nil {
		code = ExitError
	}
	return code, buf.String()
}

// newSkill creates a skill fixture and returns its directory.
func newSkill(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write := func(rel, content string, mode os.FileMode) {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("SKILL.md", "---\nname: cli-test\n---\nTest skill.\n", 0o644)
	write("scripts/run.sh", "#!/usr/bin/env bash\necho hi\n", 0o755)
	write("scripts/util.py", "print('hi')\n", 0o644)
	return dir
}

// newKey generates a key pair and writes the private and public PEM files.
func newKey(t *testing.T) (keyPath, pubPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	keyPath = filepath.Join(tmp, "release.key")
	pubPath = filepath.Join(tmp, "release.pub")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	return keyPath, pubPath
}

// keyPolicy writes a key-based policy for pubPath.
func keyPolicy(t *testing.T, pubPath string) string {
	t.Helper()
	doc := `{
  "apiVersion": "skill-trust.policy/v1",
  "signers": [{
    "name": "release-key",
    "mode": "key",
    "publicKey": {"path": "` + pubPath + `"},
    "requireTransparencyLog": false
  }]
}`
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// signedSkill returns a key-signed skill directory and its policy path.
func signedSkill(t *testing.T) (dir, policyPath string) {
	t.Helper()
	dir = newSkill(t)
	keyPath, pubPath := newKey(t)
	code, out := runCLI(t, "sign", dir, "--key", keyPath)
	if code != ExitSuccess {
		t.Fatalf("sign exit = %d, output:\n%s", code, out)
	}
	return dir, keyPolicy(t, pubPath)
}

func TestManifestCommand(t *testing.T) {
	dir := newSkill(t)
	code, out := runCLI(t, "manifest", dir)
	if code != ExitSuccess {
		t.Fatalf("exit = %d, output:\n%s", code, out)
	}
	for _, want := range []string{"digest:", "files:     3 (1 executable)"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, ".skill-trust", "manifest.json")); !os.IsNotExist(err) {
		t.Error("manifest command must not write control files without --write")
	}
}

func TestManifestWriteAndJSON(t *testing.T) {
	dir := newSkill(t)
	code, out := runCLI(t, "manifest", dir, "--write", "--json")
	if code != ExitSuccess {
		t.Fatalf("exit = %d, output:\n%s", code, out)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if doc["digest"] == nil || doc["entryCount"] != float64(3) {
		t.Errorf("unexpected JSON manifest: %s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, ".skill-trust", "manifest.json")); err != nil {
		t.Fatalf("--write did not embed the manifest: %v", err)
	}
}

func TestSignAndVerifyAllow(t *testing.T) {
	dir, policy := signedSkill(t)

	code, out := runCLI(t, "verify", dir, "--policy", policy)
	if code != ExitSuccess {
		t.Fatalf("verify exit = %d, output:\n%s", code, out)
	}
	if !strings.Contains(out, "ALLOW") || !strings.Contains(out, "release-key") {
		t.Errorf("unexpected verify output:\n%s", out)
	}
}

func TestVerifyJSONOutput(t *testing.T) {
	dir, policy := signedSkill(t)
	code, out := runCLI(t, "verify", dir, "--policy", policy, "--json")
	if code != ExitSuccess {
		t.Fatalf("exit = %d, output:\n%s", code, out)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if doc["decision"] != "allow" {
		t.Errorf("decision = %v, output:\n%s", doc["decision"], out)
	}
}

func TestVerifyReport(t *testing.T) {
	dir, policy := signedSkill(t)
	code, _ := runCLI(t, "verify", dir, "--policy", policy, "--report")
	if code != ExitSuccess {
		t.Fatalf("exit = %d", code)
	}
	raw, err := os.ReadFile(filepath.Join(dir, ".skill-trust", "report.json"))
	if err != nil {
		t.Fatalf("report not written: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("report is not JSON: %v", err)
	}
	if doc["decision"] != "allow" {
		t.Errorf("report decision = %v", doc["decision"])
	}
}

func TestVerifyTamperedBlocks(t *testing.T) {
	dir, policy := signedSkill(t)
	if err := os.WriteFile(filepath.Join(dir, "scripts", "util.py"), []byte("print('evil')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out := runCLI(t, "verify", dir, "--policy", policy)
	if code != ExitBlocked {
		t.Fatalf("exit = %d, want %d, output:\n%s", code, ExitBlocked, out)
	}
	if !strings.Contains(out, "BLOCK") || !strings.Contains(out, "ST-CONTENT-MISMATCH") {
		t.Errorf("unexpected verify output:\n%s", out)
	}
}

func TestVerifyWrongKeyBlocks(t *testing.T) {
	dir, _ := signedSkill(t)
	_, otherPub := newKey(t)
	code, out := runCLI(t, "verify", dir, "--policy", keyPolicy(t, otherPub))
	if code != ExitBlocked {
		t.Fatalf("exit = %d, want %d, output:\n%s", code, ExitBlocked, out)
	}
	if !strings.Contains(out, "ST-POLICY-NO-MATCH") {
		t.Errorf("unexpected verify output:\n%s", out)
	}
}

func TestVerifyUnsignedBlocks(t *testing.T) {
	dir := newSkill(t)
	_, pubPath := newKey(t)
	code, out := runCLI(t, "verify", dir, "--policy", keyPolicy(t, pubPath))
	if code != ExitBlocked {
		t.Fatalf("exit = %d, want %d, output:\n%s", code, ExitBlocked, out)
	}
	if !strings.Contains(out, "ST-METADATA-MISSING") {
		t.Errorf("unexpected verify output:\n%s", out)
	}
}

func TestVerifyOperationalErrors(t *testing.T) {
	dir, _ := signedSkill(t)

	if code, _ := runCLI(t, "verify", dir, "--policy", "/nonexistent.json"); code != ExitError {
		t.Errorf("missing policy exit = %d, want %d", code, ExitError)
	}
	if code, _ := runCLI(t, "verify"); code != ExitError {
		t.Errorf("missing argument exit = %d, want %d", code, ExitError)
	}
	// Policy referencing a missing trust root file fails at verifier
	// construction, before any decision: an operational error.
	badPolicy := filepath.Join(t.TempDir(), "bad.json")
	doc := `{"apiVersion": "skill-trust.policy/v1", "trustRoots": {"ghost": {"type": "trusted-root", "path": "/nonexistent.json"}}, "signers": [{"name": "k", "mode": "keyless", "certificate": {"identities": ["a"], "issuer": "i"}, "trustRoot": "ghost"}]}`
	if err := os.WriteFile(badPolicy, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _ := runCLI(t, "verify", dir, "--policy", badPolicy); code != ExitError {
		t.Errorf("unusable trust root exit = %d, want %d", code, ExitError)
	}
}

func TestSignRejectsConflictingModes(t *testing.T) {
	dir := newSkill(t)
	if code, _ := runCLI(t, "sign", dir, "--key", "a", "--id-token", "b"); code != ExitError {
		t.Errorf("conflicting modes exit = %d, want %d", code, ExitError)
	}
	if code, _ := runCLI(t, "sign", dir); code != ExitError {
		t.Errorf("no mode exit = %d, want %d", code, ExitError)
	}
}

func TestSignIDTokenFile(t *testing.T) {
	dir := newSkill(t)
	tokenFile := filepath.Join(t.TempDir(), "token.txt")
	if err := os.WriteFile(tokenFile, []byte("  fake-token  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Keyless without services fails at options validation (no Fulcio),
	// but only after the @file token has been read: an operational error.
	code, out := runCLI(t, "sign", dir, "--id-token", "@"+tokenFile)
	if code != ExitError {
		t.Fatalf("exit = %d, want %d, output:\n%s", code, ExitError, out)
	}
}

func TestInspect(t *testing.T) {
	dir, _ := signedSkill(t)
	code, out := runCLI(t, "inspect", dir)
	if code != ExitSuccess {
		t.Fatalf("exit = %d, output:\n%s", code, out)
	}
	for _, want := range []string{"matches signed manifest", "signer:    key", "bundle:"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}

	// Tamper: inspect reports drift without failing.
	if err := os.WriteFile(filepath.Join(dir, "scripts", "util.py"), []byte("print('evil')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out = runCLI(t, "inspect", dir)
	if code != ExitSuccess {
		t.Fatalf("exit = %d after tamper, output:\n%s", code, out)
	}
	if !strings.Contains(out, "difference(s) from signed manifest") {
		t.Errorf("tamper not reported:\n%s", out)
	}
}

func TestInspectUnsignedIsOperationalError(t *testing.T) {
	dir := newSkill(t)
	code, _ := runCLI(t, "inspect", dir)
	if code != ExitError {
		t.Errorf("exit = %d, want %d", code, ExitError)
	}
}

func TestInspectJSON(t *testing.T) {
	dir, _ := signedSkill(t)
	code, out := runCLI(t, "inspect", dir, "--json")
	if code != ExitSuccess {
		t.Fatalf("exit = %d, output:\n%s", code, out)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if doc["digest"] == nil || doc["contentStatus"] != "matches signed manifest" {
		t.Errorf("unexpected inspect JSON:\n%s", out)
	}
}
