package verify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/redhat-et/skill-trust/pkg/manifest"
)

// The committed fixture suite (testdata/fixtures) exercises the complete
// signed boundary with expected allow/block results. The pristine fixture
// is committed signed; every other case applies exactly one mutation to a
// copy and asserts the documented outcome. The golden manifest digest is
// recomputed from the checked-out bytes, proving the test vectors are
// stable across platforms (content digests and path rules are identical
// everywhere; git preserves the executable bit on POSIX checkouts).

type fixtureCase struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Mutation    *fixtureMutation `json:"mutation"`
	Expect      fixtureExpect    `json:"expect"`
}

type fixtureMutation struct {
	Op      string `json:"op"`
	Path    string `json:"path"`
	To      string `json:"to"`
	Content string `json:"content"`
	Mode    int    `json:"mode"`
}

type fixtureExpect struct {
	Decision      string `json:"decision"`
	Code          string `json:"code"`
	MatchedSigner string `json:"matchedSigner"`
}

type fixtureSuite struct {
	Fixture        string        `json:"fixture"`
	ManifestDigest string        `json:"manifestDigest"`
	Cases          []fixtureCase `json:"cases"`
}

func loadFixtureSuite(t *testing.T) fixtureSuite {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "fixtures", "expected.json"))
	if err != nil {
		t.Fatalf("reading expected.json: %v", err)
	}
	var suite fixtureSuite
	if err := json.Unmarshal(raw, &suite); err != nil {
		t.Fatalf("parsing expected.json: %v", err)
	}
	if suite.Fixture == "" || suite.ManifestDigest == "" || len(suite.Cases) == 0 {
		t.Fatalf("expected.json is missing fixture, manifestDigest, or cases")
	}
	return suite
}

// copyFixture copies the committed fixture (control files included) into a
// temporary directory, preserving modes.
func copyFixture(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if err := os.WriteFile(target, data, info.Mode().Perm()); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatalf("copying fixture: %v", err)
	}
	return dst
}

// applyMutation mutates a copied fixture. The mutation vocabulary mirrors
// the tamper classes the manifest spec calls out: content changes, added,
// deleted, and renamed files, executable-bit flips, control-file removal,
// and an embedded-manifest forgery.
func applyMutation(t *testing.T, dir string, m *fixtureMutation) {
	t.Helper()
	if m == nil {
		return
	}
	join := func(rel string) string { return filepath.Join(dir, filepath.FromSlash(rel)) }
	switch m.Op {
	case "write":
		if err := os.WriteFile(join(m.Path), []byte(m.Content), 0o644); err != nil {
			t.Fatalf("write %s: %v", m.Path, err)
		}
	case "remove":
		if err := os.Remove(join(m.Path)); err != nil {
			t.Fatalf("remove %s: %v", m.Path, err)
		}
	case "remove-all":
		if err := os.RemoveAll(join(m.Path)); err != nil {
			t.Fatalf("remove-all %s: %v", m.Path, err)
		}
	case "rename":
		if err := os.Rename(join(m.Path), join(m.To)); err != nil {
			t.Fatalf("rename %s -> %s: %v", m.Path, m.To, err)
		}
	case "chmod":
		if err := os.Chmod(join(m.Path), os.FileMode(m.Mode)); err != nil {
			t.Fatalf("chmod %s: %v", m.Path, err)
		}
	case "corrupt-manifest":
		// Rewrite the embedded manifest with one altered entry digest: a
		// structurally valid forgery that no longer matches the content on
		// disk (nor the signature).
		path := join(".skill-trust/manifest.json")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading embedded manifest: %v", err)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("parsing embedded manifest: %v", err)
		}
		entries := doc["entries"].([]any)
		entry := entries[0].(map[string]any)
		digest := entry["digest"].(string)
		forged := []byte(digest)
		if forged[0] == 'f' {
			forged[0] = '0'
		} else {
			forged[0] = 'f'
		}
		entry["digest"] = string(forged)
		out, err := json.Marshal(doc)
		if err != nil {
			t.Fatalf("re-marshaling forged manifest: %v", err)
		}
		if err := os.WriteFile(path, out, 0o644); err != nil {
			t.Fatalf("writing forged manifest: %v", err)
		}
	default:
		t.Fatalf("unknown mutation op %q", m.Op)
	}
}

// loadFixturePolicy loads a committed fixture policy, rewriting relative
// key and trust-root paths to absolute ones so the policy works from any
// working directory (the committed files stay usable from the CLI, where
// they resolve relative to the fixtures directory).
func loadFixturePolicy(path string) (*Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	base := filepath.Dir(path)
	for _, s := range doc["signers"].([]any) {
		rule := s.(map[string]any)
		if pk, ok := rule["publicKey"].(map[string]any); ok {
			if rel, ok := pk["path"].(string); ok {
				pk["path"] = filepath.Join(base, filepath.FromSlash(rel))
			}
		}
	}
	if roots, ok := doc["trustRoots"].(map[string]any); ok {
		for _, r := range roots {
			root, ok := r.(map[string]any)
			if !ok || root["type"] != "trusted-root" {
				continue
			}
			if rel, ok := root["path"].(string); ok {
				root["path"] = filepath.Join(base, filepath.FromSlash(rel))
			}
		}
	}
	patched, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return ParsePolicy(patched)
}

func TestSignedFixtureSuite(t *testing.T) {
	suite := loadFixtureSuite(t)
	fixtureDir := filepath.Join("..", "..", "testdata", "fixtures", suite.Fixture)
	policyPath := filepath.Join("..", "..", "testdata", "fixtures", "policy.json")

	// The golden digest is recomputed from the checked-out bytes on every
	// platform the suite runs on.
	m, err := manifest.Create(fixtureDir)
	if err != nil {
		t.Fatalf("Create fixture manifest: %v", err)
	}
	digest, err := m.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if digest != suite.ManifestDigest {
		t.Errorf("fixture manifest digest = %s, want golden %s (content or executable bits differ from the committed fixture)", digest, suite.ManifestDigest)
	}

	policy, err := loadFixturePolicy(policyPath)
	if err != nil {
		t.Fatalf("loading fixture policy: %v", err)
	}
	verifier, err := New(policy)
	if err != nil {
		t.Fatalf("New verifier: %v", err)
	}

	for _, tc := range suite.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			dir := copyFixture(t, fixtureDir)
			applyMutation(t, dir, tc.Mutation)

			result, err := verifier.VerifySkill(dir)
			if err != nil {
				t.Fatalf("VerifySkill: %v", err)
			}

			if string(result.Decision) != tc.Expect.Decision {
				t.Errorf("decision = %s, want %s (findings: %s)", result.Decision, tc.Expect.Decision, findingSummary(result))
			}

			switch tc.Expect.Decision {
			case "allow":
				if len(result.Signatures) != 1 || !result.Signatures[0].Matched {
					t.Errorf("expected the fixtures-key signature to match, got %+v", result.Signatures)
				}
			case "block":
				if tc.Expect.Code == "" {
					t.Fatal("expected.json block case is missing a finding code")
				}
				if !hasFindingCode(result, tc.Expect.Code) {
					t.Errorf("no finding with code %s (findings: %s)", tc.Expect.Code, findingSummary(result))
				}
			default:
				t.Fatalf("unknown expected decision %q", tc.Expect.Decision)
			}
		})
	}
}

// TestFixturePayloadsAreSafe pins the invariant that fixture scripts are
// inert: they contain no network calls, no filesystem writes outside echo,
// and no secret material. The suite exists to exercise verification, not
// to run payloads.
func TestFixturePayloadsAreSafe(t *testing.T) {
	suite := loadFixtureSuite(t)
	fixtureDir := filepath.Join("..", "..", "testdata", "fixtures", suite.Fixture)

	dangerous := []string{
		"curl ", "wget ", "nc ", "ssh ", "eval ", "base64 -d",
		"os.system", "subprocess", "socket", "requests",
		"child_process", "fetch(", "process.env",
		"rm -rf", "sudo ",
	}
	err := filepath.WalkDir(fixtureDir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, needle := range dangerous {
			if bytes.Contains(data, []byte(needle)) {
				return fmt.Errorf("fixture payload %s contains %q: fixtures must stay inert", p, needle)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func findingSummary(r Result) string {
	out := ""
	for i, f := range r.Findings {
		if i > 0 {
			out += "; "
		}
		out += f.Code + ": " + f.Message
	}
	return out
}

// The cross-root suite: a bundle signed keyless against the shared RHTAS
// instance (captured from a CI run) verified offline against pinned
// policies, including failure modes against the wrong trust root, the
// wrong signer identity, and modified content.
type crossRootCase struct {
	Name     string           `json:"name"`
	Fixture  string           `json:"fixture"`
	Policy   string           `json:"policy"`
	Mutation *fixtureMutation `json:"mutation"`
	Expect   fixtureExpect    `json:"expect"`
}

type crossRootSuite struct {
	Cases []crossRootCase `json:"cases"`
}

func TestCrossRootFixtureSuite(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "fixtures", "cross-root.json"))
	if err != nil {
		t.Fatalf("reading cross-root.json: %v", err)
	}
	var suite crossRootSuite
	if err := json.Unmarshal(raw, &suite); err != nil {
		t.Fatalf("parsing cross-root.json: %v", err)
	}
	if len(suite.Cases) == 0 {
		t.Fatal("cross-root.json has no cases")
	}

	fixturesDir := filepath.Join("..", "..", "testdata", "fixtures")

	for _, tc := range suite.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			fixtureDir := filepath.Join(fixturesDir, tc.Fixture)
			policy, err := loadFixturePolicy(filepath.Join(fixturesDir, tc.Policy))
			if err != nil {
				t.Fatalf("loading policy: %v", err)
			}
			verifier, err := New(policy)
			if err != nil {
				t.Fatalf("New verifier: %v", err)
			}

			dir := copyFixture(t, fixtureDir)
			applyMutation(t, dir, tc.Mutation)

			result, err := verifier.VerifySkill(dir)
			if err != nil {
				t.Fatalf("VerifySkill: %v", err)
			}

			if string(result.Decision) != tc.Expect.Decision {
				t.Errorf("decision = %s, want %s (findings: %s)", result.Decision, tc.Expect.Decision, findingSummary(result))
			}
			switch tc.Expect.Decision {
			case "allow":
				if len(result.Signatures) != 1 || !result.Signatures[0].Matched {
					t.Errorf("expected the signature to match, got %+v", result.Signatures)
				}
			case "block":
				// A block's reason may be recorded at the top level (for
				// example ST-CONTENT-MISMATCH) or per signature rule (for
				// example ST-SIGNATURE-INVALID under ST-POLICY-NO-MATCH),
				// so the expected code is matched against the union.
				if !hasFindingCode(result, tc.Expect.Code) {
					t.Errorf("no finding with code %s (findings: %s)", tc.Expect.Code, findingSummary(result))
				}
			}
		})
	}
}

// hasFindingCode reports whether the code appears in the result's
// top-level findings or in any per-signature-rule finding.
func hasFindingCode(r Result, code string) bool {
	for _, f := range r.Findings {
		if f.Code == code {
			return true
		}
	}
	for _, s := range r.Signatures {
		for _, f := range s.Findings {
			if f.Code == code {
				return true
			}
		}
	}
	return false
}
