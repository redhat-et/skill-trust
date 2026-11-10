package verify

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	testingca "github.com/sigstore/sigstore-go/pkg/testing/ca"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/redhat-et/skill-trust/pkg/manifest"
	"github.com/redhat-et/skill-trust/pkg/preflight"
)

func findingCodes(r Result) []string {
	codes := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		codes = append(codes, f.Code)
	}
	return codes
}

func hasCode(r Result, code string) bool {
	for _, f := range r.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

func verifyWithPolicy(t *testing.T, dir, policyDoc string) Result {
	t.Helper()
	p, err := ParsePolicy([]byte(policyDoc))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	v, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := v.VerifySkill(dir)
	if err != nil {
		t.Fatalf("VerifySkill: %v", err)
	}
	return res
}

// ---- Key-based full stack ----

func TestVerifyKeyBasedAllow(t *testing.T) {
	dir := testSkill(t)
	keyPath, pubPath := keyFiles(t)
	signWithKey(t, dir, keyPath)

	res := verifyWithPolicy(t, dir, keyPolicyJSON(pubPath, `,"requireTransparencyLog": false`))
	if !res.Allowed() {
		t.Fatalf("decision = %s, findings = %+v", res.Decision, res.Findings)
	}
	if res.ManifestDigest == "" || res.ManifestDigest != res.ObservedDigest {
		t.Errorf("digests: expected %q observed %q", res.ManifestDigest, res.ObservedDigest)
	}
	if len(res.Signatures) != 1 || !res.Signatures[0].Matched {
		t.Fatalf("signatures = %+v", res.Signatures)
	}
	sr := res.Signatures[0]
	if sr.Mode != ModeKey || sr.KeyHint == "" {
		t.Errorf("signature result = %+v", sr)
	}
	if !strings.Contains(res.Signer, "release-key") {
		t.Errorf("signer = %q", res.Signer)
	}
	if len(res.Findings) != 0 {
		t.Errorf("findings on allow: %+v", res.Findings)
	}
}

func TestVerifyKeyBasedWrongKey(t *testing.T) {
	dir := testSkill(t)
	keyPath, _ := keyFiles(t)
	signWithKey(t, dir, keyPath)

	_, otherPub := keyFiles(t)
	res := verifyWithPolicy(t, dir, keyPolicyJSON(otherPub, `,"requireTransparencyLog": false`))
	if res.Allowed() {
		t.Fatal("foreign-key signature allowed")
	}
	if !hasCode(res, CodePolicyNoMatch) {
		t.Errorf("findings = %v, want %s", findingCodes(res), CodePolicyNoMatch)
	}
	if len(res.Signatures) != 1 || res.Signatures[0].Matched {
		t.Fatalf("signatures = %+v", res.Signatures)
	}
	if !hasCode(res, CodeSignatureInvalid) && len(res.Signatures[0].Findings) == 0 {
		t.Errorf("per-rule findings missing: %+v", res.Signatures[0])
	}
}

func TestVerifyTamperedContent(t *testing.T) {
	dir := testSkill(t)
	keyPath, pubPath := keyFiles(t)
	signWithKey(t, dir, keyPath)

	if err := os.WriteFile(filepath.Join(dir, "scripts", "util.py"), []byte("print('evil')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := verifyWithPolicy(t, dir, keyPolicyJSON(pubPath, `,"requireTransparencyLog": false`))
	if res.Allowed() {
		t.Fatal("tampered content allowed")
	}
	if !hasCode(res, CodeContentMismatch) {
		t.Errorf("findings = %v, want %s", findingCodes(res), CodeContentMismatch)
	}
	// The signature stage is never reached for mismatched content.
	if len(res.Signatures) != 0 {
		t.Errorf("signatures evaluated despite content mismatch: %+v", res.Signatures)
	}
	if res.ObservedDigest == res.ManifestDigest {
		t.Error("observed digest should differ from expected")
	}
}

func TestVerifyAddedFile(t *testing.T) {
	dir := testSkill(t)
	keyPath, pubPath := keyFiles(t)
	signWithKey(t, dir, keyPath)

	if err := os.WriteFile(filepath.Join(dir, "scripts", "evil.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	res := verifyWithPolicy(t, dir, keyPolicyJSON(pubPath, `,"requireTransparencyLog": false`))
	if res.Allowed() || !hasCode(res, CodeContentMismatch) {
		t.Fatalf("added file not blocked: %+v", res.Findings)
	}
}

func TestVerifyUnsignedSkill(t *testing.T) {
	dir := testSkill(t)
	_, pubPath := keyFiles(t)

	res := verifyWithPolicy(t, dir, keyPolicyJSON(pubPath, ""))
	if res.Allowed() || !hasCode(res, CodeMetadataMissing) {
		t.Fatalf("unsigned skill not blocked with missing metadata: %+v", res.Findings)
	}
}

func TestVerifyMalformedBundle(t *testing.T) {
	dir := testSkill(t)
	keyPath, pubPath := keyFiles(t)
	signWithKey(t, dir, keyPath)

	bundlePath := manifest.ControlPath(dir, manifest.BundleFile)
	if err := os.WriteFile(bundlePath, []byte("{definitely not a bundle"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := verifyWithPolicy(t, dir, keyPolicyJSON(pubPath, `,"requireTransparencyLog": false`))
	if res.Allowed() || !hasCode(res, CodeMetadataMalformed) {
		t.Fatalf("malformed bundle not blocked: %+v", res.Findings)
	}
}

func TestVerifyKeylessPolicyAgainstKeyBundle(t *testing.T) {
	dir := testSkill(t)
	keyPath, _ := keyFiles(t)
	signWithKey(t, dir, keyPath)

	vs, err := testingca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	rootPath := virtualTrustedRoot(t, vs)
	doc := keylessPolicyJSON(rootPath, "someone@example.com", "https://example.com", "")
	res := verifyWithPolicy(t, dir, doc)
	if res.Allowed() || !hasCode(res, CodePolicyNoMatch) {
		t.Fatalf("key bundle matched a keyless policy: %+v", res.Findings)
	}
}

// ---- Keyless full stack (offline, via the virtual Sigstore) ----

func TestVerifyKeylessAllow(t *testing.T) {
	vs, err := testingca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	rootPath := virtualTrustedRoot(t, vs)
	dir := writeKeylessSkill(t, vs, "ci-bot@example.com", "https://token.example.com", true, true)

	res := verifyWithPolicy(t, dir, keylessPolicyJSON(rootPath, "ci-bot@example.com", "https://token.example.com", ""))
	if !res.Allowed() {
		t.Fatalf("decision = %s, findings = %+v, signatures = %+v", res.Decision, res.Findings, res.Signatures)
	}
	sr := res.Signatures[0]
	if sr.Mode != ModeKeyless || sr.Identity != "ci-bot@example.com" || sr.Issuer != "https://token.example.com" {
		t.Errorf("signature result = %+v", sr)
	}
	if !strings.Contains(res.Signer, "ci-workflow") {
		t.Errorf("signer = %q", res.Signer)
	}
}

func TestVerifyKeylessIdentityMismatch(t *testing.T) {
	vs, err := testingca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	rootPath := virtualTrustedRoot(t, vs)
	dir := writeKeylessSkill(t, vs, "ci-bot@example.com", "https://token.example.com", true, true)

	res := verifyWithPolicy(t, dir, keylessPolicyJSON(rootPath, "other-bot@example.com", "https://token.example.com", ""))
	if res.Allowed() || !hasCode(res, CodePolicyNoMatch) {
		t.Fatalf("identity mismatch allowed: %+v", res.Findings)
	}
}

func TestVerifyKeylessIssuerMismatch(t *testing.T) {
	vs, err := testingca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	rootPath := virtualTrustedRoot(t, vs)
	dir := writeKeylessSkill(t, vs, "ci-bot@example.com", "https://token.example.com", true, true)

	res := verifyWithPolicy(t, dir, keylessPolicyJSON(rootPath, "ci-bot@example.com", "https://evil.example.com", ""))
	if res.Allowed() || !hasCode(res, CodePolicyNoMatch) {
		t.Fatalf("issuer mismatch allowed: %+v", res.Findings)
	}
}

func TestVerifyKeylessMissingTlog(t *testing.T) {
	vs, err := testingca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	rootPath := virtualTrustedRoot(t, vs)
	// Bundle with TSA timestamp but no transparency log entry.
	dir := writeKeylessSkill(t, vs, "ci-bot@example.com", "https://token.example.com", false, true)

	res := verifyWithPolicy(t, dir, keylessPolicyJSON(rootPath, "ci-bot@example.com", "https://token.example.com", ""))
	if res.Allowed() {
		t.Fatal("missing transparency log allowed under default policy")
	}
	found := false
	for _, f := range res.Signatures[0].Findings {
		if f.Code == CodeEvidenceTlogMissing {
			found = true
		}
	}
	if !found {
		t.Fatalf("per-rule findings = %+v, want %s", res.Signatures[0].Findings, CodeEvidenceTlogMissing)
	}
}

func TestVerifyKeylessTlogOptional(t *testing.T) {
	vs, err := testingca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	rootPath := virtualTrustedRoot(t, vs)
	// No tlog entry, but an RFC 3161 timestamp is present; the policy
	// accepts signatures without transparency log entries.
	dir := writeKeylessSkill(t, vs, "ci-bot@example.com", "https://token.example.com", false, true)

	res := verifyWithPolicy(t, dir, keylessPolicyJSON(rootPath, "ci-bot@example.com", "https://token.example.com", `,"requireTransparencyLog": false`))
	if !res.Allowed() {
		t.Fatalf("decision = %s, findings = %+v, signatures = %+v", res.Decision, res.Findings, res.Signatures)
	}
}

func TestVerifyKeylessProvenanceMismatch(t *testing.T) {
	vs, err := testingca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	rootPath := virtualTrustedRoot(t, vs)
	dir := writeKeylessSkill(t, vs, "ci-bot@example.com", "https://token.example.com", true, true)

	res := verifyWithPolicy(t, dir, keylessPolicyJSON(rootPath, "ci-bot@example.com", "https://token.example.com",
		`,"provenance": {"sourceRepository": "acme/skills"}`))
	if res.Allowed() {
		t.Fatal("provenance mismatch allowed")
	}
	found := false
	for _, f := range res.Signatures[0].Findings {
		if f.Code == CodeProvenanceMismatch {
			found = true
		}
	}
	if !found {
		t.Fatalf("per-rule findings = %+v, want %s", res.Signatures[0].Findings, CodeProvenanceMismatch)
	}
}

// ---- Pure evaluators ----

func TestCheckProvenance(t *testing.T) {
	summary := summaryWith(sourceRepo, sourceRef, workflow, sha)
	if f := checkProvenance(ProvenanceConstraints{SourceRepository: sourceRepo}, summary); f != nil {
		t.Errorf("matching repo rejected: %+v", f)
	}
	if f := checkProvenance(ProvenanceConstraints{WorkflowName: workflow, CommitSha: sha}, summary); f != nil {
		t.Errorf("matching workflow/sha rejected: %+v", f)
	}
	if f := checkProvenance(ProvenanceConstraints{}, summary); f != nil {
		t.Errorf("empty constraints rejected: %+v", f)
	}
	if f := checkProvenance(ProvenanceConstraints{SourceRepository: "evil/repo"}, summary); f == nil || f.Code != CodeProvenanceMismatch {
		t.Errorf("wrong repo not rejected: %+v", f)
	}
	if f := checkProvenance(ProvenanceConstraints{SourceRef: "refs/heads/evil"}, summary); f == nil || f.Code != CodeProvenanceMismatch {
		t.Errorf("wrong ref not rejected: %+v", f)
	}
	if f := checkProvenance(ProvenanceConstraints{CommitSha: "deadbeef"}, summary); f == nil || f.Code != CodeProvenanceMismatch {
		t.Errorf("wrong sha not rejected: %+v", f)
	}
	// Empty certificate claims never match a constraint.
	if f := checkProvenance(ProvenanceConstraints{WorkflowName: workflow}, summaryWith("", "", "", "")); f == nil {
		t.Error("empty claims matched a constraint")
	}
}

func TestCheckFreshness(t *testing.T) {
	now := time.Now()
	fresh := []sgverify.TimestampVerificationResult{{Timestamp: now.Add(-time.Minute)}}
	stale := []sgverify.TimestampVerificationResult{{Timestamp: now.Add(-48 * time.Hour)}}
	mixed := []sgverify.TimestampVerificationResult{
		{Timestamp: now.Add(-72 * time.Hour)},
		{Timestamp: now.Add(-time.Minute)},
	}

	if f := checkFreshness(time.Hour, fresh); f != nil {
		t.Errorf("fresh signature rejected: %+v", f)
	}
	if f := checkFreshness(24*time.Hour, stale); f == nil || f.Code != CodeEvidenceStale {
		t.Errorf("stale signature not rejected: %+v", f)
	}
	// The newest timestamp counts.
	if f := checkFreshness(24*time.Hour, mixed); f != nil {
		t.Errorf("mixed timestamps rejected on the newest: %+v", f)
	}
	// No timestamps: nothing to judge (evidence requirements police this).
	if f := checkFreshness(time.Hour, nil); f != nil {
		t.Errorf("no timestamps rejected: %+v", f)
	}
}

// ---- Preflight adapter ----

func TestPreflightAdapter(t *testing.T) {
	dir := testSkill(t)
	keyPath, pubPath := keyFiles(t)
	signWithKey(t, dir, keyPath)

	p, err := ParsePolicy([]byte(keyPolicyJSON(pubPath, `,"requireTransparencyLog": false`)))
	if err != nil {
		t.Fatal(err)
	}
	v, err := New(p)
	if err != nil {
		t.Fatal(err)
	}

	pf := preflight.New(v.PreflightVerifier())
	vs, err := pf.VerifyBeforeLoad(dir)
	if err != nil {
		t.Fatalf("VerifyBeforeLoad: %v", err)
	}
	if vs.ManifestDigest == "" {
		t.Error("verified record has no digest")
	}
	if err := pf.GuardExecution(filepath.Join(dir, "scripts", "run.sh")); err != nil {
		t.Fatalf("GuardExecution on clean skill: %v", err)
	}

	// Tamper after load: the guard must block.
	if err := os.WriteFile(filepath.Join(dir, "scripts", "util.py"), []byte("print('evil')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err = pf.GuardExecution(filepath.Join(dir, "scripts", "util.py"))
	if err == nil {
		t.Fatal("tampered skill passed the guard")
	}
	var be *preflight.BlockError
	if !errors.As(err, &be) {
		t.Fatalf("err = %T, want *preflight.BlockError", err)
	}
}

// ---- Result JSON shape ----

func TestResultJSON(t *testing.T) {
	dir := testSkill(t)
	keyPath, pubPath := keyFiles(t)
	signWithKey(t, dir, keyPath)
	res := verifyWithPolicy(t, dir, keyPolicyJSON(pubPath, `,"requireTransparencyLog": false`))

	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"decision", "manifestDigest", "observedDigest", "signer", "signatures"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("marshaled result missing %q: %s", key, b)
		}
	}
	if doc["decision"] != string(preflight.Allow) {
		t.Errorf("decision = %v", doc["decision"])
	}
}

func TestVerifierRejectsNilAndEmpty(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, ErrMalformedInput) {
		t.Fatalf("err = %v, want ErrMalformedInput", err)
	}
}
