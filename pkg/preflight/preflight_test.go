package preflight

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/redhat-et/skill-trust/pkg/manifest"
)

// fixture creates a signed-shape skill directory: content plus an embedded
// control manifest generated from the content.
func fixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: t\n---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scripts", "run.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scripts", "util.py"), []byte("print(1)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Create(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.WriteControlManifest(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestVerifyBeforeLoadAllowsCleanSkill(t *testing.T) {
	dir := fixture(t)
	p := New(ManifestVerifier{})

	vs, err := p.VerifyBeforeLoad(dir)
	if err != nil {
		t.Fatalf("VerifyBeforeLoad: %v", err)
	}
	if vs.Root == "" || vs.ManifestDigest == "" {
		t.Errorf("verified record incomplete: %+v", vs)
	}
}

func TestVerifyBeforeLoadBlocksUnsignedSkill(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := New(ManifestVerifier{})

	_, err := p.VerifyBeforeLoad(dir)
	if err == nil {
		t.Fatal("expected block for unsigned skill")
	}
	var be *BlockError
	if !errors.As(err, &be) {
		t.Fatalf("err = %T, want *BlockError", err)
	}
	if be.Code != CodeVerifierFailure {
		t.Errorf("code = %s, want %s", be.Code, CodeVerifierFailure)
	}
}

func TestGuardExecutionAllowsUnchangedScript(t *testing.T) {
	dir := fixture(t)
	p := New(ManifestVerifier{})
	if _, err := p.VerifyBeforeLoad(dir); err != nil {
		t.Fatal(err)
	}

	for _, rel := range []string{"scripts/run.sh", "scripts/util.py", "SKILL.md"} {
		if err := p.GuardExecution(filepath.Join(dir, rel)); err != nil {
			t.Errorf("GuardExecution(%s): %v", rel, err)
		}
	}
}

func TestGuardExecutionBlocksTamperedScript(t *testing.T) {
	dir := fixture(t)
	p := New(ManifestVerifier{})
	vs, err := p.VerifyBeforeLoad(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "scripts", "util.py"), []byte("print('evil')\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	err = p.GuardExecution(filepath.Join(dir, "scripts", "util.py"))
	if err == nil {
		t.Fatal("expected block after tampering")
	}
	var be *BlockError
	if !errors.As(err, &be) {
		t.Fatalf("err = %T, want *BlockError", err)
	}
	if be.Code != CodeChangedAfterVerify {
		t.Errorf("code = %s, want %s", be.Code, CodeChangedAfterVerify)
	}
	if be.ExpectedDigest != vs.ManifestDigest {
		t.Errorf("expected digest not reported: %q", be.ExpectedDigest)
	}
	if be.ObservedDigest == "" || be.ObservedDigest == be.ExpectedDigest {
		t.Errorf("observed digest not reported: %q", be.ObservedDigest)
	}
}

func TestGuardExecutionBlocksAddedScript(t *testing.T) {
	dir := fixture(t)
	p := New(ManifestVerifier{})
	if _, err := p.VerifyBeforeLoad(dir); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "scripts", "evil.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := p.GuardExecution(filepath.Join(dir, "scripts", "evil.sh")); err == nil {
		t.Fatal("expected block for added file")
	}
}

func TestGuardExecutionBlocksFlippedExecutableBit(t *testing.T) {
	dir := fixture(t)
	p := New(ManifestVerifier{})
	if _, err := p.VerifyBeforeLoad(dir); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(filepath.Join(dir, "scripts", "run.sh"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := p.GuardExecution(filepath.Join(dir, "scripts", "run.sh")); err == nil {
		t.Fatal("expected block for executable bit change")
	}
}

func TestGuardExecutionIgnoresPathsOutsideSkills(t *testing.T) {
	dir := fixture(t)
	p := New(ManifestVerifier{})
	if _, err := p.VerifyBeforeLoad(dir); err != nil {
		t.Fatal(err)
	}

	outside := filepath.Join(t.TempDir(), "unrelated.sh")
	if err := os.WriteFile(outside, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := p.GuardExecution(outside); err != nil {
		t.Errorf("unrelated path blocked: %v", err)
	}
	if err := p.GuardExecution("/usr/bin/env"); err != nil {
		t.Errorf("system path blocked: %v", err)
	}
}

func TestGuardSkillPathBlocksUnverifiedSkill(t *testing.T) {
	dir := fixture(t)
	p := New(ManifestVerifier{}) // nothing verified

	err := p.GuardSkillPath(filepath.Join(dir, "SKILL.md"))
	if err == nil {
		t.Fatal("expected block for never-verified skill path")
	}
	var be *BlockError
	if !errors.As(err, &be) {
		t.Fatalf("err = %T, want *BlockError", err)
	}
	if be.Code != CodeNotVerified {
		t.Errorf("code = %s, want %s", be.Code, CodeNotVerified)
	}
}

func TestForgetClearsRecord(t *testing.T) {
	dir := fixture(t)
	p := New(ManifestVerifier{})
	if _, err := p.VerifyBeforeLoad(dir); err != nil {
		t.Fatal(err)
	}
	p.Forget(dir)
	if err := p.GuardSkillPath(filepath.Join(dir, "SKILL.md")); err == nil {
		t.Fatal("expected block after Forget")
	}
}

func TestSymlinkedSkillPathIsResolved(t *testing.T) {
	dir := fixture(t)
	p := New(ManifestVerifier{})
	if _, err := p.VerifyBeforeLoad(dir); err != nil {
		t.Fatal(err)
	}

	// A symlink alias to the skill root must not evade containment.
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Chmod(filepath.Join(dir, "scripts", "util.py"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := p.GuardExecution(filepath.Join(alias, "scripts", "util.py")); err == nil {
		t.Fatal("tamper via symlinked root was not detected")
	}
}

func TestNestedSkillRootsUseLongestMatch(t *testing.T) {
	outer := fixture(t)
	inner := fixture(t)
	// Make inner a subdirectory of outer: re-create the inner fixture
	// inside outer/inner to exercise containment.
	nested := filepath.Join(outer, "inner")
	if err := os.Rename(inner, nested); err != nil {
		t.Skipf("rename failed: %v", err)
	}
	// The outer content changed; refresh its control manifest.
	om, err := manifest.Create(outer)
	if err != nil {
		t.Fatal(err)
	}
	if err := om.WriteControlManifest(outer); err != nil {
		t.Fatal(err)
	}

	p := New(ManifestVerifier{})
	if _, err := p.VerifyBeforeLoad(outer); err != nil {
		t.Fatal(err)
	}
	if _, err := p.VerifyBeforeLoad(nested); err != nil {
		t.Fatal(err)
	}

	// Tampering with the nested skill must be caught by the nested root
	// registration, not silently allowed by the outer one.
	if err := os.WriteFile(filepath.Join(nested, "scripts", "util.py"), []byte("print('evil')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := p.GuardExecution(filepath.Join(nested, "scripts", "util.py")); err == nil {
		t.Fatal("nested skill tamper not detected")
	}
	// The tampered file is also part of the outer skill's signed content
	// (containment is physical), so the outer skill blocks too: fail
	// closed by design.
	if err := p.GuardExecution(filepath.Join(outer, "scripts", "util.py")); err == nil {
		t.Fatal("outer skill should fail closed when its content (the nested skill) changed")
	}
}
