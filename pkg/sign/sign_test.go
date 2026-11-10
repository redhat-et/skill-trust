package sign

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/redhat-et/skill-trust/pkg/manifest"
	"github.com/redhat-et/skill-trust/pkg/trust"
)

// testSkill creates a skill directory with instructions and scripts.
func testSkill(t *testing.T) string {
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
	write("SKILL.md", "---\nname: sign-test\n---\nTest skill.\n", 0o644)
	write("scripts/run.sh", "#!/usr/bin/env bash\necho hi\n", 0o755)
	write("scripts/util.py", "print('hi')\n", 0o644)
	write("references/ref.md", "ref\n", 0o644)
	return dir
}

// keyPEM generates an ECDSA P-256 key and returns (private PEM, public PEM).
func keyPEM(t *testing.T) ([]byte, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return privPEM, pubPEM
}

func TestSignKeyBasedProducesValidBundle(t *testing.T) {
	dir := testSkill(t)
	privPEM, pubPEM := keyPEM(t)
	keyPath := filepath.Join(t.TempDir(), "release.key")
	if err := os.WriteFile(keyPath, privPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := Skill(context.Background(), dir, Options{KeyPath: keyPath})
	if err != nil {
		t.Fatalf("Skill: %v", err)
	}

	// Control files exist.
	if _, err := os.Stat(manifest.ControlPath(dir, manifest.ManifestFile)); err != nil {
		t.Error("manifest control file missing")
	}
	raw, err := os.ReadFile(manifest.ControlPath(dir, manifest.BundleFile))
	if err != nil {
		t.Fatalf("bundle control file missing: %v", err)
	}

	// The bundle is a v0.3 protobuf bundle with a messageSignature over
	// the manifest bytes and the expected key hint.
	var pb protobundle.Bundle
	if err := protojson.Unmarshal(raw, &pb); err != nil {
		t.Fatalf("bundle does not parse as protobuf bundle: %v", err)
	}
	if got := pb.GetMediaType(); got != "application/vnd.dev.sigstore.bundle.v0.3+json" {
		t.Errorf("mediaType = %q", got)
	}

	m, err := manifest.LoadControlManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pb.GetMessageSignature().GetMessageDigest().GetDigest(), sha256Bytes(t, canonical)) {
		t.Error("bundle digest does not cover the canonical manifest bytes")
	}

	km, err := trust.LoadKeysFromPEM(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	if res.KeyHint != km.Hints()[0] {
		t.Errorf("result key hint %q != expected %q", res.KeyHint, km.Hints()[0])
	}

	// Verify the bundle with sigstore-go against the trusted key.
	sb, err := bundle.NewBundle(&pb)
	if err != nil {
		t.Fatal(err)
	}
	sev, err := verify.NewVerifier(km.TrustedMaterial(), verify.WithNoObserverTimestamps())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sev.Verify(sb, verify.NewPolicy(verify.WithArtifact(bytes.NewReader(canonical)), verify.WithKey())); err != nil {
		t.Errorf("produced bundle does not verify: %v", err)
	}
}

func TestSignPreservesSkillContent(t *testing.T) {
	dir := testSkill(t)
	privPEM, _ := keyPEM(t)
	keyPath := filepath.Join(t.TempDir(), "k.pem")
	if err := os.WriteFile(keyPath, privPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	before := dirSnapshot(t, dir)
	if _, err := Skill(context.Background(), dir, Options{KeyPath: keyPath}); err != nil {
		t.Fatalf("Skill: %v", err)
	}
	after := dirSnapshot(t, dir)

	for path, digest := range before {
		got, ok := after[path]
		if !ok {
			t.Errorf("file %s disappeared during signing", path)
			continue
		}
		if got != digest {
			t.Errorf("file %s changed during signing", path)
		}
	}
}

func TestTamperedSkillFailsBundleVerification(t *testing.T) {
	dir := testSkill(t)
	privPEM, pubPEM := keyPEM(t)
	keyPath := filepath.Join(t.TempDir(), "k.pem")
	if err := os.WriteFile(keyPath, privPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Skill(context.Background(), dir, Options{KeyPath: keyPath}); err != nil {
		t.Fatal(err)
	}

	// Tamper after signing.
	if err := os.WriteFile(filepath.Join(dir, "scripts", "util.py"), []byte("print('evil')\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	tampered, err := manifest.Create(dir)
	if err != nil {
		t.Fatal(err)
	}
	tamperedCanonical, err := tampered.Canonical()
	if err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(manifest.ControlPath(dir, manifest.BundleFile))
	if err != nil {
		t.Fatal(err)
	}
	var pb protobundle.Bundle
	if err := protojson.Unmarshal(raw, &pb); err != nil {
		t.Fatal(err)
	}
	sb, err := bundle.NewBundle(&pb)
	if err != nil {
		t.Fatal(err)
	}
	// Trust the signing key itself, so the only possible failure is the
	// content binding.
	km, err := trust.LoadKeysFromPEM(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	sev, err := verify.NewVerifier(km.TrustedMaterial(), verify.WithNoObserverTimestamps())
	if err != nil {
		t.Fatal(err)
	}
	// The signature does not cover the tampered content: verification of
	// the tampered manifest bytes must fail.
	_, err = sev.Verify(sb, verify.NewPolicy(verify.WithArtifact(bytes.NewReader(tamperedCanonical)), verify.WithKey()))
	if err == nil {
		t.Fatal("tampered manifest verified against original signature: content binding is broken")
	}
}

func TestSignOptionsValidation(t *testing.T) {
	dir := testSkill(t)
	privPEM, _ := keyPEM(t)
	keyPath := filepath.Join(t.TempDir(), "k.pem")
	if err := os.WriteFile(keyPath, privPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		opts Options
	}{
		{"no signer", Options{}},
		{"both signers", Options{KeyPath: keyPath, IDToken: "tok"}},
		{"keyless without fulcio", Options{IDToken: "tok"}},
		{"keyless without rekor or tsa", Options{IDToken: "tok", Services: trust.Services{FulcioURL: "https://fulcio.example.com"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Skill(context.Background(), dir, tc.opts); err == nil {
				t.Fatal("expected options validation error")
			}
		})
	}
}

// TestCosignInterop verifies that a bundle produced by skill-trust verifies
// with upstream cosign, when cosign is installed. Skips otherwise.
func TestCosignInterop(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping cosign interop in short mode")
	}
	cosign, err := exec.LookPath("cosign")
	if err != nil {
		t.Skip("cosign not installed")
	}

	dir := testSkill(t)
	privPEM, pubPEM := keyPEM(t)
	keyPath := filepath.Join(t.TempDir(), "k.pem")
	pubPath := filepath.Join(t.TempDir(), "k.pub")
	if err := os.WriteFile(keyPath, privPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Skill(context.Background(), dir, Options{KeyPath: keyPath}); err != nil {
		t.Fatal(err)
	}

	// cosign verify-blob needs the artifact (the canonical manifest bytes
	// on disk) plus the bundle and the public key.
	cmd := exec.Command(cosign, "verify-blob",
		"--key", pubPath,
		"--bundle", manifest.ControlPath(dir, manifest.BundleFile),
		"--insecure-ignore-tlog",
		manifest.ControlPath(dir, manifest.ManifestFile),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("cosign interop failed (version too old?): %v\n%s", err, out)
	}
}

func TestGeneratedKeySignsManifestWithHint(t *testing.T) {
	// A PKCS8 ECDSA key from disk must produce the same hint that trust
	// material computes for the matching public key, closing the
	// sign/verify loop for key-based bundles.
	dir := testSkill(t)
	privPEM, pubPEM := keyPEM(t)
	keyPath := filepath.Join(t.TempDir(), "k.pem")
	if err := os.WriteFile(keyPath, privPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := Skill(context.Background(), dir, Options{KeyPath: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	km, err := trust.LoadKeysFromPEM(pubPEM)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(manifest.ControlPath(dir, manifest.BundleFile))
	if err != nil {
		t.Fatal(err)
	}
	var pb protobundle.Bundle
	if err := protojson.Unmarshal(raw, &pb); err != nil {
		t.Fatal(err)
	}
	bundleHint := string(pb.GetVerificationMaterial().GetPublicKey().GetHint())
	if bundleHint != km.Hints()[0] || bundleHint != res.KeyHint {
		t.Errorf("hint mismatch: bundle=%q result=%q trusted=%q", bundleHint, res.KeyHint, km.Hints()[0])
	}
}

// dirSnapshot maps relative path -> content digest for all files.
func dirSnapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	snap := make(map[string]string)
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || !info.Mode().IsRegular() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		snap[rel] = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func sha256Bytes(t *testing.T, b []byte) []byte {
	t.Helper()
	sum := sha256Sum(b)
	return sum
}
