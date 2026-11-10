package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPublicSigstoreRoot(t *testing.T) {
	tm, err := LoadRoot(RootConfig{Type: TypeSigstorePublic})
	if err != nil {
		t.Fatalf("LoadRoot(sigstore-public): %v", err)
	}
	cas := tm.FulcioCertificateAuthorities()
	if len(cas) == 0 {
		t.Error("public root has no certificate authorities")
	}
	tlogs := tm.RekorLogs()
	if len(tlogs) == 0 {
		t.Error("public root has no transparency logs")
	}
	tsas := tm.TimestampingAuthorities()
	if len(tsas) == 0 {
		t.Error("public root has no timestamp authorities")
	}
}

func TestLoadRHTASTrustedRoot(t *testing.T) {
	path := filepath.Join("testdata", "rhtas-trusted-root.json")
	tm, err := LoadRoot(RootConfig{Type: TypeTrustedRoot, Path: path})
	if err != nil {
		t.Fatalf("LoadRoot(trusted-root): %v", err)
	}
	cas := tm.FulcioCertificateAuthorities()
	if len(cas) != 1 {
		t.Fatalf("RHTAS root CAs = %d, want 1", len(cas))
	}
	if len(tm.RekorLogs()) != 1 {
		t.Errorf("RHTAS root rekor logs = %d, want 1", len(tm.RekorLogs()))
	}
	if len(tm.TimestampingAuthorities()) != 1 {
		t.Errorf("RHTAS root TSAs = %d, want 1", len(tm.TimestampingAuthorities()))
	}
}

func TestConfigMaterialCombinesRoots(t *testing.T) {
	cfg := &Config{TrustRoots: map[string]RootConfig{
		"sigstore": {Type: TypeSigstorePublic},
		"rhtas":    {Type: TypeTrustedRoot, Path: filepath.Join("testdata", "rhtas-trusted-root.json")},
	}}

	tm, err := cfg.Material("sigstore", "rhtas")
	if err != nil {
		t.Fatalf("Material: %v", err)
	}
	// Combined material exposes both deployments' CAs and logs.
	if got := len(tm.FulcioCertificateAuthorities()); got < 3 {
		t.Errorf("combined CAs = %d, want >= 3 (2 public + 1 RHTAS)", got)
	}
	if got := len(tm.RekorLogs()); got < 3 {
		t.Errorf("combined rekor logs = %d, want >= 3", got)
	}

	// Material with no names loads everything.
	all, err := cfg.Material()
	if err != nil {
		t.Fatalf("Material(): %v", err)
	}
	if len(all.FulcioCertificateAuthorities()) != len(tm.FulcioCertificateAuthorities()) {
		t.Error("Material() with no names should load all roots")
	}
}

func TestConfigUnknownRoot(t *testing.T) {
	cfg := &Config{TrustRoots: map[string]RootConfig{
		"sigstore": {Type: TypeSigstorePublic},
	}}
	if _, err := cfg.Material("nope"); err == nil {
		t.Fatal("expected error for unknown trust root name")
	}
}

func TestLoadRootUnknownType(t *testing.T) {
	if _, err := LoadRoot(RootConfig{Type: "banana"}); err == nil {
		t.Fatal("expected error for unknown trust root type")
	}
}

func TestLoadRootMissingFile(t *testing.T) {
	if _, err := LoadRoot(RootConfig{Type: TypeTrustedRoot, Path: "/nonexistent/root.json"}); err == nil {
		t.Fatal("expected error for missing trusted root file")
	}
	if _, err := LoadRoot(RootConfig{Type: TypeTrustedRoot}); err == nil {
		t.Fatal("expected error for missing path")
	}
}

func TestKeyMaterialHintAuthentication(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := publicPEM(t, &priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	km, err := LoadKeysFromPEM(pemBytes)
	if err != nil {
		t.Fatalf("LoadKeysFromPEM: %v", err)
	}
	if len(km.Hints()) != 1 {
		t.Fatalf("hints = %v, want exactly 1", km.Hints())
	}

	tm := km.TrustedMaterial()
	hint := km.Hints()[0]

	if _, err := tm.PublicKeyVerifier(hint); err != nil {
		t.Errorf("trusted hint rejected: %v", err)
	}
	// A foreign hint must be rejected; otherwise any key-signed bundle
	// would verify.
	if _, err := tm.PublicKeyVerifier("dHJ1c3QtbWU="); err == nil {
		t.Error("foreign key hint accepted: key authentication is broken")
	}
}

func TestKeyMaterialFromPEMFile(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := publicPEM(t, &priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "release.pub")
	if err := os.WriteFile(path, pemBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	tm, err := LoadRoot(RootConfig{Type: TypeKey, Path: path})
	if err != nil {
		t.Fatalf("LoadRoot(key): %v", err)
	}
	km, err := LoadKeysFromPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tm.PublicKeyVerifier(km.Hints()[0]); err != nil {
		t.Errorf("trusted hint rejected: %v", err)
	}
}

func TestKeyMaterialNoKeys(t *testing.T) {
	if _, err := LoadKeysFromPEM([]byte("not pem at all")); err == nil {
		t.Fatal("expected error for PEM with no keys")
	}
}

func TestPublicTrustedRootJSONShape(t *testing.T) {
	b := PublicTrustedRootJSON()
	if len(b) == 0 {
		t.Fatal("embedded trusted root is empty")
	}
	// It must parse as a valid trusted root.
	if _, err := LoadRoot(RootConfig{Type: TypeSigstorePublic}); err != nil {
		t.Fatalf("embedded root does not load: %v", err)
	}
}
