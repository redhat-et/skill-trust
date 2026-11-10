package verify

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParsePolicyKeyBased(t *testing.T) {
	_, pubPath := keyFiles(t)
	p, err := ParsePolicy([]byte(keyPolicyJSON(pubPath, "")))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if p.APIVersion != PolicyAPIVersion {
		t.Errorf("apiVersion = %q", p.APIVersion)
	}
	if len(p.Signers) != 1 || p.Signers[0].Mode != ModeKey {
		t.Fatalf("signers = %+v", p.Signers)
	}
	if len(p.keyPEM["release-key"]) == 0 {
		t.Error("public key not resolved during parsing")
	}
}

func TestParsePolicyKeyless(t *testing.T) {
	doc := `{
  "apiVersion": "skill-trust.policy/v1",
  "signers": [{
    "name": "ci",
    "mode": "keyless",
    "certificate": {
      "identityRegexp": "^https://github.com/org/",
      "issuer": "https://token.actions.githubusercontent.com"
    }
  }]
}`
	p, err := ParsePolicy([]byte(doc))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if p.Signers[0].Certificate.IdentityRegexp != "^https://github.com/org/" {
		t.Errorf("identityRegexp not parsed")
	}
}

func TestParsePolicyDurationForms(t *testing.T) {
	doc := `{
  "apiVersion": "skill-trust.policy/v1",
  "defaults": {"maxSignatureAge": "24h"},
  "signers": [{
    "name": "ci",
    "mode": "keyless",
    "certificate": {"identities": ["a"], "issuer": "i"},
    "maxSignatureAge": 3600000000000
  }]
}`
	p, err := ParsePolicy([]byte(doc))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if got := time.Duration(*p.Defaults.MaxSignatureAge); got != 24*time.Hour {
		t.Errorf("defaults maxAge = %v", got)
	}
	if got := time.Duration(*p.Signers[0].MaxSignatureAge); got != time.Hour {
		t.Errorf("signer maxAge = %v", got)
	}
	// Per-signer value wins over the default.
	if got := p.maxAge(&p.Signers[0]); got != time.Hour {
		t.Errorf("resolved maxAge = %v, want 1h", got)
	}
}

func TestParsePolicyDefaultsResolution(t *testing.T) {
	_, pubPath := keyFiles(t)
	doc := `{
  "apiVersion": "skill-trust.policy/v1",
  "defaults": {"requireTransparencyLog": false, "requireSignedTimestamps": true},
  "signers": [{"name": "k", "mode": "key", "publicKey": {"path": "` + pubPath + `"}}]
}`
	p, err := ParsePolicy([]byte(doc))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if p.requireTlog(&p.Signers[0]) {
		t.Error("requireTlog default false not applied")
	}
	if !p.requireTSA(&p.Signers[0]) {
		t.Error("requireSignedTimestamps default true not applied")
	}
	// Absent everything: tlog required by default.
	bare, err := ParsePolicy([]byte(`{"apiVersion": "skill-trust.policy/v1", "signers": [{"name": "k", "mode": "key", "publicKey": {"path": "` + pubPath + `"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !bare.requireTlog(&SignerRule{}) {
		t.Error("tlog should be required by default")
	}
}

func TestParsePolicyRejects(t *testing.T) {
	_, pubPath := keyFiles(t)
	cases := []struct {
		name string
		doc  string
		want error
	}{
		{"bad api version", `{"apiVersion": "v0", "signers": []}`, ErrUnsupportedContent},
		{"no signers", `{"apiVersion": "skill-trust.policy/v1", "signers": []}`, ErrPolicyFailure},
		{"not json", `{`, ErrMalformedInput},
		{"keyless without certificate", `{"apiVersion": "skill-trust.policy/v1", "signers": [{"name": "c", "mode": "keyless"}]}`, ErrMalformedInput},
		{
			"keyless identities and regexp",
			`{"apiVersion": "skill-trust.policy/v1", "signers": [{"name": "c", "mode": "keyless", "certificate": {"identities": ["a"], "identityRegexp": "x", "issuer": "i"}}]}`,
			ErrMalformedInput,
		},
		{
			"keyless without identity",
			`{"apiVersion": "skill-trust.policy/v1", "signers": [{"name": "c", "mode": "keyless", "certificate": {"issuer": "i"}}]}`,
			ErrMalformedInput,
		},
		{
			"keyless without issuer",
			`{"apiVersion": "skill-trust.policy/v1", "signers": [{"name": "c", "mode": "keyless", "certificate": {"identities": ["a"]}}]}`,
			ErrMalformedInput,
		},
		{
			"keyless issuer and regexp",
			`{"apiVersion": "skill-trust.policy/v1", "signers": [{"name": "c", "mode": "keyless", "certificate": {"identities": ["a"], "issuer": "i", "issuerRegexp": "j"}}]}`,
			ErrMalformedInput,
		},
		{
			"key with certificate",
			`{"apiVersion": "skill-trust.policy/v1", "signers": [{"name": "k", "mode": "key", "publicKey": {"path": "` + pubPath + `"}, "certificate": {"identities": ["a"], "issuer": "i"}}]}`,
			ErrMalformedInput,
		},
		{
			"key without publicKey",
			`{"apiVersion": "skill-trust.policy/v1", "signers": [{"name": "k", "mode": "key"}]}`,
			ErrMalformedInput,
		},
		{
			"key with provenance",
			`{"apiVersion": "skill-trust.policy/v1", "signers": [{"name": "k", "mode": "key", "publicKey": {"path": "` + pubPath + `"}, "provenance": {"sourceRepository": "org/repo"}}]}`,
			ErrMalformedInput,
		},
		{
			"unknown mode",
			`{"apiVersion": "skill-trust.policy/v1", "signers": [{"name": "x", "mode": "banana"}]}`,
			ErrUnsupportedContent,
		},
		{
			"unknown trust root",
			`{"apiVersion": "skill-trust.policy/v1", "signers": [{"name": "k", "mode": "key", "publicKey": {"path": "` + pubPath + `"}, "trustRoot": "ghost"}]}`,
			ErrMalformedInput,
		},
		{
			"duplicate rule names",
			`{"apiVersion": "skill-trust.policy/v1", "signers": [
				{"name": "k", "mode": "key", "publicKey": {"path": "` + pubPath + `"}},
				{"name": "k", "mode": "key", "publicKey": {"path": "` + pubPath + `"}}]}`,
			ErrMalformedInput,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParsePolicy([]byte(tc.doc))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestParsePolicyKeyPathMissing(t *testing.T) {
	doc := keyPolicyJSON("/nonexistent/key.pub", "")
	if _, err := ParsePolicy([]byte(doc)); !errors.Is(err, ErrTrustUnavailable) {
		t.Fatalf("err = %v, want ErrTrustUnavailable", err)
	}
}

func TestLoadPolicyFile(t *testing.T) {
	_, pubPath := keyFiles(t)
	path := writePolicy(t, keyPolicyJSON(pubPath, ""))
	if _, err := LoadPolicy(path); err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if _, err := LoadPolicy(filepath.Join(t.TempDir(), "nope.json")); !errors.Is(err, ErrMalformedInput) {
		t.Fatalf("err = %v, want ErrMalformedInput", err)
	}
}

func TestPolicyRejectsKeyPEMGarbage(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.pub")
	if err := os.WriteFile(bad, []byte("not a pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	doc := keyPolicyJSON(bad, "")
	// Parsing resolves the key path eagerly; garbage PEM is caught when the
	// verifier compiles the rule (New), not at parse time, because the
	// parse step only reads the file.
	if _, err := ParsePolicy([]byte(doc)); err != nil {
		t.Fatalf("ParsePolicy should not validate PEM contents: %v", err)
	}
	p, _ := ParsePolicy([]byte(doc))
	if _, err := New(p); !errors.Is(err, ErrCryptoFailure) {
		t.Fatalf("err = %v, want ErrCryptoFailure", err)
	}
}

func TestPolicyJSONRoundTrip(t *testing.T) {
	_, pubPath := keyFiles(t)
	p, err := ParsePolicy([]byte(keyPolicyJSON(pubPath, `,"maxSignatureAge": "1h"`)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	// Round-trip: the duration survives a marshal/parse cycle.
	back, err := ParsePolicy(b)
	if err != nil {
		t.Fatalf("re-parsing marshaled policy: %v (doc: %s)", err, b)
	}
	if got := back.maxAge(&back.Signers[0]); got != time.Hour {
		t.Errorf("round-tripped maxAge = %v, want 1h", got)
	}
}
