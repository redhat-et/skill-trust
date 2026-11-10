package verify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor/pkg/types/hashedrekord"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	fulciocert "github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	sgroot "github.com/sigstore/sigstore-go/pkg/root"
	testingca "github.com/sigstore/sigstore-go/pkg/testing/ca"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/redhat-et/skill-trust/pkg/manifest"
	"github.com/redhat-et/skill-trust/pkg/sign"
)

// Provenance test constants.
const (
	sourceRepo = "acme/skills"
	sourceRef  = "refs/heads/main"
	workflow   = "release.yml"
	sha        = "d7a8f9e0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8"
)

// summaryWith builds a certificate summary with GitHub workflow claims.
func summaryWith(repo, ref, workflowName, commitSha string) fulciocert.Summary {
	return fulciocert.Summary{
		Extensions: fulciocert.Extensions{
			GithubWorkflowRepository: repo,
			GithubWorkflowRef:        ref,
			GithubWorkflowName:       workflowName,
			GithubWorkflowSHA:        commitSha,
		},
	}
}

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
	write("SKILL.md", "---\nname: verify-test\n---\nTest skill.\n", 0o644)
	write("scripts/run.sh", "#!/usr/bin/env bash\necho hi\n", 0o755)
	write("scripts/util.py", "print('hi')\n", 0o644)
	return dir
}

// keyFiles generates an ECDSA P-256 key and writes the private key and
// public key PEM files, returning their paths.
func keyFiles(t *testing.T) (string, string) {
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
	privPath := filepath.Join(tmp, "release.key")
	pubPath := filepath.Join(tmp, "release.pub")
	if err := os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	return privPath, pubPath
}

// keyPolicyJSON builds a key-based policy referencing pubPath.
func keyPolicyJSON(pubPath string, knobs string) string {
	return `{
  "apiVersion": "skill-trust.policy/v1",
  "name": "test",
  "signers": [
    {
      "name": "release-key",
      "mode": "key",
      "publicKey": {"path": "` + pubPath + `"}` + knobs + `
    }
  ]
}`
}

// writePolicy writes a policy JSON document and returns its path.
func writePolicy(t *testing.T, doc string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// signWithKey signs the skill at dir with the key at keyPath.
func signWithKey(t *testing.T, dir, keyPath string) {
	t.Helper()
	if _, err := sign.Skill(t.Context(), dir, sign.Options{KeyPath: keyPath}); err != nil {
		t.Fatalf("sign.Skill: %v", err)
	}
}

// canonicalOf loads the canonical manifest bytes of a signed skill.
func canonicalOf(t *testing.T, dir string) []byte {
	t.Helper()
	m, err := manifest.LoadControlManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// virtualTrustedRoot builds a TrustedRoot JSON document from a virtual
// Sigstore (test CA, Rekor, and TSA) and returns its path.
func virtualTrustedRoot(t *testing.T, vs *testingca.VirtualSigstore) string {
	t.Helper()
	// The virtual Sigstore keys its rekor log map by the hex-encoded log ID
	// but stores the hex string's own bytes as the log ID. Real trusted
	// roots carry raw key IDs, so fix the IDs to decoded bytes for the map
	// keys to survive the trusted-root JSON round trip.
	vsLogs := vs.RekorLogs()
	rekorLogs := make(map[string]*sgroot.TransparencyLog, len(vsLogs))
	for key, log := range vsLogs {
		fixed := *log
		raw, err := hex.DecodeString(key)
		if err != nil {
			t.Fatalf("decoding rekor log id %q: %v", key, err)
		}
		fixed.ID = raw
		rekorLogs[key] = &fixed
	}
	tr, err := sgroot.NewTrustedRoot(
		"application/vnd.dev.sigstore.trustedroot+json;version=0.1",
		vs.FulcioCertificateAuthorities(),
		vs.CTLogs(),
		vs.TimestampingAuthorities(),
		rekorLogs,
	)
	if err != nil {
		t.Fatalf("building trusted root from virtual sigstore: %v", err)
	}
	b, err := tr.MarshalJSON()
	if err != nil {
		t.Fatalf("marshaling trusted root: %v", err)
	}
	path := filepath.Join(t.TempDir(), "testca-trusted-root.json")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// keylessBundle signs canonical with a virtual Sigstore keyless identity
// and returns the equivalent protobuf v0.3 bundle and its compact JSON.
func keylessBundle(t *testing.T, vs *testingca.VirtualSigstore, identity, issuer string, canonical []byte, keepTlog bool, keepTSA bool) (*protobundle.Bundle, []byte) {
	t.Helper()
	entity, err := vs.Sign(identity, issuer, canonical)
	if err != nil {
		t.Fatalf("virtual sigstore sign: %v", err)
	}

	sc, err := entity.SignatureContent()
	if err != nil {
		t.Fatal(err)
	}
	ms, ok := sc.(*sgbundle.MessageSignature)
	if !ok {
		t.Fatalf("signature content is %T, want *bundle.MessageSignature", sc)
	}
	sig := ms.Signature()
	digest := ms.Digest()

	vc, err := entity.VerificationContent()
	if err != nil {
		t.Fatal(err)
	}
	certContent, ok := vc.(*sgbundle.Certificate)
	if !ok {
		t.Fatalf("verification content is %T, want *bundle.Certificate", vc)
	}
	cert := certContent.Certificate()

	vm := &protobundle.VerificationMaterial{
		Content: &protobundle.VerificationMaterial_Certificate{
			Certificate: &protocommon.X509Certificate{RawBytes: cert.Raw},
		},
	}
	if keepTlog {
		entries, err := entity.TlogEntries()
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			tle := e.TransparencyLogEntry()
			// The virtual Sigstore's Sign uses the deprecated tlog.NewEntry,
			// which omits KindVersion and inclusion proofs. Complete the
			// entry so it serializes as a valid bundle v0.3 tlog entry
			// (which requires an inclusion proof) with the same kind and
			// version the canonicalized body parses as.
			if tle.KindVersion == nil {
				tle.KindVersion = &protorekor.KindVersion{
					Kind:    hashedrekord.KIND,
					Version: hashedrekord.New().DefaultVersion(),
				}
			}
			if tle.InclusionProof == nil {
				ip, err := vs.GetInclusionProof(tle.CanonicalizedBody)
				if err != nil {
					t.Fatal(err)
				}
				hashes := make([][]byte, 0, len(ip.Hashes))
				for _, h := range ip.Hashes {
					b, err := hex.DecodeString(h)
					if err != nil {
						t.Fatal(err)
					}
					hashes = append(hashes, b)
				}
				rootHash, err := hex.DecodeString(*ip.RootHash)
				if err != nil {
					t.Fatal(err)
				}
				tle.InclusionProof = &protorekor.InclusionProof{
					LogIndex:   *ip.LogIndex,
					TreeSize:   *ip.TreeSize,
					RootHash:   rootHash,
					Hashes:     hashes,
					Checkpoint: &protorekor.Checkpoint{Envelope: *ip.Checkpoint},
				}
			}
			vm.TlogEntries = append(vm.TlogEntries, tle)
		}
	}
	if keepTSA {
		tsrs, err := entity.Timestamps()
		if err != nil {
			t.Fatal(err)
		}
		for _, tsr := range tsrs {
			if vm.TimestampVerificationData == nil {
				vm.TimestampVerificationData = &protobundle.TimestampVerificationData{}
			}
			vm.TimestampVerificationData.Rfc3161Timestamps = append(
				vm.TimestampVerificationData.Rfc3161Timestamps,
				&protocommon.RFC3161SignedTimestamp{SignedTimestamp: tsr})
		}
	}

	pb := &protobundle.Bundle{
		MediaType:            "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: vm,
		Content: &protobundle.Bundle_MessageSignature{
			MessageSignature: &protocommon.MessageSignature{
				MessageDigest: &protocommon.HashOutput{
					Algorithm: protocommon.HashAlgorithm_SHA2_256,
					Digest:    digest,
				},
				Signature: sig,
			},
		},
	}

	raw, err := protojson.Marshal(pb)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		t.Fatal(err)
	}
	return pb, buf.Bytes()
}

// writeKeylessSkill materializes a signed keyless skill: fixture content,
// embedded manifest, and the keyless bundle as the control bundle file.
func writeKeylessSkill(t *testing.T, vs *testingca.VirtualSigstore, identity, issuer string, keepTlog, keepTSA bool) string {
	t.Helper()
	dir := testSkill(t)
	m, err := manifest.Create(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.WriteControlManifest(dir); err != nil {
		t.Fatal(err)
	}
	canonical := canonicalOf(t, dir)
	_, bundleJSON := keylessBundle(t, vs, identity, issuer, canonical, keepTlog, keepTSA)
	bundlePath := manifest.ControlPath(dir, manifest.BundleFile)
	if err := os.MkdirAll(filepath.Dir(bundlePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundlePath, bundleJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func keylessPolicyJSON(trustRootPath, identity, issuer string, extra string) string {
	return `{
  "apiVersion": "skill-trust.policy/v1",
  "name": "test",
  "trustRoots": {
    "testca": {"type": "trusted-root", "path": "` + trustRootPath + `"}
  },
  "signers": [
    {
      "name": "ci-workflow",
      "mode": "keyless",
      "certificate": {
        "identities": ["` + identity + `"],
        "issuer": "` + issuer + `"
      },
      "trustRoot": "testca"` + extra + `
    }
  ]
}`
}
