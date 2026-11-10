// Package trust implements the skill-trust trust configuration layer: one
// configuration model for public Sigstore and RHTAS (or any Sigstore-compatible
// deployment) endpoints and trust material.
//
// Trust material is verification-side state: the certificate authorities,
// transparency logs, CT logs, timestamp authorities, and public keys that a
// verifier trusts. Services are signing-side state: the Fulcio, Rekor, and
// TSA endpoints a signer talks to. Both are expressed as data so an
// organization can switch between public Sigstore and RHTAS without
// changing the skill package format.
//
// Verification is offline-capable: bundles carry their certificates,
// transparency log inclusion proofs, and timestamps, and are checked
// against locally loaded trust material without contacting any service.
package trust

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

// Trust root types.
const (
	// TypeSigstorePublic selects the public Sigstore good instance. The
	// trusted root is embedded in the binary; see docs/TRUST-CONFIG.md for
	// refresh behavior.
	TypeSigstorePublic = "sigstore-public"

	// TypeTrustedRoot selects a Sigstore TrustedRoot JSON document by
	// path, as published by an RHTAS TUF server or any Sigstore
	// deployment.
	TypeTrustedRoot = "trusted-root"

	// TypeCA selects a PEM certificate authority bundle by path, for
	// private Fulcio-style deployments.
	TypeCA = "ca"

	// TypeKey selects a PEM public key file by path, for key-based
	// verification.
	TypeKey = "key"
)

// ErrTrustUnavailable is returned when trust material cannot be loaded.
// It maps to finding code ST-TRUST-UNAVAILABLE.
var ErrTrustUnavailable = errors.New("unavailable trust material")

// RootConfig is one named trust root in a trust configuration.
type RootConfig struct {
	// Type is one of the Type* constants.
	Type string `json:"type"`

	// Path locates the trust material file for the trusted-root, ca, and
	// key types.
	Path string `json:"path,omitempty"`
}

// Config is the trustRoots section of a verification policy.
type Config struct {
	// TrustRoots maps a name (referenced by signer rules) to its
	// configuration.
	TrustRoots map[string]RootConfig `json:"trustRoots"`
}

// Root returns the configuration for a named trust root.
func (c *Config) Root(name string) (RootConfig, error) {
	if c == nil || len(c.TrustRoots) == 0 {
		return RootConfig{}, fmt.Errorf("%w: no trust roots configured", ErrTrustUnavailable)
	}
	rc, ok := c.TrustRoots[name]
	if !ok {
		return RootConfig{}, fmt.Errorf("%w: unknown trust root %q", ErrTrustUnavailable, name)
	}
	return rc, nil
}

// Material loads the named trust roots and returns them as a single
// trusted material collection usable by a verifier. With no names it
// loads every configured root.
func (c *Config) Material(names ...string) (root.TrustedMaterial, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: nil trust configuration", ErrTrustUnavailable)
	}
	if len(names) == 0 {
		for name := range c.TrustRoots {
			names = append(names, name)
		}
	}
	var collection root.TrustedMaterialCollection
	for _, name := range names {
		rc, err := c.Root(name)
		if err != nil {
			return nil, err
		}
		tm, err := LoadRoot(rc)
		if err != nil {
			return nil, err
		}
		collection = append(collection, tm)
	}
	if len(collection) == 0 {
		return nil, fmt.Errorf("%w: no usable trust material", ErrTrustUnavailable)
	}
	return collection, nil
}

// LoadRoot loads one trust root configuration into trusted material.
func LoadRoot(rc RootConfig) (root.TrustedMaterial, error) {
	switch rc.Type {
	case TypeSigstorePublic:
		return root.NewTrustedRootFromJSON(PublicTrustedRootJSON())
	case TypeTrustedRoot:
		if rc.Path == "" {
			return nil, fmt.Errorf("%w: trusted-root type requires a path", ErrTrustUnavailable)
		}
		return root.NewTrustedRootFromPath(rc.Path)
	case TypeCA:
		return caTrustedRoot(rc.Path)
	case TypeKey:
		if rc.Path == "" {
			return nil, fmt.Errorf("%w: key type requires a path", ErrTrustUnavailable)
		}
		pemBytes, err := os.ReadFile(rc.Path)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrTrustUnavailable, err)
		}
		km, err := LoadKeysFromPEM(pemBytes)
		if err != nil {
			return nil, err
		}
		return km.TrustedMaterial(), nil
	default:
		return nil, fmt.Errorf("%w: unknown trust root type %q", ErrTrustUnavailable, rc.Type)
	}
}

// caTrustedRoot builds a trusted root from a PEM CA bundle.
func caTrustedRoot(path string) (root.TrustedMaterial, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: ca type requires a path", ErrTrustUnavailable)
	}
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTrustUnavailable, err)
	}
	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTrustUnavailable, err)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%w: no certificates in %s", ErrTrustUnavailable, path)
	}

	cas := make([]root.CertificateAuthority, 0, len(certs))
	for _, cert := range certs {
		ca := &root.FulcioCertificateAuthority{
			Root:                cert,
			ValidityPeriodStart: cert.NotBefore,
			ValidityPeriodEnd:   cert.NotAfter,
		}
		cas = append(cas, ca)
	}

	tr, err := root.NewTrustedRoot(
		"application/vnd.dev.sigstore.trustedroot+json;version=0.1",
		cas,
		nil, // certificate transparency logs (not used for offline CA verification)
		nil, // timestamp authorities
		nil, // rekor logs
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTrustUnavailable, err)
	}
	return tr, nil
}

// KeyMaterial holds public keys for key-based verification, indexed by
// their Sigstore key hints (base64(SHA-256(SPKI))). Bundles carry only the
// hint; the expected keys are supplied by trust configuration, and hint
// comparison is what authenticates the signer.
type KeyMaterial struct {
	verifiers map[string]root.TimeConstrainedVerifier
}

// LoadKeysFromPEM loads one or more public keys from PEM data.
func LoadKeysFromPEM(pemBytes []byte) (*KeyMaterial, error) {
	km := &KeyMaterial{verifiers: make(map[string]root.TimeConstrainedVerifier)}

	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "PUBLIC KEY" {
			continue
		}
		pub, err := cryptoutils.UnmarshalPEMToPublicKey(pem.EncodeToMemory(block))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrTrustUnavailable, err)
		}
		hint, err := KeyHint(pub)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrTrustUnavailable, err)
		}
		verifier, err := signature.LoadVerifier(pub, crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrTrustUnavailable, err)
		}
		km.verifiers[hint] = root.NewExpiringKey(verifier, time.Time{}, time.Time{})
	}
	if len(km.verifiers) == 0 {
		return nil, fmt.Errorf("%w: no public keys found in PEM data", ErrTrustUnavailable)
	}
	return km, nil
}

// TrustedMaterial returns the keys as trusted material. The returned
// material rejects any key hint it does not hold, which is the key-based
// equivalent of certificate chain validation.
func (km *KeyMaterial) TrustedMaterial() root.TrustedMaterial {
	return root.NewTrustedPublicKeyMaterial(func(keyID string) (root.TimeConstrainedVerifier, error) {
		v, ok := km.verifiers[keyID]
		if !ok {
			return nil, fmt.Errorf("%w: public key hint %q is not a trusted key", ErrTrustUnavailable, keyID)
		}
		return v, nil
	})
}

// Hints returns the key hints held by this material.
func (km *KeyMaterial) Hints() []string {
	hints := make([]string, 0, len(km.verifiers))
	for h := range km.verifiers {
		hints = append(hints, h)
	}
	return hints
}

// KeyHint computes the Sigstore public key hint for a public key:
// base64(SHA-256(x509.MarshalPKIXPublicKey(key))). This matches the hint
// embedded in Sigstore bundles produced by skill-trust and by cosign.
func KeyHint(pub crypto.PublicKey) (string, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(spki)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}
