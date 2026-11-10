// Package sign implements skill-trust signing: converting a skill directory
// into a canonical manifest and producing a Sigstore bundle over the
// manifest bytes in .skill-trust/.
//
// Two signing modes share one bundle model:
//
//   - key-based: a PEM private key (the bundle carries a public key hint;
//     verification authenticates the key against trust configuration);
//   - keyless: an ephemeral key plus a Fulcio-issued certificate obtained
//     with a pre-acquired OIDC identity token (for CI, a GitHub Actions
//     OIDC token), optionally recorded in Rekor and timestamped by an RFC
//     3161 authority.
//
// Signing never modifies skill content outside .skill-trust/.
package sign

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	sgsign "github.com/sigstore/sigstore-go/pkg/sign"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/redhat-et/skill-trust/internal/keypair"
	"github.com/redhat-et/skill-trust/pkg/manifest"
	"github.com/redhat-et/skill-trust/pkg/trust"
)

// Errors returned by signing. They map to the ST-SIGNATURE-* finding space
// at verification time.
var (
	// ErrInvalidOptions indicates a contradictory or incomplete Options
	// value (for example both a key and an identity token).
	ErrInvalidOptions = errors.New("invalid signing options")

	// ErrSigningFailed wraps failures from the signing stack (key parsing,
	// Fulcio, Rekor, TSA).
	ErrSigningFailed = errors.New("signing failed")
)

// Options configures one signing operation.
type Options struct {
	// KeyPath locates a PEM private key for key-based signing. Exactly one
	// of KeyPath or IDToken must be set.
	KeyPath string

	// IDToken is a pre-acquired OIDC identity token for keyless signing
	// (for example a GitHub Actions token requested with audience
	// "sigstore"). Fulcio exchanges it for a short-lived certificate.
	IDToken string

	// Services selects the signing deployment endpoints (Fulcio, Rekor,
	// TSA). The zero value performs a fully offline key-based signing
	// with no transparency log entry or timestamp; verification of such a
	// bundle must use a policy that does not require them.
	Services trust.Services

	// TrustedRoot optionally supplies verification trust material; when
	// set, the signer self-verifies the produced bundle before returning.
	TrustedRoot root.TrustedMaterial
}

// Result reports what a signing operation produced.
type Result struct {
	// ManifestDigest is the signed content identity (SHA-256 of the
	// canonical manifest bytes).
	ManifestDigest string `json:"manifestDigest"`

	// BundlePath is the written bundle control file.
	BundlePath string `json:"bundlePath"`

	// ManifestPath is the written manifest control file.
	ManifestPath string `json:"manifestPath"`

	// KeyHint is set for key-based signing: the public key hint embedded
	// in the bundle.
	KeyHint string `json:"keyHint,omitempty"`

	// Certificate is set for keyless signing: the Fulcio-issued signer
	// certificate. It is excluded from JSON output; Identity and Issuer
	// carry the relevant claims.
	Certificate *x509.Certificate `json:"-"`

	// Identity is the signer identity (certificate SAN) for keyless
	// signing.
	Identity string `json:"identity,omitempty"`

	// Issuer is the OIDC issuer recorded in the certificate for keyless
	// signing.
	Issuer string `json:"issuer,omitempty"`

	// HasTlogEntry reports whether a transparency log entry with an
	// offline-verifiable inclusion proof was embedded.
	HasTlogEntry bool `json:"hasTlogEntry"`

	// HasTimestamp reports whether an RFC 3161 timestamp was embedded.
	HasTimestamp bool `json:"hasTimestamp"`
}

// Skill signs the skill rooted at dir.
//
// It builds the canonical manifest, writes .skill-trust/manifest.json,
// signs the canonical manifest bytes, and writes
// .skill-trust/bundle.sigstore.json. Skill content outside .skill-trust/
// is never modified; an existing bundle is replaced.
func Skill(ctx context.Context, dir string, opts Options) (*Result, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}

	m, err := manifest.Create(dir)
	if err != nil {
		return nil, fmt.Errorf("building manifest: %w", err)
	}
	canonical, err := m.Canonical()
	if err != nil {
		return nil, fmt.Errorf("serializing manifest: %w", err)
	}
	digest, err := m.Digest()
	if err != nil {
		return nil, fmt.Errorf("computing manifest digest: %w", err)
	}

	bundleOpts, kp, err := opts.bundleOptions(ctx)
	if err != nil {
		return nil, err
	}

	pb, err := sgsign.Bundle(&sgsign.PlainData{Data: canonical}, kp, bundleOpts)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSigningFailed, err)
	}

	bundleJSON, err := marshalBundle(pb)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSigningFailed, err)
	}

	if err := m.WriteControlManifest(dir); err != nil {
		return nil, fmt.Errorf("writing manifest control file: %w", err)
	}
	bundlePath := manifest.ControlPath(dir, manifest.BundleFile)
	if err := os.MkdirAll(filepath.Dir(bundlePath), 0o755); err != nil {
		return nil, fmt.Errorf("writing bundle: %w", err)
	}
	if err := os.WriteFile(bundlePath, bundleJSON, 0o644); err != nil {
		return nil, fmt.Errorf("writing bundle: %w", err)
	}

	res := &Result{
		ManifestDigest: digest,
		BundlePath:     bundlePath,
		ManifestPath:   manifest.ControlPath(dir, manifest.ManifestFile),
	}

	switch {
	case opts.KeyPath != "":
		res.KeyHint = string(kp.GetHint())
	case opts.IDToken != "":
		// Extract identity material from the produced bundle.
		res.Certificate = certificateFromBundle(pb)
		if res.Certificate != nil {
			res.Identity = sanFromCert(res.Certificate)
			res.Issuer = issuerFromCert(res.Certificate)
		}
	}

	if len(pb.GetVerificationMaterial().GetTlogEntries()) > 0 {
		res.HasTlogEntry = true
	}
	if len(pb.GetVerificationMaterial().GetTimestampVerificationData().GetRfc3161Timestamps()) > 0 {
		res.HasTimestamp = true
	}

	return res, nil
}

func (o Options) validate() error {
	switch {
	case o.KeyPath != "" && o.IDToken != "":
		return fmt.Errorf("%w: provide either a key or an identity token, not both", ErrInvalidOptions)
	case o.KeyPath == "" && o.IDToken == "":
		return fmt.Errorf("%w: provide a key path (key-based) or an identity token (keyless)", ErrInvalidOptions)
	case o.KeyPath != "":
		return o.Services.Validate(false)
	default:
		if o.Services.FulcioURL == "" {
			return fmt.Errorf("%w: keyless signing requires Services.FulcioURL", ErrInvalidOptions)
		}
		// Fulcio certificates are short-lived; without a transparency log
		// entry or an RFC 3161 timestamp the certificate cannot be
		// time-validated at verification.
		if o.Services.RekorURL == "" && o.Services.TSAURL == "" {
			return fmt.Errorf("%w: keyless signing requires a Rekor URL or a TSA URL so the certificate can be time-validated", ErrInvalidOptions)
		}
		return nil
	}
}

func (o Options) bundleOptions(ctx context.Context) (sgsign.BundleOptions, sgsign.Keypair, error) {
	opts := sgsign.BundleOptions{Context: ctx}

	if o.TrustedRoot != nil {
		opts.TrustedRoot = o.TrustedRoot
	}

	if o.Services.RekorURL != "" {
		opts.TransparencyLogs = []sgsign.Transparency{
			sgsign.NewRekor(&sgsign.RekorOptions{
				BaseURL: o.Services.RekorURL,
				Timeout: 90 * time.Second,
				Retries: 2,
			}),
		}
	}
	if o.Services.TSAURL != "" {
		opts.TimestampAuthorities = []*sgsign.TimestampAuthority{
			sgsign.NewTimestampAuthority(&sgsign.TimestampAuthorityOptions{
				URL:     o.Services.TSAURL,
				Timeout: 30 * time.Second,
				Retries: 2,
			}),
		}
	}

	switch {
	case o.KeyPath != "":
		pemBytes, err := os.ReadFile(o.KeyPath)
		if err != nil {
			return opts, nil, fmt.Errorf("%w: reading key: %v", ErrSigningFailed, err)
		}
		kp, err := keypair.LoadFromPEM(pemBytes)
		if err != nil {
			return opts, nil, fmt.Errorf("%w: %v", ErrSigningFailed, err)
		}
		// For key-based bundles, self-verification needs the signer's own
		// public key in the trust material (the bundle carries only a key
		// hint, and Rekor v1 entries record the signing key). Combine the
		// configured trusted root with the signer's key material.
		if o.TrustedRoot != nil {
			pubPEM, err := kp.GetPublicKeyPem()
			if err != nil {
				return opts, nil, fmt.Errorf("%w: %v", ErrSigningFailed, err)
			}
			km, err := trust.LoadKeysFromPEM([]byte(pubPEM))
			if err != nil {
				return opts, nil, fmt.Errorf("%w: %v", ErrSigningFailed, err)
			}
			opts.TrustedRoot = root.TrustedMaterialCollection{o.TrustedRoot, km.TrustedMaterial()}
		}
		return opts, kp, nil

	default:
		kp, err := sgsign.NewEphemeralKeypair(nil)
		if err != nil {
			return opts, nil, fmt.Errorf("%w: %v", ErrSigningFailed, err)
		}
		opts.CertificateProvider = sgsign.NewFulcio(&sgsign.FulcioOptions{
			BaseURL: o.Services.FulcioURL,
			Timeout: 30 * time.Second,
			Retries: 2,
		})
		opts.CertificateProviderOptions = &sgsign.CertificateProviderOptions{
			IDToken: o.IDToken,
		}
		return opts, kp, nil
	}
}

// marshalBundle serializes a protobuf bundle as deterministic, compact
// JSON. protojson output is deliberately non-deterministic across builds,
// so the bytes are compacted through encoding/json before storage.
func marshalBundle(pb *protobundle.Bundle) ([]byte, error) {
	raw, err := protojson.Marshal(pb)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func certificateFromBundle(pb *protobundle.Bundle) *x509.Certificate {
	vm := pb.GetVerificationMaterial()
	if vm == nil {
		return nil
	}
	chain := vm.GetCertificate().GetRawBytes()
	if len(chain) == 0 {
		// v0.3 bundles may carry an X509CertificateChain instead.
		certs := vm.GetX509CertificateChain().GetCertificates()
		if len(certs) == 0 {
			return nil
		}
		chain = certs[0].GetRawBytes()
	}
	cert, err := x509.ParseCertificate(chain)
	if err != nil {
		return nil
	}
	return cert
}

func sanFromCert(cert *x509.Certificate) string {
	if len(cert.URIs) > 0 {
		return cert.URIs[0].String()
	}
	if len(cert.EmailAddresses) > 0 {
		return cert.EmailAddresses[0]
	}
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}
	return ""
}

func issuerFromCert(cert *x509.Certificate) string {
	for _, ext := range cert.Extensions {
		if ext.Id.String() == "1.3.6.1.4.1.57264.1.1" { // Fulcio OIDC issuer extension
			return string(ext.Value)
		}
	}
	return ""
}
