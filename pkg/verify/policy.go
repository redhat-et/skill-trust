// Package verify implements skill-trust verification: manifest
// recomputation, Sigstore bundle verification, and organization policy
// evaluation, composed into one fail-closed allow/block decision.
//
// The three stages are independently callable: manifest generation lives
// in pkg/manifest, cryptographic bundle verification and policy evaluation
// are exposed here as separate types and functions. The package never
// executes skill content.
package verify

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/redhat-et/skill-trust/pkg/trust"
)

// Duration wraps time.Duration for JSON policies: it accepts either a
// duration string ("24h", "30m") or an integer nanosecond count.
type Duration time.Duration

// UnmarshalJSON implements json.Unmarshaler.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		v, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", s, err)
		}
		*d = Duration(v)
		return nil
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("invalid duration: %w", err)
	}
	*d = Duration(n)
	return nil
}

// MarshalJSON implements json.Marshaler.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// PolicyAPIVersion is the only supported policy schema version.
const PolicyAPIVersion = "skill-trust.policy/v1"

// Error taxonomy. Verification problems that are decisions (block) are
// reported in Result.Findings; operational failures (bad input, unusable
// trust material) are errors wrapping these sentinels.
var (
	// ErrMalformedInput indicates unparseable or structurally invalid
	// input (policy file, control files, bundle).
	ErrMalformedInput = errors.New("malformed input")

	// ErrUnsupportedContent indicates skill content or formats that v1
	// rejects.
	ErrUnsupportedContent = errors.New("unsupported content")

	// ErrCryptoFailure indicates cryptographic material could not be used
	// (for example, an unparseable public key). A signature that fails
	// cryptographic verification is not an error: it is a block decision
	// reported as an ST-SIGNATURE-INVALID finding.
	ErrCryptoFailure = errors.New("cryptographic failure")

	// ErrPolicyFailure indicates a signature failed the organization
	// policy (no matching signer rule).
	ErrPolicyFailure = errors.New("policy failure")

	// ErrTrustUnavailable indicates trust material could not be loaded.
	ErrTrustUnavailable = errors.New("unavailable trust material")
)

// Signing modes.
const (
	ModeKeyless = "keyless"
	ModeKey     = "key"
)

// CertConstraints constrains keyless signer identities.
type CertConstraints struct {
	// Identities lists exact SAN values accepted for this signer.
	Identities []string `json:"identities,omitempty"`

	// IdentityRegexp is an RE2 alternative to Identities.
	IdentityRegexp string `json:"identityRegexp,omitempty"`

	// Issuer is the exact OIDC issuer recorded in the certificate.
	Issuer string `json:"issuer,omitempty"`

	// IssuerRegexp is an RE2 alternative to Issuer.
	IssuerRegexp string `json:"issuerRegexp,omitempty"`
}

// PublicKeyRef locates the expected public key for key-based signers.
type PublicKeyRef struct {
	// Path to a PEM public key file.
	Path string `json:"path,omitempty"`

	// Raw is an inline base64-encoded PEM public key.
	Raw string `json:"raw,omitempty"`
}

// ProvenanceConstraints requires certificate claims to match.
type ProvenanceConstraints struct {
	SourceRepository string `json:"sourceRepository,omitempty"`
	SourceRef        string `json:"sourceRef,omitempty"`
	WorkflowName     string `json:"workflowName,omitempty"`
	CommitSha        string `json:"commitSha,omitempty"`
}

func (p ProvenanceConstraints) empty() bool {
	return p == ProvenanceConstraints{}
}

// SignerRule is one allowed signer in a policy.
type SignerRule struct {
	Name        string                 `json:"name"`
	Mode        string                 `json:"mode"`
	Certificate *CertConstraints       `json:"certificate,omitempty"`
	PublicKey   *PublicKeyRef          `json:"publicKey,omitempty"`
	Provenance  *ProvenanceConstraints `json:"provenance,omitempty"`

	// TrustRoot names an entry in Policy.TrustRoots. Empty means the
	// default trust material for the mode: the embedded public Sigstore
	// root for keyless rules, none for key rules.
	TrustRoot string `json:"trustRoot,omitempty"`

	RequireTransparencyLog  *bool     `json:"requireTransparencyLog,omitempty"`
	RequireSignedTimestamps *bool     `json:"requireSignedTimestamps,omitempty"`
	MaxSignatureAge         *Duration `json:"maxSignatureAge,omitempty"`
}

// Defaults are policy-wide defaults applied when a rule omits a knob.
type Defaults struct {
	RequireTransparencyLog  *bool     `json:"requireTransparencyLog,omitempty"`
	RequireSignedTimestamps *bool     `json:"requireSignedTimestamps,omitempty"`
	MaxSignatureAge         *Duration `json:"maxSignatureAge,omitempty"`
}

// Policy is a parsed organization verification policy.
type Policy struct {
	APIVersion string                      `json:"apiVersion"`
	Name       string                      `json:"name,omitempty"`
	TrustRoots map[string]trust.RootConfig `json:"trustRoots,omitempty"`
	Signers    []SignerRule                `json:"signers"`
	Defaults   Defaults                    `json:"defaults,omitempty"`

	// keyPEM caches resolved public key PEM per rule name.
	keyPEM map[string][]byte
}

// LoadPolicy reads and validates a policy from a path.
func LoadPolicy(path string) (*Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: reading policy: %v", ErrMalformedInput, err)
	}
	return ParsePolicy(raw)
}

// ParsePolicy parses and validates a policy document.
func ParsePolicy(data []byte) (*Policy, error) {
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("%w: parsing policy: %v", ErrMalformedInput, err)
	}
	if p.APIVersion != PolicyAPIVersion {
		return nil, fmt.Errorf("%w: unsupported policy apiVersion %q (supported: %q)", ErrUnsupportedContent, p.APIVersion, PolicyAPIVersion)
	}
	if len(p.Signers) == 0 {
		return nil, fmt.Errorf("%w: policy defines no signers; it would block every skill", ErrPolicyFailure)
	}
	p.keyPEM = make(map[string][]byte, len(p.Signers))
	seen := make(map[string]struct{}, len(p.Signers))
	for i := range p.Signers {
		r := &p.Signers[i]
		if r.Name == "" {
			return nil, fmt.Errorf("%w: signer rule %d has no name", ErrMalformedInput, i)
		}
		if _, dup := seen[r.Name]; dup {
			return nil, fmt.Errorf("%w: duplicate signer rule name %q", ErrMalformedInput, r.Name)
		}
		seen[r.Name] = struct{}{}
		if err := p.validateRule(r); err != nil {
			return nil, err
		}
	}
	return &p, nil
}

func (p *Policy) validateRule(r *SignerRule) error {
	switch r.Mode {
	case ModeKeyless:
		if r.Certificate == nil {
			return fmt.Errorf("%w: keyless signer %q requires certificate constraints", ErrMalformedInput, r.Name)
		}
		c := r.Certificate
		if len(c.Identities) > 0 && c.IdentityRegexp != "" {
			return fmt.Errorf("%w: signer %q sets both identities and identityRegexp", ErrMalformedInput, r.Name)
		}
		if len(c.Identities) == 0 && c.IdentityRegexp == "" {
			return fmt.Errorf("%w: keyless signer %q requires identities or identityRegexp", ErrMalformedInput, r.Name)
		}
		if c.Issuer != "" && c.IssuerRegexp != "" {
			return fmt.Errorf("%w: signer %q sets both issuer and issuerRegexp", ErrMalformedInput, r.Name)
		}
		if c.Issuer == "" && c.IssuerRegexp == "" {
			return fmt.Errorf("%w: keyless signer %q requires issuer or issuerRegexp", ErrMalformedInput, r.Name)
		}
		if r.Provenance != nil && !r.Provenance.empty() {
			// allowed for keyless
		}
	case ModeKey:
		if r.Certificate != nil {
			return fmt.Errorf("%w: key signer %q must not set certificate constraints", ErrMalformedInput, r.Name)
		}
		if r.PublicKey == nil || (r.PublicKey.Path == "" && r.PublicKey.Raw == "") {
			return fmt.Errorf("%w: key signer %q requires a publicKey (path or raw)", ErrMalformedInput, r.Name)
		}
		if r.Provenance != nil && !r.Provenance.empty() {
			return fmt.Errorf("%w: signer %q combines key mode with provenance constraints, which can never match (key-based signatures carry no certificate claims)", ErrMalformedInput, r.Name)
		}
		pem, err := p.resolveKey(r)
		if err != nil {
			return err
		}
		p.keyPEM[r.Name] = pem
	default:
		return fmt.Errorf("%w: signer %q has unknown mode %q (supported: keyless, key)", ErrUnsupportedContent, r.Name, r.Mode)
	}

	if r.TrustRoot != "" {
		if _, ok := p.TrustRoots[r.TrustRoot]; !ok {
			return fmt.Errorf("%w: signer %q references unknown trust root %q", ErrMalformedInput, r.Name, r.TrustRoot)
		}
	}
	return nil
}

func (p *Policy) resolveKey(r *SignerRule) ([]byte, error) {
	if r.PublicKey.Path != "" {
		b, err := os.ReadFile(r.PublicKey.Path)
		if err != nil {
			return nil, fmt.Errorf("%w: reading public key for signer %q: %v", ErrTrustUnavailable, r.Name, err)
		}
		return b, nil
	}
	// Inline base64 PEM.
	b, err := base64.StdEncoding.DecodeString(r.PublicKey.Raw)
	if err != nil {
		return nil, fmt.Errorf("%w: decoding public key for signer %q: %v", ErrMalformedInput, r.Name, err)
	}
	return b, nil
}

// requireTlog resolves the transparency log requirement for a rule.
func (p *Policy) requireTlog(r *SignerRule) bool {
	if r.RequireTransparencyLog != nil {
		return *r.RequireTransparencyLog
	}
	if p.Defaults.RequireTransparencyLog != nil {
		return *p.Defaults.RequireTransparencyLog
	}
	return true
}

// requireTSA resolves the signed-timestamp requirement for a rule.
func (p *Policy) requireTSA(r *SignerRule) bool {
	if r.RequireSignedTimestamps != nil {
		return *r.RequireSignedTimestamps
	}
	if p.Defaults.RequireSignedTimestamps != nil {
		return *p.Defaults.RequireSignedTimestamps
	}
	return false
}

// maxAge resolves the maximum signature age for a rule (0 = no limit).
func (p *Policy) maxAge(r *SignerRule) time.Duration {
	if r.MaxSignatureAge != nil {
		return time.Duration(*r.MaxSignatureAge)
	}
	if p.Defaults.MaxSignatureAge != nil {
		return time.Duration(*p.Defaults.MaxSignatureAge)
	}
	return 0
}

// trustConfig converts the policy's trust roots into a trust.Config.
func (p *Policy) trustConfig() *trust.Config {
	return &trust.Config{TrustRoots: p.TrustRoots}
}
