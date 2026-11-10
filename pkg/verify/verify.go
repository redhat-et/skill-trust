package verify

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	fulciocert "github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	sgroot "github.com/sigstore/sigstore-go/pkg/root"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/redhat-et/skill-trust/pkg/manifest"
	"github.com/redhat-et/skill-trust/pkg/preflight"
	"github.com/redhat-et/skill-trust/pkg/trust"
)

// Finding codes, stable and documented in docs/POLICY.md.
const (
	CodePolicyMalformed     = "ST-POLICY-MALFORMED"
	CodePolicyNoMatch       = "ST-POLICY-NO-MATCH"
	CodePolicyNoSigners     = "ST-POLICY-NO-SIGNERS"
	CodeContentMismatch     = "ST-CONTENT-MISMATCH"
	CodeContentInvalid      = "ST-CONTENT-INVALID"
	CodeMetadataMissing     = "ST-METADATA-MISSING"
	CodeMetadataMalformed   = "ST-METADATA-MALFORMED"
	CodeSignatureInvalid    = "ST-SIGNATURE-INVALID"
	CodeEvidenceTlogMissing = "ST-EVIDENCE-TLOG-MISSING"
	CodeEvidenceTsaMissing  = "ST-EVIDENCE-TSA-MISSING"
	CodeEvidenceStale       = "ST-EVIDENCE-STALE"
	CodeTrustUnavailable    = "ST-TRUST-UNAVAILABLE"
	CodeProvenanceMismatch  = "ST-PROVENANCE-MISMATCH"
)

// Finding is one machine- and human-readable verification finding.
type Finding = preflight.Finding

// SignatureResult reports the evaluation of one signer rule against the
// skill's signature bundle.
type SignatureResult struct {
	// Rule is the signer rule name from the policy.
	Rule string `json:"rule"`

	// Mode is the signing mode ("keyless" or "key").
	Mode string `json:"mode"`

	// Identity is the certificate SAN for keyless signatures.
	Identity string `json:"identity,omitempty"`

	// Issuer is the OIDC issuer for keyless signatures.
	Issuer string `json:"issuer,omitempty"`

	// KeyHint is the public key hint for key-based signatures.
	KeyHint string `json:"keyHint,omitempty"`

	// Matched reports whether the rule fully matched: cryptographic
	// verification, identity, evidence, provenance, and freshness.
	Matched bool `json:"matched"`

	// Findings are the reasons this rule did not match, if it did not.
	Findings []Finding `json:"findings,omitempty"`
}

// Result is the outcome of verifying one skill directory. It embeds the
// preflight result shape so adapters can consume it directly.
type Result struct {
	preflight.Result

	// Signatures reports every signer rule evaluation.
	Signatures []SignatureResult `json:"signatures"`
}

// NewResult returns a blocked result with no findings yet.
func NewResult() Result {
	return Result{Result: preflight.Result{Decision: preflight.Block}}
}

// Allowed reports whether verification allows loading and execution.
func (r Result) Allowed() bool { return r.Decision == preflight.Allow }

// compiledRule is a signer rule with its trust material and verifier
// prepared at Verifier construction time.
type compiledRule struct {
	rule *SignerRule

	// material is the trusted material for the rule.
	material sgroot.TrustedMaterial

	// verifier performs cryptographic and evidence verification.
	verifier *sgverify.Verifier

	// identityOption is the policy identity option: WithCertificateIdentity
	// for keyless rules, WithKey for key rules.
	identityOption sgverify.PolicyOption
}

// Verifier evaluates skills against a policy. Construct one with New and
// reuse it; it is safe for concurrent use after construction.
type Verifier struct {
	policy *Policy
	rules  []compiledRule
}

// New compiles a policy into a Verifier, loading and validating all trust
// material up front. It fails if any trust material is unavailable.
func New(p *Policy) (*Verifier, error) {
	if p == nil {
		return nil, fmt.Errorf("%w: nil policy", ErrMalformedInput)
	}
	v := &Verifier{policy: p}
	for i := range p.Signers {
		r := &p.Signers[i]
		cr, err := v.compileRule(r)
		if err != nil {
			return nil, err
		}
		v.rules = append(v.rules, cr)
	}
	if len(v.rules) == 0 {
		return nil, fmt.Errorf("%w: policy has no signer rules", ErrPolicyFailure)
	}
	return v, nil
}

// compileRule resolves trust material and verifier options for one rule.
func (v *Verifier) compileRule(r *SignerRule) (compiledRule, error) {
	cr := compiledRule{rule: r}

	// Resolve trust material.
	switch r.Mode {
	case ModeKeyless:
		tm, err := v.loadTrustMaterial(r)
		if err != nil {
			return cr, err
		}
		cr.material = tm

		cid, err := certificateIdentity(r.Certificate)
		if err != nil {
			return cr, fmt.Errorf("%w: signer %q: %v", ErrMalformedInput, r.Name, err)
		}
		cr.identityOption = sgverify.WithCertificateIdentity(cid)

	case ModeKey:
		pemBytes, ok := v.policy.keyPEM[r.Name]
		if !ok {
			return cr, fmt.Errorf("%w: signer %q has no resolved public key", ErrTrustUnavailable, r.Name)
		}
		km, err := trust.LoadKeysFromPEM(pemBytes)
		if err != nil {
			return cr, fmt.Errorf("%w: signer %q: %v", ErrCryptoFailure, r.Name, err)
		}
		if r.TrustRoot != "" {
			tm, err := v.loadTrustMaterial(r)
			if err != nil {
				return cr, err
			}
			// Key material for hint authentication plus the trust root for
			// transparency log and timestamp verification.
			cr.material = sgroot.TrustedMaterialCollection{km.TrustedMaterial(), tm}
		} else {
			cr.material = km.TrustedMaterial()
		}
		cr.identityOption = sgverify.WithKey()

	default:
		return cr, fmt.Errorf("%w: signer %q has unknown mode %q", ErrUnsupportedContent, r.Name, r.Mode)
	}

	// Build the verifier options from the evidence requirements. Exactly
	// one time strategy is required by sigstore-go.
	requireTlog := v.policy.requireTlog(r)
	requireTSA := v.policy.requireTSA(r)

	var opts []sgverify.VerifierOption
	switch {
	case requireTlog && requireTSA:
		opts = []sgverify.VerifierOption{
			sgverify.WithTransparencyLog(1),
			sgverify.WithSignedTimestamps(1),
		}
	case requireTlog:
		opts = []sgverify.VerifierOption{
			sgverify.WithTransparencyLog(1),
			sgverify.WithObserverTimestamps(1),
		}
	case requireTSA:
		opts = []sgverify.VerifierOption{sgverify.WithSignedTimestamps(1)}
	case r.Mode == ModeKeyless:
		// Keyless certificates are short-lived and must be time-validated
		// against observer timestamps; with the transparency log not
		// required, this means an RFC 3161 timestamp.
		opts = []sgverify.VerifierOption{sgverify.WithObserverTimestamps(1)}
	default:
		opts = []sgverify.VerifierOption{sgverify.WithNoObserverTimestamps()}
	}

	sev, err := sgverify.NewVerifier(cr.material, opts...)
	if err != nil {
		return cr, fmt.Errorf("%w: signer %q: verifier construction: %v", ErrTrustUnavailable, r.Name, err)
	}
	cr.verifier = sev
	return cr, nil
}

// loadTrustMaterial resolves the trust material for a rule: the named
// trust root, or the embedded public Sigstore root when unspecified.
func (v *Verifier) loadTrustMaterial(r *SignerRule) (sgroot.TrustedMaterial, error) {
	if r.TrustRoot == "" {
		tm, err := trust.LoadRoot(trust.RootConfig{Type: trust.TypeSigstorePublic})
		if err != nil {
			return nil, fmt.Errorf("%w: signer %q: public Sigstore root: %v", ErrTrustUnavailable, r.Name, err)
		}
		return tm, nil
	}
	tm, err := v.policy.trustConfig().Material(r.TrustRoot)
	if err != nil {
		return nil, fmt.Errorf("%w: signer %q: trust root %q: %v", ErrTrustUnavailable, r.Name, r.TrustRoot, err)
	}
	return tm, nil
}

// VerifySkill verifies the skill rooted at dir against the policy. The
// returned Result is always meaningful when err is nil: verification
// failures are decisions (findings, block), not errors. An error return
// means the verifier could not run at all (unusable trust material,
// unreadable input beyond control files).
func (v *Verifier) VerifySkill(dir string) (Result, error) {
	res := NewResult()

	// 1. Embedded manifest (control file).
	embedded, err := manifest.LoadControlManifest(dir)
	if err != nil {
		res.Findings = append(res.Findings, Finding{
			Code:    CodeMetadataMissing,
			Message: fmt.Sprintf("embedded manifest: %v", err),
		})
		return res, nil
	}
	expectedDigest, err := embedded.Digest()
	if err != nil {
		res.Findings = append(res.Findings, Finding{
			Code:    CodeMetadataMalformed,
			Message: fmt.Sprintf("embedded manifest digest: %v", err),
		})
		return res, nil
	}
	res.ManifestDigest = expectedDigest

	// 2. Recompute the manifest from the directory.
	observed, err := manifest.Create(dir)
	if err != nil {
		code := CodeContentInvalid
		if errors.Is(err, manifest.ErrMalformedInput) {
			code = CodeMetadataMalformed
		}
		res.Findings = append(res.Findings, Finding{
			Code:    code,
			Message: fmt.Sprintf("recomputing manifest: %v", err),
		})
		return res, nil
	}
	observedDigest, err := observed.Digest()
	if err != nil {
		res.Findings = append(res.Findings, Finding{
			Code:    CodeContentInvalid,
			Message: fmt.Sprintf("recomputed manifest digest: %v", err),
		})
		return res, nil
	}
	res.ObservedDigest = observedDigest

	// 3. Content comparison.
	if diffs := manifest.Compare(embedded, observed); len(diffs) > 0 {
		for _, d := range diffs {
			res.Findings = append(res.Findings, Finding{
				Code:    CodeContentMismatch,
				Message: d.Details,
			})
		}
		return res, nil
	}

	// 4. Signature bundle (control file).
	raw, err := os.ReadFile(manifest.ControlPath(dir, manifest.BundleFile))
	if err != nil {
		res.Findings = append(res.Findings, Finding{
			Code:    CodeMetadataMissing,
			Message: fmt.Sprintf("signature bundle: %v", err),
		})
		return res, nil
	}
	var pb protobundle.Bundle
	if err := protojson.Unmarshal(raw, &pb); err != nil {
		res.Findings = append(res.Findings, Finding{
			Code:    CodeMetadataMalformed,
			Message: fmt.Sprintf("signature bundle does not parse as a Sigstore bundle: %v", err),
		})
		return res, nil
	}
	sb, err := sgbundle.NewBundle(&pb)
	if err != nil {
		res.Findings = append(res.Findings, Finding{
			Code:    CodeMetadataMalformed,
			Message: fmt.Sprintf("signature bundle is structurally invalid: %v", err),
		})
		return res, nil
	}

	// The signed subject: canonical bytes of the manifest. The embedded
	// and recomputed manifests are identical at this point.
	canonical, err := embedded.Canonical()
	if err != nil {
		res.Findings = append(res.Findings, Finding{
			Code:    CodeMetadataMalformed,
			Message: fmt.Sprintf("canonical manifest: %v", err),
		})
		return res, nil
	}

	// 5. Evaluate every signer rule; one full match allows.
	matched := false
	for _, cr := range v.rules {
		sr := v.evaluateRule(cr, &pb, sb, canonical)
		res.Signatures = append(res.Signatures, sr)
		if sr.Matched {
			matched = true
			res.Signer = describeSigner(sr)
		}
	}
	if !matched {
		res.Findings = append(res.Findings, Finding{
			Code:    CodePolicyNoMatch,
			Message: "the signature did not fully match any signer rule (see signatures for per-rule findings)",
		})
		return res, nil
	}

	res.Decision = preflight.Allow
	return res, nil
}

// evaluateRule runs one signer rule against the bundle.
func (v *Verifier) evaluateRule(cr compiledRule, pb *protobundle.Bundle, sb *sgbundle.Bundle, canonical []byte) SignatureResult {
	sr := SignatureResult{Rule: cr.rule.Name, Mode: cr.rule.Mode}

	// Descriptive fields from the bundle.
	if cert := certFromBundle(pb); cert != nil {
		if summary, err := fulciocert.SummarizeCertificate(cert); err == nil {
			sr.Identity = summary.SubjectAlternativeName
			sr.Issuer = summary.Issuer
		} else {
			sr.Identity = sanOf(cert)
		}
	}
	if hint := pb.GetVerificationMaterial().GetPublicKey().GetHint(); len(hint) > 0 {
		sr.KeyHint = string(hint)
	}

	fail := func(code, message string) SignatureResult {
		sr.Findings = append(sr.Findings, Finding{Code: code, Message: message})
		return sr
	}

	// Evidence presence pre-checks: distinguish "absent" from "invalid".
	requireTlog := v.policy.requireTlog(cr.rule)
	requireTSA := v.policy.requireTSA(cr.rule)
	if requireTlog && len(pb.GetVerificationMaterial().GetTlogEntries()) == 0 {
		return fail(CodeEvidenceTlogMissing, "rule requires a transparency log entry; the bundle has none")
	}
	if requireTSA && len(pb.GetVerificationMaterial().GetTimestampVerificationData().GetRfc3161Timestamps()) == 0 {
		return fail(CodeEvidenceTsaMissing, "rule requires an RFC 3161 timestamp; the bundle has none")
	}

	// Cryptographic and evidence verification.
	policy := sgverify.NewPolicy(sgverify.WithArtifact(bytes.NewReader(canonical)), cr.identityOption)
	vr, err := cr.verifier.Verify(sb, policy)
	if err != nil {
		return fail(CodeSignatureInvalid, err.Error())
	}

	// Identity and key descriptors from the verification result.
	if vr.Signature != nil && vr.Signature.Certificate != nil {
		if vr.Signature.Certificate.SubjectAlternativeName != "" {
			sr.Identity = vr.Signature.Certificate.SubjectAlternativeName
		}
		if vr.Signature.Certificate.Issuer != "" {
			sr.Issuer = vr.Signature.Certificate.Issuer
		}
	}
	if vr.Signature != nil && vr.Signature.PublicKeyID != nil && len(*vr.Signature.PublicKeyID) > 0 {
		sr.KeyHint = string(*vr.Signature.PublicKeyID)
	}

	// Provenance constraints (keyless only; key rules cannot have them).
	if cr.rule.Provenance != nil && !cr.rule.Provenance.empty() {
		cert := certFromBundle(pb)
		if cert == nil {
			return fail(CodeProvenanceMismatch, "rule requires certificate provenance claims; the signature carries no certificate")
		}
		summary, err := fulciocert.SummarizeCertificate(cert)
		if err != nil {
			return fail(CodeProvenanceMismatch, fmt.Sprintf("summarizing certificate: %v", err))
		}
		if f := checkProvenance(*cr.rule.Provenance, summary); f != nil {
			return fail(f.Code, f.Message)
		}
	}

	// Freshness.
	if maxAge := v.policy.maxAge(cr.rule); maxAge > 0 {
		if f := checkFreshness(maxAge, vr.VerifiedTimestamps); f != nil {
			return fail(f.Code, f.Message)
		}
	}

	// Every check passed: the rule matches.
	sr.Matched = true
	return sr
}

// PreflightVerifier returns the verifier as a preflight.Verifier for
// harness adapters.
func (v *Verifier) PreflightVerifier() preflight.Verifier {
	return preflightVerifier{v}
}

type preflightVerifier struct{ v *Verifier }

func (p preflightVerifier) VerifySkill(dir string) (preflight.Result, error) {
	res, err := p.v.VerifySkill(dir)
	return res.Result, err
}

// certificateIdentity builds a sigstore-go certificate identity from the
// rule's constraints.
func certificateIdentity(c *CertConstraints) (sgverify.CertificateIdentity, error) {
	issuer, issuerRe := c.Issuer, c.IssuerRegexp
	switch {
	case len(c.Identities) == 1:
		return sgverify.NewShortCertificateIdentity(issuer, issuerRe, c.Identities[0], "")
	case len(c.Identities) > 1:
		var sb strings.Builder
		sb.WriteString("^(")
		for i, id := range c.Identities {
			if i > 0 {
				sb.WriteString("|")
			}
			sb.WriteString(regexp.QuoteMeta(id))
		}
		sb.WriteString(")$")
		return sgverify.NewShortCertificateIdentity(issuer, issuerRe, "", sb.String())
	default:
		return sgverify.NewShortCertificateIdentity(issuer, issuerRe, "", c.IdentityRegexp)
	}
}

// checkProvenance verifies certificate claims against the rule's
// provenance constraints. Returns nil when all constraints pass.
//
// GitHub Actions certificates carry Fulcio's workflow extensions; both the
// original fields (e.g. GithubWorkflowRepository "owner/repo") and the
// newer generic fields (e.g. SourceRepositoryURI) are accepted, in either
// combination, so constraints match certificates across Fulcio versions.
func checkProvenance(p ProvenanceConstraints, summary fulciocert.Summary) *Finding {
	check := func(field string, expected string, actuals ...string) *Finding {
		if expected == "" {
			return nil
		}
		for _, actual := range actuals {
			if actual != "" && actual == expected {
				return nil
			}
		}
		return &Finding{
			Code:    CodeProvenanceMismatch,
			Message: fmt.Sprintf("provenance %s: expected %q, certificate claims %q", field, expected, strings.Join(nonEmpty(actuals), " or ")),
		}
	}
	if f := check("sourceRepository", p.SourceRepository, summary.GithubWorkflowRepository, summary.SourceRepositoryURI); f != nil {
		return f
	}
	if f := check("sourceRef", p.SourceRef, summary.GithubWorkflowRef, summary.SourceRepositoryRef); f != nil {
		return f
	}
	if f := check("workflowName", p.WorkflowName, summary.GithubWorkflowName); f != nil {
		return f
	}
	if f := check("commitSha", p.CommitSha, summary.GithubWorkflowSHA, summary.SourceRepositoryDigest); f != nil {
		return f
	}
	return nil
}

func nonEmpty(values []string) []string {
	var out []string
	for _, v := range values {
		if v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return []string{"(no claim)"}
	}
	return out
}

// checkFreshness verifies the signature is not older than maxAge, using
// the newest verified observer timestamp as the signature time. Returns
// nil when fresh (or when no timestamp exists, which the evidence
// requirements have already policed).
func checkFreshness(maxAge time.Duration, timestamps []sgverify.TimestampVerificationResult) *Finding {
	if len(timestamps) == 0 {
		return nil
	}
	newest := timestamps[0].Timestamp
	for _, ts := range timestamps[1:] {
		if ts.Timestamp.After(newest) {
			newest = ts.Timestamp
		}
	}
	if age := time.Since(newest); age > maxAge {
		return &Finding{
			Code:    CodeEvidenceStale,
			Message: fmt.Sprintf("signature is %s old, exceeding maxSignatureAge %s (newest verified timestamp %s)", age.Round(time.Second), maxAge, newest.UTC().Format(time.RFC3339)),
		}
	}
	return nil
}

// certFromBundle extracts the signer certificate from bundle verification
// material, if present.
func certFromBundle(pb *protobundle.Bundle) *x509.Certificate {
	vm := pb.GetVerificationMaterial()
	if vm == nil {
		return nil
	}
	raw := vm.GetCertificate().GetRawBytes()
	if len(raw) == 0 {
		certs := vm.GetX509CertificateChain().GetCertificates()
		if len(certs) == 0 {
			return nil
		}
		raw = certs[0].GetRawBytes()
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil
	}
	return cert
}

func sanOf(cert *x509.Certificate) string {
	if len(cert.URIs) > 0 {
		return cert.URIs[0].String()
	}
	if len(cert.EmailAddresses) > 0 {
		return cert.EmailAddresses[0]
	}
	return ""
}

func describeSigner(sr SignatureResult) string {
	switch sr.Mode {
	case ModeKeyless:
		return fmt.Sprintf("rule %q (keyless identity %s, issuer %s)", sr.Rule, sr.Identity, sr.Issuer)
	default:
		return fmt.Sprintf("rule %q (key %s)", sr.Rule, sr.KeyHint)
	}
}

// DigestOnlyPolicy is a helper for callers that verify an already-extracted
// canonical manifest against a bundle; it is used by tests and tooling.
func DigestOnlyPolicy(canonical []byte, identity sgverify.PolicyOption) sgverify.PolicyBuilder {
	return sgverify.NewPolicy(sgverify.WithArtifact(bytes.NewReader(canonical)), identity)
}

var _ = protocommon.HashAlgorithm_SHA2_256 // keep the import for documentation of bundle digest algorithms
