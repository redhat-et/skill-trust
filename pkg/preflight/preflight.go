// Package preflight defines the harness enforcement contract for verified
// skills.
//
// A harness adapter uses this package to verify a skill before loading its
// instructions, to associate execution with a verified content digest, and
// to re-verify before any skill-associated file is executed or read. The
// package never executes skill content and never implements a second
// manifest or signature algorithm: all trust decisions flow through a
// Verifier.
//
// Script enforcement is path-containment based, which is what makes it
// cover every helper runtime — Bash, Python, JavaScript, or anything else
// an agent can invoke — without parsing per-language command syntax.
package preflight

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/redhat-et/skill-trust/pkg/manifest"
)

// Decision is the outcome of a verification.
type Decision string

// Decisions.
const (
	Allow Decision = "allow"
	Block Decision = "block"
)

// Finding is one machine- and human-readable verification finding.
// Codes are stable and documented in docs/POLICY.md.
type Finding struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Result is the outcome of verifying one skill directory.
type Result struct {
	Decision       Decision  `json:"decision"`
	ManifestDigest string    `json:"manifestDigest"` // expected (signed) digest
	ObservedDigest string    `json:"observedDigest"` // recomputed digest
	Signer         string    `json:"signer,omitempty"`
	Findings       []Finding `json:"findings"`
}

// Allowed reports whether the result permits loading and execution.
func (r Result) Allowed() bool { return r.Decision == Allow }

// BlockError is returned when a guard denies an operation. It carries the
// machine-readable code, the user-readable message, and the expected and
// observed digests for reporting.
type BlockError struct {
	Code               string
	Message            string
	ExpectedDigest     string
	ObservedDigest     string
	UnderlyingFindings []Finding
}

func (e *BlockError) Error() string {
	if e.ExpectedDigest != "" && e.ObservedDigest != "" && e.ExpectedDigest != e.ObservedDigest {
		return fmt.Sprintf("%s: %s (expected digest %s, observed %s)", e.Code, e.Message, e.ExpectedDigest, e.ObservedDigest)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Finding codes used by the preflight layer itself. Signature, policy, and
// evidence codes (ST-*) are produced by the verifier and passed through.
const (
	// CodeNotVerified is used when a path belongs to a skill that was
	// never verified (loaded or executed without a preflight allow).
	CodeNotVerified = "ST-PREFLIGHT-NOT-VERIFIED"

	// CodeChangedAfterVerify is used when content changed between the
	// allow decision and a later guard check.
	CodeChangedAfterVerify = "ST-PREFLIGHT-CHANGED-AFTER-VERIFY"

	// CodeVerifierFailure is used when the verifier itself failed or
	// blocked the skill.
	CodeVerifierFailure = "ST-PREFLIGHT-VERIFIER-FAILURE"
)

// Verifier verifies one skill directory. The verify package provides the
// production implementation (manifest recomputation, bundle verification,
// policy evaluation). Adapters must not implement their own.
type Verifier interface {
	// VerifySkill verifies the skill rooted at dir and returns the
	// decision with the expected (signed) and observed (recomputed)
	// manifest digests.
	VerifySkill(dir string) (Result, error)
}

// VerifiedSkill records a successful verification of one skill root.
type VerifiedSkill struct {
	// Root is the absolute, symlink-free path of the verified skill
	// directory.
	Root string

	// ManifestDigest is the verified content identity.
	ManifestDigest string

	// VerifiedAt is when the allow decision was made.
	VerifiedAt time.Time
}

// Preflight tracks verified skills and guards loading and execution.
// It is safe for concurrent use.
type Preflight struct {
	verifier Verifier

	mu       sync.RWMutex
	verified map[string]VerifiedSkill // root path -> record
}

// New creates a Preflight using the provided Verifier.
func New(v Verifier) *Preflight {
	return &Preflight{
		verifier: v,
		verified: make(map[string]VerifiedSkill),
	}
}

// VerifyBeforeLoad implements step 1-4 of the harness contract: verify the
// skill rooted at dir before any instruction (SKILL.md) or resource is
// read. On success the skill is registered as verified and its content
// identity is associated with the root. On failure nothing is registered.
func (p *Preflight) VerifyBeforeLoad(dir string) (VerifiedSkill, error) {
	abs, err := absPath(dir)
	if err != nil {
		return VerifiedSkill{}, &BlockError{Code: CodeVerifierFailure, Message: err.Error()}
	}

	res, err := p.verifier.VerifySkill(abs)
	if err != nil {
		return VerifiedSkill{}, &BlockError{
			Code:               CodeVerifierFailure,
			Message:            fmt.Sprintf("verification of %s failed: %v", abs, err),
			ExpectedDigest:     res.ManifestDigest,
			ObservedDigest:     res.ObservedDigest,
			UnderlyingFindings: res.Findings,
		}
	}
	if !res.Allowed() {
		return VerifiedSkill{}, &BlockError{
			Code:               CodeVerifierFailure,
			Message:            fmt.Sprintf("verification of %s blocked", abs),
			ExpectedDigest:     res.ManifestDigest,
			ObservedDigest:     res.ObservedDigest,
			UnderlyingFindings: res.Findings,
		}
	}

	vs := VerifiedSkill{
		Root:           abs,
		ManifestDigest: res.ManifestDigest,
		VerifiedAt:     time.Now(),
	}

	p.mu.Lock()
	p.verified[abs] = vs
	p.mu.Unlock()

	return vs, nil
}

// GuardExecution must be called before a harness executes or reads any
// file whose path may belong to a skill (for example, before running a
// Bash, Python, or JavaScript helper referenced by a skill instruction).
//
// path is resolved to an absolute path. Three outcomes:
//
//   - path is not under any registered skill root: allowed (not a
//     skill-trust-managed file);
//   - path is under a registered skill root and the skill still verifies
//     to the same digest: allowed;
//   - path is under a registered skill root whose content changed, or
//     whose verification now fails: BlockError.
//
// The check is by path containment and digest re-verification, not by
// parsing the command, so it covers every helper runtime uniformly.
func (p *Preflight) GuardExecution(path string) error {
	abs, err := absPath(path)
	if err != nil {
		// An unresolvable path is not under a verified skill root.
		return nil
	}

	root, ok := p.containingRoot(abs)
	if !ok {
		return nil
	}

	res, err := p.verifier.VerifySkill(root)
	if err != nil {
		return &BlockError{
			Code:               CodeChangedAfterVerify,
			Message:            fmt.Sprintf("skill %s failed re-verification: %v", root, err),
			ExpectedDigest:     p.recordedDigest(root),
			ObservedDigest:     res.ObservedDigest,
			UnderlyingFindings: res.Findings,
		}
	}
	if !res.Allowed() {
		return &BlockError{
			Code:               CodeChangedAfterVerify,
			Message:            fmt.Sprintf("skill %s changed or no longer satisfies policy after it was loaded", root),
			ExpectedDigest:     p.recordedDigest(root),
			ObservedDigest:     res.ObservedDigest,
			UnderlyingFindings: res.Findings,
		}
	}
	return nil
}

// GuardSkillPath is like GuardExecution but for a path that the harness
// already knows belongs to a skill (for example the skill directory itself
// on reload). If the path is under a registered root it must re-verify; if
// it is not registered at all it is treated as unverified and blocked,
// because the caller asserted it is a skill path.
func (p *Preflight) GuardSkillPath(path string) error {
	abs, err := absPath(path)
	if err != nil {
		return &BlockError{Code: CodeNotVerified, Message: fmt.Sprintf("cannot resolve skill path %s", path)}
	}
	if _, ok := p.containingRoot(abs); !ok {
		return &BlockError{
			Code:    CodeNotVerified,
			Message: fmt.Sprintf("skill path %s was never verified before use", abs),
		}
	}
	return p.GuardExecution(abs)
}

// containingRoot returns the registered skill root containing path, if any.
func (p *Preflight) containingRoot(abs string) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	// Exact match first (the skill root itself).
	if _, ok := p.verified[abs]; ok {
		return abs, true
	}
	// Longest registered root that is a path prefix of abs.
	best := ""
	for root := range p.verified {
		if len(root) > len(best) && strings.HasPrefix(abs, root+string(filepath.Separator)) {
			best = root
		}
	}
	if best != "" {
		return best, true
	}
	return "", false
}

func (p *Preflight) recordedDigest(root string) string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if vs, ok := p.verified[root]; ok {
		return vs.ManifestDigest
	}
	return ""
}

// Forget removes the verification record for a skill root (for example
// after the harness unloads the skill).
func (p *Preflight) Forget(dir string) {
	abs, err := absPath(dir)
	if err != nil {
		return
	}
	p.mu.Lock()
	delete(p.verified, abs)
	p.mu.Unlock()
}

// absPath resolves dir to an absolute, symlink-free path.
func absPath(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	// Evaluate symlinks in the parent chain so containment checks cannot
	// be evaded with a symlinked path component. A missing final element
	// is tolerated; missing parents are not.
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		if parent, perr := filepath.EvalSymlinks(filepath.Dir(abs)); perr == nil {
			return filepath.Join(parent, filepath.Base(abs)), nil
		}
		return "", err
	}
	return resolved, nil
}

// ManifestVerifier is a Verifier that performs content-identity
// verification only: it recomputes the manifest from the directory and
// compares it with the embedded .skill-trust/manifest.json. It performs no
// signature or policy checks and is intended for integrity-only use and
// for tests. Production adapters must use the full verifier.
type ManifestVerifier struct{}

// VerifySkill implements Verifier.
func (ManifestVerifier) VerifySkill(dir string) (Result, error) {
	embedded, err := manifest.LoadControlManifest(dir)
	if err != nil {
		return Result{Decision: Block, Findings: []Finding{{
			Code:    "ST-METADATA-MISSING",
			Message: err.Error(),
		}}}, nil
	}

	observed, err := manifest.Create(dir)
	if err != nil {
		return Result{Decision: Block, Findings: []Finding{{
			Code:    "ST-CONTENT-INVALID",
			Message: err.Error(),
		}}}, nil
	}

	expectedDigest, err := embedded.Digest()
	if err != nil {
		return Result{Decision: Block, Findings: []Finding{{
			Code:    "ST-METADATA-MALFORMED",
			Message: err.Error(),
		}}}, nil
	}
	observedDigest, err := observed.Digest()
	if err != nil {
		return Result{Decision: Block, Findings: []Finding{{
			Code:    "ST-CONTENT-INVALID",
			Message: err.Error(),
		}}}, nil
	}

	res := Result{
		Decision:       Allow,
		ManifestDigest: expectedDigest,
		ObservedDigest: observedDigest,
	}

	if diffs := manifest.Compare(embedded, observed); len(diffs) > 0 {
		res.Decision = Block
		for _, d := range diffs {
			res.Findings = append(res.Findings, Finding{
				Code:    "ST-CONTENT-MISMATCH",
				Message: d.Details,
			})
		}
	}
	return res, nil
}
