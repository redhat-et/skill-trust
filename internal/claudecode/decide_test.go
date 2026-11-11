package claudecode

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/redhat-et/skill-trust/pkg/preflight"
)

// fakeVerifier implements preflight.Verifier for testing
type fakeVerifier map[string]preflight.Result

func (f fakeVerifier) VerifySkill(dir string) (preflight.Result, error) {
	if res, ok := f[dir]; ok {
		return res, nil
	}
	return preflight.Result{
		Decision: preflight.Block,
		Findings: []preflight.Finding{{
			Code:    "ST-METADATA-MISSING",
			Message: "no verification data",
		}},
	}, nil
}

// errorVerifier always returns an error
type errorVerifier struct {
	err error
}

func (e errorVerifier) VerifySkill(dir string) (preflight.Result, error) {
	return preflight.Result{}, e.err
}

func TestDecideTable(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name          string
		verifyResult  preflight.Result
		prev          *Record
		strict        bool
		wantAllowed   bool
		wantBlockCode string
		wantWarning   bool
		wantNewRecord bool
		wantRecordNil bool // for sticky rows
	}{
		// Row: allow + no previous record + strict=true → allow, record digest
		{
			name: "AllowNoPrevStrict",
			verifyResult: preflight.Result{
				Decision:       preflight.Allow,
				ManifestDigest: "abc123",
				ObservedDigest: "abc123",
			},
			prev:          nil,
			strict:        true,
			wantAllowed:   true,
			wantNewRecord: true,
		},
		// Row: allow + no previous record + strict=false → allow, record digest
		{
			name: "AllowNoPrevNonStrict",
			verifyResult: preflight.Result{
				Decision:       preflight.Allow,
				ManifestDigest: "abc123",
				ObservedDigest: "abc123",
			},
			prev:          nil,
			strict:        false,
			wantAllowed:   true,
			wantNewRecord: true,
		},
		// Row: allow + allowed same digest + strict=true → allow (no new record)
		{
			name: "AllowSameDigestStrict",
			verifyResult: preflight.Result{
				Decision:       preflight.Allow,
				ManifestDigest: "abc123",
				ObservedDigest: "abc123",
			},
			prev:          &Record{Allowed: true, Digest: "abc123", VerifiedAt: now.Add(-time.Hour)},
			strict:        true,
			wantAllowed:   true,
			wantRecordNil: true,
		},
		// Row: allow + allowed same digest + strict=false → allow
		{
			name: "AllowSameDigestNonStrict",
			verifyResult: preflight.Result{
				Decision:       preflight.Allow,
				ManifestDigest: "abc123",
				ObservedDigest: "abc123",
			},
			prev:          &Record{Allowed: true, Digest: "abc123", VerifiedAt: now.Add(-time.Hour)},
			strict:        false,
			wantAllowed:   true,
			wantRecordNil: true,
		},
		// Row: allow + allowed different digest + strict=true → block CodeChangedAfterVerify
		{
			name: "AllowDifferentDigestStrict",
			verifyResult: preflight.Result{
				Decision:       preflight.Allow,
				ManifestDigest: "xyz789",
				ObservedDigest: "xyz789",
			},
			prev:          &Record{Allowed: true, Digest: "abc123", VerifiedAt: now.Add(-time.Hour)},
			strict:        true,
			wantAllowed:   false,
			wantBlockCode: preflight.CodeChangedAfterVerify,
			wantRecordNil: true, // sticky, never return new record
		},
		// Row: allow + allowed different digest + strict=false → block CodeChangedAfterVerify
		{
			name: "AllowDifferentDigestNonStrict",
			verifyResult: preflight.Result{
				Decision:       preflight.Allow,
				ManifestDigest: "xyz789",
				ObservedDigest: "xyz789",
			},
			prev:          &Record{Allowed: true, Digest: "abc123", VerifiedAt: now.Add(-time.Hour)},
			strict:        false,
			wantAllowed:   false,
			wantBlockCode: preflight.CodeChangedAfterVerify,
			wantRecordNil: true, // sticky
		},
		// Row: allow + not-allowed → allow and record (self-healing, both strict values)
		{
			name: "AllowAfterNotAllowedStrict",
			verifyResult: preflight.Result{
				Decision:       preflight.Allow,
				ManifestDigest: "xyz789",
				ObservedDigest: "xyz789",
			},
			prev:          &Record{Allowed: false, Digest: "abc123", VerifiedAt: now.Add(-time.Hour)},
			strict:        true,
			wantAllowed:   true,
			wantNewRecord: true,
		},
		{
			name: "AllowAfterNotAllowedNonStrict",
			verifyResult: preflight.Result{
				Decision:       preflight.Allow,
				ManifestDigest: "xyz789",
				ObservedDigest: "xyz789",
			},
			prev:          &Record{Allowed: false, Digest: "abc123", VerifiedAt: now.Add(-time.Hour)},
			strict:        false,
			wantAllowed:   true,
			wantNewRecord: true,
		},
		// Row: block + allowed → block CodeChangedAfterVerify (both strict values)
		{
			name: "BlockAfterAllowedStrict",
			verifyResult: preflight.Result{
				Decision:       preflight.Block,
				ManifestDigest: "abc123",
				ObservedDigest: "def456",
				Findings: []preflight.Finding{{
					Code:    "ST-CONTENT-MISMATCH",
					Message: "content changed",
				}},
			},
			prev:          &Record{Allowed: true, Digest: "abc123", VerifiedAt: now.Add(-time.Hour)},
			strict:        true,
			wantAllowed:   false,
			wantBlockCode: preflight.CodeChangedAfterVerify,
			wantRecordNil: true, // sticky
		},
		{
			name: "BlockAfterAllowedNonStrict",
			verifyResult: preflight.Result{
				Decision:       preflight.Block,
				ManifestDigest: "abc123",
				ObservedDigest: "def456",
				Findings: []preflight.Finding{{
					Code:    "ST-CONTENT-MISMATCH",
					Message: "content changed",
				}},
			},
			prev:          &Record{Allowed: true, Digest: "abc123", VerifiedAt: now.Add(-time.Hour)},
			strict:        false,
			wantAllowed:   false,
			wantBlockCode: preflight.CodeChangedAfterVerify,
			wantRecordNil: true, // sticky
		},
		// Row: block + none + strict=true → block NotVerified (unsigned)
		{
			name: "BlockNoPrevStrictUnsigned",
			verifyResult: preflight.Result{
				Decision: preflight.Block,
				Findings: []preflight.Finding{{
					Code:    "ST-METADATA-MISSING",
					Message: "no .skill-trust directory",
				}},
			},
			prev:          nil,
			strict:        true,
			wantAllowed:   false,
			wantBlockCode: preflight.CodeNotVerified,
		},
		// Row: block + none + strict=false → allow with Warning
		{
			name: "BlockNoPrevNonStrictUnsigned",
			verifyResult: preflight.Result{
				Decision: preflight.Block,
				Findings: []preflight.Finding{{
					Code:    "ST-METADATA-MISSING",
					Message: "no .skill-trust directory",
				}},
			},
			prev:        nil,
			strict:      false,
			wantAllowed: true,
			wantWarning: true,
		},
		// Row: block + not-allowed + strict=true → block VerifierFailure (signed but failed)
		{
			name: "BlockNotAllowedStrictSigned",
			verifyResult: preflight.Result{
				Decision:       preflight.Block,
				ManifestDigest: "abc123",
				ObservedDigest: "def456",
				Findings: []preflight.Finding{{
					Code:    "ST-CONTENT-MISMATCH",
					Message: "content mismatch",
				}},
			},
			prev:          &Record{Allowed: false, Digest: "abc123", VerifiedAt: now.Add(-time.Hour)},
			strict:        true,
			wantAllowed:   false,
			wantBlockCode: preflight.CodeVerifierFailure,
		},
		// Row: block + not-allowed + strict=false → allow with Warning
		{
			name: "BlockNotAllowedNonStrictSigned",
			verifyResult: preflight.Result{
				Decision:       preflight.Block,
				ManifestDigest: "abc123",
				ObservedDigest: "def456",
				Findings: []preflight.Finding{{
					Code:    "ST-CONTENT-MISMATCH",
					Message: "content mismatch",
				}},
			},
			prev:        &Record{Allowed: false, Digest: "abc123", VerifiedAt: now.Add(-time.Hour)},
			strict:      false,
			wantAllowed: true,
			wantWarning: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temp root for the test
			root := t.TempDir()

			// For unsigned tests, ensure .skill-trust doesn't exist
			// For signed tests, create .skill-trust
			if strings.Contains(tt.name, "Unsigned") {
				// Don't create .skill-trust
			} else if strings.Contains(tt.name, "Signed") {
				os.Mkdir(filepath.Join(root, ".skill-trust"), 0o755)
			}

			verifier := fakeVerifier{root: tt.verifyResult}

			outcome, newRecord := Decide(verifier, root, tt.prev, tt.strict, now)

			if outcome.Allowed != tt.wantAllowed {
				t.Errorf("Allowed = %v, want %v", outcome.Allowed, tt.wantAllowed)
			}

			if tt.wantBlockCode != "" {
				if outcome.Block == nil {
					t.Errorf("expected Block with code %s, got nil", tt.wantBlockCode)
				} else if outcome.Block.Code != tt.wantBlockCode {
					t.Errorf("Block.Code = %s, want %s", outcome.Block.Code, tt.wantBlockCode)
				}
			}

			if tt.wantWarning && outcome.Warning == "" {
				t.Error("expected Warning, got empty string")
			}

			if tt.wantRecordNil && newRecord != nil {
				t.Errorf("expected nil record (sticky), got %+v", newRecord)
			}

			if tt.wantNewRecord && newRecord == nil {
				t.Error("expected new record, got nil")
			}

			if newRecord != nil {
				if newRecord.Digest != tt.verifyResult.ManifestDigest {
					t.Errorf("newRecord.Digest = %s, want %s", newRecord.Digest, tt.verifyResult.ManifestDigest)
				}
				if newRecord.Allowed != tt.wantAllowed {
					t.Errorf("newRecord.Allowed = %v, want %v", newRecord.Allowed, tt.wantAllowed)
				}
			}
		})
	}
}

func TestDecideVerifierError(t *testing.T) {
	now := time.Now()

	t.Run("VerifierErrorWithPrevAllowed", func(t *testing.T) {
		root := t.TempDir()
		prev := &Record{
			Allowed:    true,
			Digest:     "prev-digest",
			VerifiedAt: now.Add(-time.Hour),
		}
		verifier := errorVerifier{err: fmt.Errorf("verifier crashed")}

		outcome, newRecord := Decide(verifier, root, prev, true, now)

		// Error + prev allowed → CHANGED-AFTER-VERIFY
		if outcome.Allowed {
			t.Error("expected blocked")
		}
		if outcome.Block == nil || outcome.Block.Code != preflight.CodeChangedAfterVerify {
			t.Errorf("expected CodeChangedAfterVerify, got %v", outcome.Block)
		}
		if newRecord != nil {
			t.Error("expected nil record (sticky)")
		}
	})

	t.Run("VerifierErrorUnsignedStrict", func(t *testing.T) {
		root := t.TempDir()
		// Don't create .skill-trust (unsigned)
		verifier := errorVerifier{err: fmt.Errorf("verifier crashed")}

		outcome, newRecord := Decide(verifier, root, nil, true, now)

		// Error + unsigned + strict → NOT-VERIFIED
		if outcome.Allowed {
			t.Error("expected blocked")
		}
		if outcome.Block == nil || outcome.Block.Code != preflight.CodeNotVerified {
			t.Errorf("expected CodeNotVerified, got %v", outcome.Block)
		}
		if newRecord != nil {
			t.Error("expected nil record")
		}
	})

	t.Run("VerifierErrorNonStrictNoPrev", func(t *testing.T) {
		root := t.TempDir()
		verifier := errorVerifier{err: fmt.Errorf("verifier crashed")}

		outcome, newRecord := Decide(verifier, root, nil, false, now)

		// Error + none/not-allowed + strict=false → allow with warning
		if !outcome.Allowed {
			t.Error("expected allowed with warning")
		}
		if outcome.Warning == "" {
			t.Error("expected warning")
		}
		if newRecord != nil {
			t.Error("expected nil record")
		}
	})
}

func TestReasonIncludesDigests(t *testing.T) {
	root := t.TempDir()

	outcome := Outcome{
		Root:    root,
		Allowed: false,
		Block: &preflight.BlockError{
			Code:           preflight.CodeChangedAfterVerify,
			Message:        "skill changed",
			ExpectedDigest: "abc123",
			ObservedDigest: "xyz789",
			UnderlyingFindings: []preflight.Finding{
				{Code: "ST-CONTENT-MISMATCH", Message: "file changed"},
				{Code: "ST-ANOTHER", Message: "another issue"},
			},
		},
	}

	reason := Reason(outcome)

	if !strings.Contains(reason, preflight.CodeChangedAfterVerify) {
		t.Error("reason should contain block code")
	}
	if !strings.Contains(reason, "skill changed") {
		t.Error("reason should contain message")
	}
	if !strings.Contains(reason, "expected digest abc123") {
		t.Error("reason should contain expected digest")
	}
	if !strings.Contains(reason, "observed digest xyz789") {
		t.Error("reason should contain observed digest")
	}
	if !strings.Contains(reason, "ST-CONTENT-MISMATCH") {
		t.Error("reason should contain underlying finding code")
	}
	if !strings.Contains(reason, "file changed") {
		t.Error("reason should contain underlying finding message")
	}
}

func TestDecideUnsignedDetection(t *testing.T) {
	now := time.Now()

	t.Run("UnsignedNoSkillTrustDir", func(t *testing.T) {
		root := t.TempDir()
		// Don't create .skill-trust directory

		verifier := fakeVerifier{
			root: preflight.Result{
				Decision: preflight.Block,
				Findings: []preflight.Finding{{
					Code:    "ST-METADATA-MISSING",
					Message: "no bundle",
				}},
			},
		}

		outcome, _ := Decide(verifier, root, nil, true, now)

		if outcome.Block == nil || outcome.Block.Code != preflight.CodeNotVerified {
			t.Errorf("expected CodeNotVerified for unsigned, got %v", outcome.Block)
		}
	})

	t.Run("SignedHasSkillTrustDir", func(t *testing.T) {
		root := t.TempDir()
		// Create .skill-trust directory
		os.Mkdir(filepath.Join(root, ".skill-trust"), 0o755)

		verifier := fakeVerifier{
			root: preflight.Result{
				Decision:       preflight.Block,
				ManifestDigest: "abc123",
				ObservedDigest: "def456",
				Findings: []preflight.Finding{{
					Code:    "ST-CONTENT-MISMATCH",
					Message: "content mismatch",
				}},
			},
		}

		outcome, _ := Decide(verifier, root, nil, true, now)

		if outcome.Block == nil || outcome.Block.Code != preflight.CodeVerifierFailure {
			t.Errorf("expected CodeVerifierFailure for signed but failed, got %v", outcome.Block)
		}
	})

	t.Run("SignedWithSTMetadataCode", func(t *testing.T) {
		root := t.TempDir()
		// Create .skill-trust directory (exists, so it's signed)
		os.Mkdir(filepath.Join(root, ".skill-trust"), 0o755)

		// Findings contain ST-METADATA-* code but it's signed
		verifier := fakeVerifier{
			root: preflight.Result{
				Decision: preflight.Block,
				Findings: []preflight.Finding{{
					Code:    "ST-METADATA-MALFORMED",
					Message: "malformed metadata",
				}},
			},
		}

		outcome, _ := Decide(verifier, root, nil, true, now)

		// Should be CodeVerifierFailure (signed but failed)
		if outcome.Block == nil || outcome.Block.Code != preflight.CodeVerifierFailure {
			t.Errorf("expected CodeVerifierFailure for signed with ST-METADATA-* code, got %v", outcome.Block)
		}
	})
}

func TestDecideExpectedObservedDigests(t *testing.T) {
	now := time.Now()
	root := t.TempDir()

	prev := &Record{
		Allowed:    true,
		Digest:     "expected-digest",
		VerifiedAt: now.Add(-time.Hour),
	}

	verifier := fakeVerifier{
		root: preflight.Result{
			Decision:       preflight.Allow,
			ManifestDigest: "observed-digest",
			ObservedDigest: "observed-digest",
		},
	}

	outcome, _ := Decide(verifier, root, prev, true, now)

	if outcome.Block == nil {
		t.Fatal("expected block for changed digest")
	}

	if outcome.Block.ExpectedDigest != "expected-digest" {
		t.Errorf("ExpectedDigest = %s, want expected-digest", outcome.Block.ExpectedDigest)
	}

	if outcome.Block.ObservedDigest != "observed-digest" {
		t.Errorf("ObservedDigest = %s, want observed-digest", outcome.Block.ObservedDigest)
	}
}

func TestReasonLimitsFindings(t *testing.T) {
	root := t.TempDir()

	// Create more than 5 findings
	findings := make([]preflight.Finding, 10)
	for i := 0; i < 10; i++ {
		findings[i] = preflight.Finding{
			Code:    fmt.Sprintf("CODE-%d", i),
			Message: fmt.Sprintf("message %d", i),
		}
	}

	outcome := Outcome{
		Root:    root,
		Allowed: false,
		Block: &preflight.BlockError{
			Code:               preflight.CodeVerifierFailure,
			Message:            "verification failed",
			UnderlyingFindings: findings,
		},
	}

	reason := Reason(outcome)

	// Should contain first 5 findings
	for i := 0; i < 5; i++ {
		code := fmt.Sprintf("CODE-%d", i)
		if !strings.Contains(reason, code) {
			t.Errorf("reason should contain %s", code)
		}
	}

	// Should not contain findings beyond 5
	for i := 5; i < 10; i++ {
		code := fmt.Sprintf("CODE-%d", i)
		if strings.Contains(reason, code) {
			t.Errorf("reason should not contain %s (beyond limit)", code)
		}
	}
}
