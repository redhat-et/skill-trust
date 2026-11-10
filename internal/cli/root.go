// Package cli implements the skill-trust command line interface. It is a
// thin, stable wrapper over the library packages: manifest computation,
// signing, verification, and inspection. The CLI never executes, imports,
// or interprets skill content.
package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Exit codes, stable across releases:
//
//	0 — success (for verify: the skill is allowed)
//	1 — verification decision: the skill is blocked (findings reported)
//	2 — operational error (bad arguments, unreadable input, unavailable
//	    trust material); no decision was reached
const (
	ExitSuccess = 0
	ExitBlocked = 1
	ExitError   = 2
)

// exitCode is set by commands before returning; Execute reports it.
var exitCode = ExitSuccess

// jsonOutput switches all commands to machine-readable JSON on stdout.
var jsonOutput bool

var rootCmd = &cobra.Command{
	Use:   "skill-trust",
	Short: "Sign and verify AI agent skills with Sigstore",
	Long: `skill-trust signs and verifies AI agent skills.

A skill is a directory with a SKILL.md at its root. Signing produces a
canonical manifest of every file (content digests and executable bits) and
a Sigstore bundle over the manifest bytes, both stored under
.skill-trust/. Verification recomputes the manifest, compares it byte for
byte with the signed one, and evaluates the signature against an
organization policy. The tool never executes, imports, or interprets skill
content.

Exit codes: 0 success (verify: allowed), 1 blocked, 2 operational error.`,
	Example: `  # Compute the manifest of a skill directory:
  skill-trust manifest ./my-skill

  # Sign with a release key (offline; no log entry or timestamp):
  skill-trust sign ./my-skill --key release.key

  # Sign with a release key, recording to Rekor and the TSA of the
  # deployment described by .skill-trust-services.json:
  skill-trust sign ./my-skill --key release.key --services services.json

  # Keyless signing in CI against the public Sigstore good instance
  # (Fulcio + Rekor + TSA), using a pre-acquired OIDC token:
  skill-trust sign ./my-skill --id-token "$OIDC_TOKEN" --services public.json

  # Keyless signing against RHTAS: point --services at your RHTAS
  # endpoints file (fulcioURL, rekorURL, tsaURL) and give the token from
  # your OIDC provider. The services file may also carry trustedRootPath
  # pointing at the RHTAS TrustedRoot JSON so the signer self-verifies.
  skill-trust sign ./my-skill --id-token @token.txt --services rhtas.json

  # Verify a skill against an organization policy:
  skill-trust verify ./my-skill --policy policy.json

  # Inspect the control files of a signed skill (no policy, no crypto):
  skill-trust inspect ./my-skill`,
	Version: version(),
}

// Execute runs the CLI and returns the process exit code.
func Execute() int {
	if err := rootCmd.Execute(); err != nil {
		// cobra has already printed usage errors.
		return ExitError
	}
	return exitCode
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false,
		"emit machine-readable JSON on stdout")
}

// version reports the build version from embedded VCS information when
// available.
func version() string {
	if v := os.Getenv("SKILL_TRUST_VERSION"); v != "" {
		return v
	}
	// best-effort: builds from a git worktree carry (devel) with vcs info
	return "devel"
}

// fail prints an operational error and terminates with ExitError.
func fail(err error) {
	fmt.Fprintf(os.Stderr, "skill-trust: %v\n", err)
	exitCode = ExitError
}

// failf is fail with formatting.
func failf(format string, args ...any) {
	fail(fmt.Errorf(format, args...))
}

var errBlocked = errors.New("blocked")
