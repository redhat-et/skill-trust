package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/redhat-et/skill-trust/pkg/sign"
	"github.com/redhat-et/skill-trust/pkg/trust"
)

var (
	signKey      string
	signIDToken  string
	signServices string
)

var signCmd = &cobra.Command{
	Use:   "sign <dir>",
	Short: "Sign a skill directory",
	Long: `Sign a skill directory.

Builds the canonical manifest, embeds it as .skill-trust/manifest.json, and
produces a Sigstore bundle over the manifest bytes at
.skill-trust/bundle.sigstore.json. Skill content outside .skill-trust/ is
never modified.

Exactly one signing mode is selected:

  --key       key-based signing with a PEM private key. Without services,
              the bundle carries no transparency log entry or timestamp;
              verification then needs a policy that does not require them.

  --id-token  keyless signing: Fulcio exchanges a pre-acquired OIDC
              identity token (for example a GitHub Actions token requested
              with audience "sigstore") for a short-lived certificate.
              The value is a token, "@file" containing one, or "github"
              to fetch a fresh token from the GitHub Actions runtime
              (requires the id-token: write permission). Requires
              services with a Fulcio URL, plus Rekor or a TSA so the
              certificate can be time-validated.

The --services file selects the signing deployment (Fulcio, Rekor, TSA
endpoints); see docs/TRUST-CONFIG.md. When --services is not given,
.skill-trust-services.json in the working directory is used if present.
A services file may set trustedRootPath to make the signer self-verify its
output before returning; switching between the public Sigstore instance
and RHTAS is a configuration change, not a code change.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		dir := args[0]

		if signKey != "" && signIDToken != "" {
			failf("provide either --key or --id-token, not both")
			return
		}
		if signKey == "" && signIDToken == "" {
			failf("provide a signing mode: --key <path> (key-based) or --id-token <token|@file> (keyless)")
			return
		}

		idToken := signIDToken
		switch {
		case strings.HasPrefix(idToken, "@"):
			b, err := os.ReadFile(strings.TrimPrefix(idToken, "@"))
			if err != nil {
				failf("reading identity token: %v", err)
				return
			}
			idToken = strings.TrimSpace(string(b))
		case idToken == "github":
			// Fetch a fresh OIDC token from the GitHub Actions runtime.
			token, err := sign.GitHubOIDCToken(cmd.Context(), sign.GitHubOIDCAudience)
			if err != nil {
				failf("fetching GitHub OIDC token: %v", err)
				return
			}
			idToken = token
		}

		services, err := resolveServices()
		if err != nil {
			fail(err)
			return
		}

		opts := sign.Options{
			KeyPath:  signKey,
			IDToken:  idToken,
			Services: services,
		}
		if services.TrustedRootPath != "" {
			tm, err := trust.LoadRoot(trust.RootConfig{
				Type: trust.TypeTrustedRoot,
				Path: services.TrustedRootPath,
			})
			if err != nil {
				failf("loading trusted root %q: %v", services.TrustedRootPath, err)
				return
			}
			opts.TrustedRoot = tm
		}

		res, err := sign.Skill(cmd.Context(), dir, opts)
		if err != nil {
			failf("signing %s: %v", dir, err)
			return
		}

		if jsonOutput {
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			if err := enc.Encode(res); err != nil {
				failf("encoding output: %v", err)
				return
			}
			return
		}

		w := cmd.OutOrStdout()
		fmt.Fprintf(w, "signed:    %s\n", dir)
		fmt.Fprintf(w, "digest:    %s\n", res.ManifestDigest)
		switch {
		case res.KeyHint != "":
			fmt.Fprintf(w, "mode:      key (hint %s)\n", res.KeyHint)
		case res.Identity != "":
			fmt.Fprintf(w, "mode:      keyless\n")
			fmt.Fprintf(w, "identity:  %s\n", res.Identity)
			fmt.Fprintf(w, "issuer:    %s\n", res.Issuer)
		default:
			fmt.Fprintf(w, "mode:      unknown\n")
		}
		fmt.Fprintf(w, "rekor:     %s\n", yesNo(res.HasTlogEntry))
		fmt.Fprintf(w, "timestamp: %s\n", yesNo(res.HasTimestamp))
		fmt.Fprintf(w, "bundle:    %s\n", res.BundlePath)
	},
}

// resolveServices loads signing services: the --services path when given,
// else the conventional .skill-trust-services.json when it exists, else
// the zero value (fully offline key-based signing).
func resolveServices() (trust.Services, error) {
	if signServices != "" {
		return trust.LoadServices(signServices)
	}
	if _, err := os.Stat(trust.DefaultServicesPath); err == nil {
		return trust.LoadServices(trust.DefaultServicesPath)
	}
	return trust.Services{}, nil
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func init() {
	signCmd.Flags().StringVar(&signKey, "key", "",
		"path to a PEM private key for key-based signing")
	signCmd.Flags().StringVar(&signIDToken, "id-token", "",
		"OIDC identity token for keyless signing, @file containing it, or \"github\" to fetch one from the GitHub Actions runtime")
	signCmd.Flags().StringVar(&signServices, "services", "",
		"path to a signing services JSON file (default: .skill-trust-services.json if present)")
	rootCmd.AddCommand(signCmd)
}
