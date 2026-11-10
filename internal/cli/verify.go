package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/redhat-et/skill-trust/pkg/manifest"
	"github.com/redhat-et/skill-trust/pkg/verify"
)

var (
	verifyPolicy string
	verifyReport bool
)

var verifyCmd = &cobra.Command{
	Use:   "verify <dir>",
	Short: "Verify a skill directory against a policy",
	Long: `Verify a skill directory against an organization policy.

Loads the embedded manifest, recomputes it from the directory, compares
them byte for byte, and evaluates the signature bundle against every
signer rule in the policy. The skill is allowed only when the content is
unmodified and at least one signer rule fully matches: cryptography,
identity, provenance, evidence, and freshness.

Verification is fail closed: any missing control file, any content
difference, any failed check blocks the skill. The command never executes,
imports, or interprets skill content.

Exit codes: 0 allowed, 1 blocked (findings reported), 2 operational
error. See docs/POLICY.md for the policy schema and finding codes.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		dir := args[0]
		if verifyPolicy == "" {
			failf("--policy is required")
			return
		}

		p, err := verify.LoadPolicy(verifyPolicy)
		if err != nil {
			failf("loading policy: %v", err)
			return
		}
		v, err := verify.New(p)
		if err != nil {
			failf("preparing verifier: %v", err)
			return
		}
		res, err := v.VerifySkill(dir)
		if err != nil {
			failf("verifying %s: %v", dir, err)
			return
		}

		if verifyReport {
			reportPath := manifest.ControlPath(dir, manifest.ReportFile)
			if err := os.MkdirAll(manifest.ControlPath(dir, ""), 0o755); err != nil {
				failf("writing report: %v", err)
				return
			}
			b, err := json.MarshalIndent(res, "", "  ")
			if err != nil {
				failf("encoding report: %v", err)
				return
			}
			b = append(b, '\n')
			if err := os.WriteFile(reportPath, b, 0o644); err != nil {
				failf("writing report: %v", err)
				return
			}
		}

		w := cmd.OutOrStdout()
		if jsonOutput {
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			if err := enc.Encode(res); err != nil {
				failf("encoding output: %v", err)
				return
			}
		} else {
			if res.Allowed() {
				fmt.Fprintf(w, "ALLOW %s\n", dir)
				fmt.Fprintf(w, "  signer:  %s\n", res.Signer)
				fmt.Fprintf(w, "  digest:  %s\n", res.ManifestDigest)
			} else {
				fmt.Fprintf(w, "BLOCK %s\n", dir)
			}
			if res.ManifestDigest != "" && !res.Allowed() {
				fmt.Fprintf(w, "  expected digest: %s\n", res.ManifestDigest)
				if res.ObservedDigest != "" && res.ObservedDigest != res.ManifestDigest {
					fmt.Fprintf(w, "  observed digest: %s\n", res.ObservedDigest)
				}
			}
			for _, f := range res.Findings {
				fmt.Fprintf(w, "  finding: [%s] %s\n", f.Code, f.Message)
			}
			for _, s := range res.Signatures {
				status := "no match"
				if s.Matched {
					status = "matched"
				}
				fmt.Fprintf(w, "  rule %s (%s): %s\n", s.Rule, s.Mode, status)
				for _, f := range s.Findings {
					fmt.Fprintf(w, "    [%s] %s\n", f.Code, f.Message)
				}
			}
		}

		if !res.Allowed() {
			exitCode = ExitBlocked
		}
	},
}

func init() {
	verifyCmd.Flags().StringVar(&verifyPolicy, "policy", "",
		"path to the verification policy JSON (required)")
	verifyCmd.Flags().BoolVar(&verifyReport, "report", false,
		"write the verification result to .skill-trust/report.json")
	verifyCmd.MarkFlagRequired("policy")
	rootCmd.AddCommand(verifyCmd)
}
