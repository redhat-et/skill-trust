package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/redhat-et/skill-trust/pkg/manifest"
)

var manifestWrite bool

var manifestCmd = &cobra.Command{
	Use:   "manifest <dir>",
	Short: "Compute the canonical manifest of a skill directory",
	Long: `Compute the canonical manifest of a skill directory.

The manifest lists every file under the skill root with its content digest
and executable bit; its canonical JSON form is the subject that signing
covers. This command does not sign; it shows what would be signed. Use
--write to embed the manifest as the .skill-trust/manifest.json control
file (sign does this automatically).`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		dir := args[0]
		m, err := manifest.Create(dir)
		if err != nil {
			failf("computing manifest: %v", err)
			return
		}
		digest, err := m.Digest()
		if err != nil {
			failf("computing digest: %v", err)
			return
		}

		wrote := false
		if manifestWrite {
			if err := m.WriteControlManifest(dir); err != nil {
				failf("writing manifest control file: %v", err)
				return
			}
			wrote = true
		}

		executable := 0
		for _, e := range m.Entries {
			if e.Executable {
				executable++
			}
		}

		if jsonOutput {
			out := struct {
				Version         int              `json:"version"`
				HashAlgorithm   string           `json:"hashAlgorithm"`
				Digest          string           `json:"digest"`
				EntryCount      int              `json:"entryCount"`
				ExecutableCount int              `json:"executableCount"`
				Entries         []manifest.Entry `json:"entries"`
				WroteControl    bool             `json:"wroteControlFile,omitempty"`
			}{
				Version:         m.Version,
				HashAlgorithm:   m.HashAlgorithm,
				Digest:          digest,
				EntryCount:      len(m.Entries),
				ExecutableCount: executable,
				Entries:         m.Entries,
				WroteControl:    wrote,
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			if err := enc.Encode(out); err != nil {
				failf("encoding output: %v", err)
				return
			}
			return
		}

		w := cmd.OutOrStdout()
		fmt.Fprintf(w, "digest:    %s\n", digest)
		fmt.Fprintf(w, "version:   %d (%s)\n", m.Version, m.HashAlgorithm)
		fmt.Fprintf(w, "files:     %d (%d executable)\n", len(m.Entries), executable)
		if wrote {
			fmt.Fprintf(w, "wrote:     %s\n", manifest.ControlPath(dir, manifest.ManifestFile))
		}
	},
}

func init() {
	manifestCmd.Flags().BoolVar(&manifestWrite, "write", false,
		"write the manifest to .skill-trust/manifest.json")
	rootCmd.AddCommand(manifestCmd)
}
