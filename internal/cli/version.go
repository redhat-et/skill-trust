package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/spf13/cobra"
)

// buildVersion is set via ldflags at build time:
// -ldflags "-X github.com/redhat-et/skill-trust/internal/cli.buildVersion=v0.2.0"
var buildVersion string

// VersionInfo reports the version, commit, and Go version.
type VersionInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	GoVersion string `json:"goVersion"`
}

// Version returns the current version information.
func Version() VersionInfo {
	info, _ := debug.ReadBuildInfo()
	return resolveVersion(buildVersion, os.Getenv, info)
}

// resolveVersion determines the version from ldflags, environment, or build info.
// Precedence: ldflag > env > buildinfo.
func resolveVersion(ldflag string, getenv func(string) string, info *debug.BuildInfo) VersionInfo {
	var v VersionInfo

	// Determine Go version
	if info != nil && info.GoVersion != "" {
		v.GoVersion = info.GoVersion
	} else {
		v.GoVersion = runtime.Version()
	}

	// Determine version with precedence: ldflag > env > buildinfo
	if ldflag != "" {
		v.Version = ldflag
		return v
	}

	if env := getenv("SKILL_TRUST_VERSION"); env != "" {
		v.Version = env
		return v
	}

	if info == nil {
		v.Version = "devel"
		return v
	}

	// Use buildinfo
	if info.Main.Version != "" && info.Main.Version != "(devel)" {
		v.Version = info.Main.Version
		return v
	}

	// Handle (devel) with VCS information
	var revision, modified string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}

	if revision != "" {
		v.Commit = revision
		// Shorten revision to 7 chars for version string
		shortRev := revision
		if len(shortRev) > 7 {
			shortRev = shortRev[:7]
		}
		v.Version = "devel+" + shortRev
		if modified == "true" {
			v.Version += "-dirty"
		}
	} else {
		v.Version = "devel"
	}

	return v
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		info := Version()
		if jsonOutput {
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			if err := enc.Encode(info); err != nil {
				fail(err)
			}
			return
		}
		var parts []string
		parts = append(parts, fmt.Sprintf("skill-trust version %s", info.Version))
		if info.Commit != "" {
			parts = append(parts, fmt.Sprintf("commit %s", info.Commit))
		}
		parts = append(parts, fmt.Sprintf("go %s", info.GoVersion))
		fmt.Fprintln(cmd.OutOrStdout(), strings.Join(parts, ", "))
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
