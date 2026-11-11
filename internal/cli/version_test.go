package cli

import (
	"encoding/json"
	"runtime/debug"
	"strings"
	"testing"
)

func TestResolveVersionPrecedence(t *testing.T) {
	tests := []struct {
		name        string
		ldflag      string
		envVersion  string
		buildInfo   *debug.BuildInfo
		wantVersion string
		wantCommit  string
	}{
		{
			name:        "ldflag beats env and buildinfo",
			ldflag:      "v0.2.0",
			envVersion:  "v9",
			buildInfo:   &debug.BuildInfo{Main: debug.Module{Version: "v0.1.0"}},
			wantVersion: "v0.2.0",
		},
		{
			name:        "env beats buildinfo",
			ldflag:      "",
			envVersion:  "v9",
			buildInfo:   &debug.BuildInfo{Main: debug.Module{Version: "v0.1.0"}},
			wantVersion: "v9",
		},
		{
			name:        "buildinfo version",
			ldflag:      "",
			envVersion:  "",
			buildInfo:   &debug.BuildInfo{Main: debug.Module{Version: "v0.1.0"}},
			wantVersion: "v0.1.0",
		},
		{
			name:       "buildinfo devel with vcs",
			ldflag:     "",
			envVersion: "",
			buildInfo: &debug.BuildInfo{
				Main: debug.Module{Version: "(devel)"},
				Settings: []debug.BuildSetting{
					{Key: "vcs.revision", Value: "abcdef1234567"},
					{Key: "vcs.modified", Value: "true"},
				},
			},
			wantVersion: "devel+abcdef1-dirty",
			wantCommit:  "abcdef1234567",
		},
		{
			name:        "nil info",
			ldflag:      "",
			envVersion:  "",
			buildInfo:   nil,
			wantVersion: "devel",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getenv := func(key string) string {
				if key == "SKILL_TRUST_VERSION" {
					return tt.envVersion
				}
				return ""
			}
			got := resolveVersion(tt.ldflag, getenv, tt.buildInfo)
			if got.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", got.Version, tt.wantVersion)
			}
			if tt.wantCommit != "" && got.Commit != tt.wantCommit {
				t.Errorf("Commit = %q, want %q", got.Commit, tt.wantCommit)
			}
			if got.GoVersion == "" {
				t.Error("GoVersion should not be empty")
			}
		})
	}
}

func TestVersionCommand(t *testing.T) {
	code, out := runCLI(t, "version")
	if code != ExitSuccess {
		t.Errorf("exit code = %d, want %d", code, ExitSuccess)
	}
	if !strings.HasPrefix(out, "skill-trust version ") {
		t.Errorf("output should start with 'skill-trust version ', got: %q", out)
	}
}

func TestVersionCommandJSON(t *testing.T) {
	code, out := runCLI(t, "version", "--json")
	if code != ExitSuccess {
		t.Errorf("exit code = %d, want %d", code, ExitSuccess)
	}
	var info VersionInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v\nOutput: %s", err, out)
	}
	if info.Version == "" {
		t.Error("Version should not be empty")
	}
	if info.GoVersion == "" {
		t.Error("GoVersion should not be empty")
	}
}

func TestRootVersionFlagMatches(t *testing.T) {
	code, out := runCLI(t, "--version")
	if code != ExitSuccess {
		t.Errorf("exit code = %d, want %d", code, ExitSuccess)
	}
	expected := Version().Version
	if !strings.Contains(out, expected) {
		t.Errorf("--version output should contain %q, got: %q", expected, out)
	}
}
