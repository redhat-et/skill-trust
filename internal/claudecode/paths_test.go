package claudecode

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestNormalizePath(t *testing.T) {
	// Test case: collapse symlinked ancestor to canonical path
	t.Run("CollapseSymlinkedAncestor", func(t *testing.T) {
		tmpReal := t.TempDir()
		canonical, err := filepath.EvalSymlinks(tmpReal)
		if err != nil {
			t.Fatal(err)
		}
		skillDir := filepath.Join(tmpReal, "demo")
		if err := os.Mkdir(skillDir, 0o755); err != nil {
			t.Fatal(err)
		}

		tmpAlias := t.TempDir()
		alias := filepath.Join(tmpAlias, "alias")
		if err := os.Symlink(tmpReal, alias); err != nil {
			t.Fatal(err)
		}

		viaAlias := NormalizePath(filepath.Join(alias, "demo", "scripts", "run.sh"))
		if !strings.HasPrefix(viaAlias, canonical) {
			t.Errorf("expected path to start with %s, got %s", canonical, viaAlias)
		}
		if strings.HasPrefix(viaAlias, alias) {
			t.Errorf("expected path not to start with alias %s, got %s", alias, viaAlias)
		}
	})

	// Test case: resolve deepest existing ancestor for not-yet-existing path
	t.Run("DeepestExistingAncestor", func(t *testing.T) {
		tmpReal := t.TempDir()
		canonical, err := filepath.EvalSymlinks(tmpReal)
		if err != nil {
			t.Fatal(err)
		}

		tmpAlias := t.TempDir()
		alias := filepath.Join(tmpAlias, "alias")
		if err := os.Symlink(tmpReal, alias); err != nil {
			t.Fatal(err)
		}

		viaAlias := NormalizePath(filepath.Join(alias, "scripts", "not-yet.sh"))
		if !strings.HasPrefix(viaAlias, canonical) {
			t.Errorf("expected path to start with %s, got %s", canonical, viaAlias)
		}
	})

	// Test case: pass through paths that do not exist at all
	t.Run("NonexistentPath", func(t *testing.T) {
		p := "/nonexistent/skill/scripts/run.sh"
		got := NormalizePath(p)
		if got != p {
			t.Errorf("expected %s, got %s", p, got)
		}
	})

	// Test case: handle double slashes and .. in nonexistent paths
	t.Run("DoubleSlashAndDotDot", func(t *testing.T) {
		// Reach the temp dir through a symlink, as on macOS where
		// /var -> /private/var; NormalizePath must return the real path.
		tmpReal := symlinkedTempDir(t)
		// Create /tmp/x/a
		aDir := filepath.Join(tmpReal, "a")
		os.Mkdir(aDir, 0o755)

		// Path with double slash and ..
		p := filepath.Join(tmpReal, "a//b/../missing")
		got := NormalizePath(p)
		// Should clean to <realpath>/a/missing
		resolved, err := filepath.EvalSymlinks(tmpReal)
		if err != nil {
			t.Fatal(err)
		}
		expected := filepath.Join(resolved, "a", "missing")
		if got != expected {
			t.Errorf("NormalizePath(%q) = %q, want %q", p, got, expected)
		}
	})
}

func TestCommandPaths(t *testing.T) {
	cwd := "/proj"

	tests := []struct {
		name     string
		command  string
		cwd      string
		expected []string
	}{
		{
			name:     "ExtractPathLikeTokens",
			command:  "bash /proj/scripts/run.sh",
			cwd:      cwd,
			expected: []string{"/proj/scripts/run.sh"},
		},
		{
			name:     "ExtractPythonPath",
			command:  "python .opencode/skill/demo/scripts/util.py",
			cwd:      cwd,
			expected: []string{"/proj/.opencode/skill/demo/scripts/util.py"},
		},
		{
			name:     "RelativeTokensAgainstCwd",
			command:  "./scripts/run.sh",
			cwd:      "/proj/skill",
			expected: []string{"/proj/skill/scripts/run.sh"},
		},
		{
			name:     "DoubleQuotedPaths",
			command:  `bash "/proj/my skill/run.sh"`,
			cwd:      cwd,
			expected: []string{"/proj/my skill/run.sh"},
		},
		{
			name:     "SingleQuotedPaths",
			command:  `bash '/proj/my skill/run.sh'`,
			cwd:      cwd,
			expected: []string{"/proj/my skill/run.sh"},
		},
		{
			name:     "IgnoreFlagsURLsRedirectsVariables",
			command:  "curl https://example.com/x.py -o out.py > log 2>&1 $SCRIPT",
			cwd:      cwd,
			expected: []string{},
		},
		{
			name:     "IgnoreTokensWithoutPathSeparator",
			command:  "echo hello python util.py",
			cwd:      cwd,
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CommandPaths(tt.command, tt.cwd, "")
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("CommandPaths(%q, %q) = %v, want %v", tt.command, tt.cwd, got, tt.expected)
			}
		})
	}
}

func TestCandidatePaths(t *testing.T) {
	t.Run("PathFieldsAndCommandFields", func(t *testing.T) {
		input := map[string]any{
			"path":    "src/a.ts",
			"command": "bash scripts/run.sh",
			"timeout": 5,
		}
		got := CandidatePaths(input, "/proj", "")
		// Should contain these paths (order doesn't matter, cwd always included)
		hasATS := false
		hasRunSh := false
		hasProj := false
		for _, p := range got {
			if p == "/proj/src/a.ts" {
				hasATS = true
			}
			if p == "/proj/scripts/run.sh" {
				hasRunSh = true
			}
			if p == "/proj" {
				hasProj = true
			}
		}
		if !hasATS || !hasRunSh || !hasProj {
			t.Errorf("got %v, missing expected paths", got)
		}
	})

	t.Run("CommonPathKeySpellings", func(t *testing.T) {
		input := map[string]any{
			"filePath":  "a",
			"workdir":   "/w",
			"directory": "d",
		}
		got := CandidatePaths(input, "/proj", "")
		// Should be normalized and deduplicated
		hasA := false
		hasW := false
		hasD := false
		for _, p := range got {
			if p == "/proj/a" {
				hasA = true
			}
			if p == "/w" {
				hasW = true
			}
			if p == "/proj/d" {
				hasD = true
			}
		}
		if !hasA || !hasW || !hasD {
			t.Errorf("got %v, missing expected paths", got)
		}
	})

	t.Run("IgnoreNonStringAndEmptyValues", func(t *testing.T) {
		input := map[string]any{
			"path":    3,
			"command": nil,
			"other":   "",
		}
		got := CandidatePaths(input, "/proj", "")
		if len(got) != 1 || got[0] != "/proj" {
			t.Errorf("got %v, want [/proj]", got)
		}
	})

	t.Run("NestedInput", func(t *testing.T) {
		input := map[string]any{
			"outer": map[string]any{
				"file_path": "nested/file.txt",
			},
			"arr": []any{
				map[string]any{"command": "bash scripts/x.sh"},
			},
		}
		got := CandidatePaths(input, "/root", "")
		hasNested := false
		hasScript := false
		for _, p := range got {
			if p == "/root/nested/file.txt" {
				hasNested = true
			}
			if p == "/root/scripts/x.sh" {
				hasScript = true
			}
		}
		if !hasNested || !hasScript {
			t.Errorf("got %v, missing nested paths", got)
		}
	})

	t.Run("NonexistentFileInRoot", func(t *testing.T) {
		root := t.TempDir()
		realRoot, _ := filepath.EvalSymlinks(root)
		input := map[string]any{
			"file_path": filepath.Join(root, "scripts/new.sh"),
		}
		got := CandidatePaths(input, root, "")
		expected := filepath.Join(realRoot, "scripts", "new.sh")
		hasExpected := false
		for _, p := range got {
			if p == expected {
				hasExpected = true
				break
			}
		}
		if !hasExpected {
			t.Errorf("got %v, expected to contain %s", got, expected)
		}
	})

	t.Run("NonObjectInput", func(t *testing.T) {
		got := CandidatePaths("str", "/cwd", "")
		if len(got) != 1 || got[0] != "/cwd" {
			t.Errorf("got %v, want [/cwd]", got)
		}

		got = CandidatePaths(nil, "/cwd", "")
		if len(got) != 1 || got[0] != "/cwd" {
			t.Errorf("got %v, want [/cwd]", got)
		}
	})
}

func TestCommandPathsExpandsHome(t *testing.T) {
	home := "/home/u"
	for _, tc := range []struct{ command, want string }{
		{"cat ~/.claude/skills/x/SKILL.md", "/home/u/.claude/skills/x/SKILL.md"},
		{"cat $HOME/.claude/skills/x/SKILL.md", "/home/u/.claude/skills/x/SKILL.md"},
		{`cat "${HOME}/.claude/skills/x/SKILL.md"`, "/home/u/.claude/skills/x/SKILL.md"},
		{"ls ~", "/home/u"},
	} {
		got := CommandPaths(tc.command, "/proj", home)
		if len(got) != 1 || got[0] != tc.want {
			t.Errorf("CommandPaths(%q) = %v, want [%s]", tc.command, got, tc.want)
		}
	}
	// "~user/..." is not expanded; it is a relative-looking token.
	if got := CommandPaths("cat ~other/x", "/proj", home); len(got) != 1 || got[0] != "/proj/~other/x" {
		t.Errorf("CommandPaths(~other/x) = %v", got)
	}
	// Tool path keys expand too.
	got := CandidatePaths(map[string]any{"file_path": "~/.claude/skills/x/SKILL.md"}, "/proj", home)
	found := false
	for _, p := range got {
		if p == NormalizePath("/home/u/.claude/skills/x/SKILL.md") {
			found = true
		}
	}
	if !found {
		t.Errorf("CandidatePaths did not expand ~ in file_path: %v", got)
	}
}

// symlinkedTempDir returns a path to a fresh temp directory that is reached
// through a symlink, reproducing macOS where t.TempDir() lives under
// /var -> /private/var. Tests must compare against resolved paths.
func symlinkedTempDir(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	return link
}
