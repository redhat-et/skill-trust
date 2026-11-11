package claudecode

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultLocations(t *testing.T) {
	cwd := "/proj/apps/web"
	loc := DefaultLocations(cwd)

	if loc.Home == "" {
		t.Error("Home should not be empty")
	}
	if loc.Cwd != cwd {
		t.Errorf("Cwd = %s, want %s", loc.Cwd, cwd)
	}
	if loc.PluginsDir == "" {
		t.Error("PluginsDir should not be empty")
	}
}

func TestDiscoverLocations(t *testing.T) {
	tmp := t.TempDir()

	// Create home/.claude/skills/demo
	homeSkills := filepath.Join(tmp, "home", ".claude", "skills")
	demoDir := filepath.Join(homeSkills, "demo")
	os.MkdirAll(demoDir, 0o755)
	os.WriteFile(filepath.Join(demoDir, "SKILL.md"), []byte("demo skill"), 0o644)

	// Create project/.claude/skills/proj-skill
	projectDir := filepath.Join(tmp, "project")
	projectSkills := filepath.Join(projectDir, ".claude", "skills", "proj-skill")
	os.MkdirAll(projectSkills, 0o755)
	os.WriteFile(filepath.Join(projectSkills, "SKILL.md"), []byte("project skill"), 0o644)

	// Create repo/.git
	repoDir := filepath.Join(tmp, "repo")
	os.MkdirAll(filepath.Join(repoDir, ".git"), 0o755)

	// Create repo/apps/.claude/skills/app-skill
	repoAppSkills := filepath.Join(repoDir, "apps", ".claude", "skills", "app-skill")
	os.MkdirAll(repoAppSkills, 0o755)
	os.WriteFile(filepath.Join(repoAppSkills, "SKILL.md"), []byte("app skill"), 0o644)

	// Create plugin via installed_plugins.json
	pluginsDir := filepath.Join(tmp, "plugins")
	cacheDir := filepath.Join(pluginsDir, "cache", "m", "p", "1.0", "skills", "s")
	os.MkdirAll(cacheDir, 0o755)
	os.WriteFile(filepath.Join(cacheDir, "SKILL.md"), []byte("plugin skill"), 0o644)

	pluginsJSON := filepath.Join(pluginsDir, "installed_plugins.json")
	installData := map[string]any{
		"version": 2,
		"plugins": map[string]any{
			"p@m": []map[string]any{
				{"installPath": filepath.Join(pluginsDir, "cache", "m", "p", "1.0")},
			},
		},
	}
	data, _ := json.Marshal(installData)
	os.WriteFile(pluginsJSON, data, 0o644)

	// Create a directory without SKILL.md (should be skipped)
	noSkillDir := filepath.Join(homeSkills, "no-skill")
	os.MkdirAll(noSkillDir, 0o755)

	loc := Locations{
		Home:       filepath.Join(tmp, "home"),
		Cwd:        filepath.Join(repoDir, "apps", "web"),
		ProjectDir: projectDir,
		PluginsDir: pluginsDir,
		Enterprise: []string{},
	}

	skills := loc.Discover()

	// Should find: demo, proj-skill, app-skill, p:s
	foundDemo := false
	foundProj := false
	foundApp := false
	foundPlugin := false

	for _, s := range skills {
		if s.Name == "demo" {
			foundDemo = true
		}
		if s.Name == "proj-skill" {
			foundProj = true
		}
		if s.Name == "app-skill" {
			foundApp = true
		}
		if s.Name == "p:s" {
			foundPlugin = true
		}
	}

	if !foundDemo {
		t.Error("Expected to find demo skill")
	}
	if !foundProj {
		t.Error("Expected to find proj-skill")
	}
	if !foundApp {
		t.Error("Expected to find app-skill")
	}
	if !foundPlugin {
		t.Error("Expected to find plugin skill p:s")
	}
}

func TestRootOfIgnoresStraySkillMD(t *testing.T) {
	tmp := t.TempDir()

	// Create repo/skills/demo/SKILL.md without .claude parent
	skillDir := filepath.Join(tmp, "repo", "skills", "demo")
	os.MkdirAll(skillDir, 0o755)
	os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("stray"), 0o644)

	loc := Locations{
		Home: tmp,
		Cwd:  tmp,
	}
	skills := loc.Discover()

	path := filepath.Join(skillDir, "SKILL.md")
	root, ok := loc.RootOf(path, skills)
	if ok {
		t.Errorf("RootOf(%q) = %q, want false (no .claude parent)", path, root)
	}
}

func TestRootOfNestedClaudeSkills(t *testing.T) {
	tmp := t.TempDir()

	// Create repo/apps/web/.claude/skills/deploy
	deployDir := filepath.Join(tmp, "repo", "apps", "web", ".claude", "skills", "deploy")
	os.MkdirAll(deployDir, 0o755)
	os.WriteFile(filepath.Join(deployDir, "SKILL.md"), []byte("deploy"), 0o644)

	scriptPath := filepath.Join(deployDir, "scripts", "x.sh")

	loc := Locations{
		Home: tmp,
		Cwd:  filepath.Join(tmp, "repo", "apps", "web"),
	}
	skills := loc.Discover()

	root, ok := loc.RootOf(scriptPath, skills)
	if !ok {
		t.Fatalf("RootOf(%q) returned false", scriptPath)
	}

	expectedRoot := NormalizePath(deployDir)
	if root != expectedRoot {
		t.Errorf("RootOf(%q) = %q, want %q", scriptPath, root, expectedRoot)
	}
}

func TestRootOfSymlinkedInstall(t *testing.T) {
	tmp := t.TempDir()

	// Create src/foo
	srcDir := filepath.Join(tmp, "src", "foo")
	os.MkdirAll(srcDir, 0o755)
	os.WriteFile(filepath.Join(srcDir, "SKILL.md"), []byte("foo"), 0o644)

	// Create home/.claude/skills/foo as symlink to src/foo
	homeSkills := filepath.Join(tmp, "home", ".claude", "skills")
	if err := os.MkdirAll(homeSkills, 0o755); err != nil {
		t.Fatal(err)
	}
	symlinkPath := filepath.Join(homeSkills, "foo")
	if err := os.Symlink(srcDir, symlinkPath); err != nil {
		t.Fatal(err)
	}

	loc := Locations{
		Home: filepath.Join(tmp, "home"),
		Cwd:  tmp,
	}
	skills := loc.Discover()

	// Both paths should map to the realpath of src/foo
	srcRealpath := NormalizePath(srcDir)

	root1, ok1 := loc.RootOf(filepath.Join(homeSkills, "foo", "SKILL.md"), skills)
	if !ok1 {
		t.Fatalf("RootOf via symlink returned false")
	}
	if root1 != srcRealpath {
		t.Errorf("RootOf via symlink = %q, want %q", root1, srcRealpath)
	}

	skillMDPath := filepath.Join(srcDir, "SKILL.md")
	root2, ok2 := loc.RootOf(skillMDPath, skills)
	if !ok2 {
		t.Fatalf("RootOf via real path returned false")
	}
	if root2 != srcRealpath {
		t.Errorf("RootOf via real path = %q, want %q", root2, srcRealpath)
	}
}

func TestRootOfPluginCacheBoundary(t *testing.T) {
	tmp := t.TempDir()

	// Create PluginsDir/cache-evil/.../skills/x (should NOT match)
	evilDir := filepath.Join(tmp, "plugins", "cache-evil", "m", "p", "1.0", "skills", "x")
	os.MkdirAll(evilDir, 0o755)
	os.WriteFile(filepath.Join(evilDir, "SKILL.md"), []byte("evil"), 0o644)

	loc := Locations{
		Home:       tmp,
		Cwd:        tmp,
		PluginsDir: filepath.Join(tmp, "plugins"),
	}

	path := filepath.Join(evilDir, "scripts", "test.sh")
	root, ok := loc.RootOf(path, nil)
	if ok {
		t.Errorf("RootOf(%q) should not match cache-evil, got %q", path, root)
	}
}

func TestResolveSkillNames(t *testing.T) {
	skills := []Skill{
		{Name: "deploy", Root: "/proj/.claude/skills/deploy"},
		{Name: "p:s", Root: "/plugins/p/skills/s"},
		{Name: "apps/web:deploy", Root: "/proj/apps/web/.claude/skills/deploy"},
	}

	tests := []struct {
		name      string
		input     string
		wantRoots []string
	}{
		{"ExactMatch", "deploy", []string{"/proj/.claude/skills/deploy"}},
		{"PluginMatch", "p:s", []string{"/plugins/p/skills/s"}},
		{"NestedMatch", "apps/web:deploy", []string{"/proj/apps/web/.claude/skills/deploy"}},
		{"UnknownSkill", "unknown", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRoots := ResolveSkillNames(tt.input, skills)
			if len(gotRoots) != len(tt.wantRoots) {
				t.Errorf("ResolveSkillNames(%q) returned %d roots, want %d", tt.input, len(gotRoots), len(tt.wantRoots))
			}
			for i, want := range tt.wantRoots {
				if i >= len(gotRoots) || gotRoots[i] != want {
					t.Errorf("ResolveSkillNames(%q) = %v, want %v", tt.input, gotRoots, tt.wantRoots)
					break
				}
			}
		})
	}

	// Test suffix match with exactly one candidate
	t.Run("SuffixMatchUnique", func(t *testing.T) {
		skillsSuffixOnly := []Skill{
			{Name: "apps/web:deploy", Root: "/proj/apps/web/.claude/skills/deploy"},
		}
		roots := ResolveSkillNames("deploy", skillsSuffixOnly)
		if len(roots) != 1 || roots[0] != "/proj/apps/web/.claude/skills/deploy" {
			t.Errorf("ResolveSkillNames(deploy) with suffix-only = %v, want one match", roots)
		}
	})

	// Test multiple exact matches (e.g., home and project both have "deploy")
	t.Run("MultipleExactMatches", func(t *testing.T) {
		multiSkills := []Skill{
			{Name: "deploy", Root: "/home/.claude/skills/deploy"},
			{Name: "deploy", Root: "/project/.claude/skills/deploy"},
		}
		roots := ResolveSkillNames("deploy", multiSkills)
		if len(roots) != 2 {
			t.Errorf("ResolveSkillNames(deploy) with duplicates returned %d roots, want 2", len(roots))
		}
		hasHome := false
		hasProject := false
		for _, r := range roots {
			if r == "/home/.claude/skills/deploy" {
				hasHome = true
			}
			if r == "/project/.claude/skills/deploy" {
				hasProject = true
			}
		}
		if !hasHome || !hasProject {
			t.Errorf("ResolveSkillNames(deploy) = %v, want both home and project", roots)
		}
	})

	// Ambiguous suffix match: every candidate is returned, not none.
	t.Run("SuffixMatchAmbiguous", func(t *testing.T) {
		ambiguous := []Skill{
			{Name: "a:deploy", Root: "/plugins/a/skills/deploy"},
			{Name: "b:deploy", Root: "/plugins/b/skills/deploy"},
		}
		roots := ResolveSkillNames("deploy", ambiguous)
		if len(roots) != 2 {
			t.Errorf("ResolveSkillNames(deploy) ambiguous = %v, want both roots", roots)
		}
	})
}

func TestResolveSkillDirectoryScoped(t *testing.T) {
	base := t.TempDir()
	project := filepath.Join(base, "project")
	nested := filepath.Join(project, "apps", "web", ".claude", "skills", "deploy")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "SKILL.md"), []byte("# x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A scoped directory without SKILL.md is not a skill.
	if err := os.MkdirAll(filepath.Join(project, "apps", "api", ".claude", "skills", "deploy"), 0o755); err != nil {
		t.Fatal(err)
	}
	other := []Skill{{Name: "deploy", Root: "/elsewhere/.claude/skills/deploy"}}
	want := NormalizePath(nested)

	for _, l := range []Locations{{Cwd: project}, {Cwd: "/nonexistent", ProjectDir: project}} {
		got := l.ResolveSkill("apps/web:deploy", other)
		if len(got) != 1 || got[0] != want {
			t.Errorf("ResolveSkill(apps/web:deploy) with %+v = %v, want [%s]", l, got, want)
		}
	}

	l := Locations{Cwd: project}
	for _, name := range []string{"apps/api:deploy", "../project/apps/web:deploy", "apps/../apps/web:deploy", project + "/apps/web:deploy", "apps/web:../deploy"} {
		for _, r := range l.ResolveSkill(name, nil) {
			if r == want {
				t.Errorf("ResolveSkill(%q) must not resolve the scoped directory, got %v", name, r)
			}
		}
	}
}
