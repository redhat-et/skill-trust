package claudecode

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// Locations holds the search paths for skill discovery.
type Locations struct {
	Home       string   // User home directory
	Cwd        string   // Current working directory
	ProjectDir string   // CLAUDE_PROJECT_DIR
	PluginsDir string   // ~/.claude/plugins
	Enterprise []string // Platform-specific enterprise locations
}

// DefaultLocations returns the standard skill search locations.
func DefaultLocations(cwd string) Locations {
	home, _ := os.UserHomeDir()
	pluginsDir := filepath.Join(home, ".claude", "plugins")
	projectDir := os.Getenv("CLAUDE_PROJECT_DIR")

	var enterprise []string
	switch runtime.GOOS {
	case "linux":
		enterprise = []string{"/etc/claude-code/.claude/skills"}
	case "darwin":
		enterprise = []string{"/Library/Application Support/ClaudeCode/.claude/skills"}
	}

	return Locations{
		Home:       home,
		Cwd:        cwd,
		ProjectDir: projectDir,
		PluginsDir: pluginsDir,
		Enterprise: enterprise,
	}
}

// Skill represents one discovered skill.
type Skill struct {
	Name string // Skill name (plugin skills are "plugin:skill")
	Root string // Absolute, normalized skill root
}

// Discover finds all skills in the configured locations.
func (l Locations) Discover() []Skill {
	var skills []Skill
	seen := make(map[string]bool)

	// Helper to add a skill if it has SKILL.md and hasn't been seen
	addSkill := func(name, root string) {
		// Check if root is a directory (follows symlinks)
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			return
		}

		normalized := NormalizePath(root)
		if seen[normalized] {
			return
		}
		skillMD := filepath.Join(root, "SKILL.md")
		if _, err := os.Stat(skillMD); err == nil {
			skills = append(skills, Skill{Name: name, Root: normalized})
			seen[normalized] = true
		}
	}

	// Home/.claude/skills and Home/.claude/skills/synced
	homeSkills := filepath.Join(l.Home, ".claude", "skills")
	if entries, err := os.ReadDir(homeSkills); err == nil {
		for _, e := range entries {
			// addSkill will check if it's a directory (following symlinks)
			addSkill(e.Name(), filepath.Join(homeSkills, e.Name()))
		}
	}
	homeSynced := filepath.Join(homeSkills, "synced")
	if entries, err := os.ReadDir(homeSynced); err == nil {
		for _, e := range entries {
			addSkill(e.Name(), filepath.Join(homeSynced, e.Name()))
		}
	}

	// Project/.claude/skills
	if l.ProjectDir != "" {
		projectSkills := filepath.Join(l.ProjectDir, ".claude", "skills")
		if entries, err := os.ReadDir(projectSkills); err == nil {
			for _, e := range entries {
				addSkill(e.Name(), filepath.Join(projectSkills, e.Name()))
			}
		}
	}

	// Cwd and ancestors up to .git (inclusive)
	current := l.Cwd
	for {
		claudeSkills := filepath.Join(current, ".claude", "skills")
		if entries, err := os.ReadDir(claudeSkills); err == nil {
			for _, e := range entries {
				addSkill(e.Name(), filepath.Join(claudeSkills, e.Name()))
			}
		}

		// Check if we're at .git (inclusive means we process this dir, then stop)
		hasGit := false
		if _, err := os.Stat(filepath.Join(current, ".git")); err == nil {
			hasGit = true
		}

		parent := filepath.Dir(current)
		if parent == current || hasGit {
			break
		}

		current = parent
	}

	// Enterprise directories
	for _, entDir := range l.Enterprise {
		if entries, err := os.ReadDir(entDir); err == nil {
			for _, e := range entries {
				addSkill(e.Name(), filepath.Join(entDir, e.Name()))
			}
		}
	}

	// Plugin skills from installed_plugins.json (deterministic order)
	pluginsJSON := filepath.Join(l.PluginsDir, "installed_plugins.json")
	if data, err := os.ReadFile(pluginsJSON); err == nil {
		var installed struct {
			Plugins map[string][]struct {
				InstallPath string `json:"installPath"`
			} `json:"plugins"`
		}
		if err := json.Unmarshal(data, &installed); err == nil {
			// Sort plugin keys for deterministic order
			var pluginKeys []string
			for key := range installed.Plugins {
				pluginKeys = append(pluginKeys, key)
			}
			sort.Strings(pluginKeys)

			for _, pluginKey := range pluginKeys {
				installs := installed.Plugins[pluginKey]
				// Extract plugin name (before @)
				pluginName := pluginKey
				if idx := strings.Index(pluginKey, "@"); idx > 0 {
					pluginName = pluginKey[:idx]
				}

				for _, inst := range installs {
					skillsDir := filepath.Join(inst.InstallPath, "skills")
					if entries, err := os.ReadDir(skillsDir); err == nil {
						for _, e := range entries {
							name := pluginName + ":" + e.Name()
							addSkill(name, filepath.Join(skillsDir, e.Name()))
						}
					}
				}
			}
		}
	}

	return skills
}

// RootOf returns the skill root containing the given path. First checks
// discovered skills for the longest match, then walks ancestry for
// SKILL.md in valid skill locations.
func (l Locations) RootOf(path string, discovered []Skill) (string, bool) {
	normalized := NormalizePath(path)

	// First: longest discovered root containing the path
	var best string
	for _, s := range discovered {
		if normalized == s.Root || strings.HasPrefix(normalized, s.Root+string(filepath.Separator)) {
			if len(s.Root) > len(best) {
				best = s.Root
			}
		}
	}
	if best != "" {
		return best, true
	}

	// Second: ancestry walk on the **unresolved** absolute path
	abs := path
	if !filepath.IsAbs(path) {
		abs, _ = filepath.Abs(path)
	}
	abs = filepath.Clean(abs)

	current := abs
	for {
		// Check if this directory has SKILL.md
		skillMD := filepath.Join(current, "SKILL.md")
		if _, err := os.Stat(skillMD); err == nil {
			// Verify it's in a valid location
			parent := filepath.Dir(current)
			parentName := filepath.Base(parent)

			// Must be in a "skills" directory under ".claude"
			if parentName == "skills" {
				grandparent := filepath.Dir(parent)
				grandparentName := filepath.Base(grandparent)

				if grandparentName == ".claude" {
					return NormalizePath(current), true
				}

				// Or under PluginsDir/cache (check separator boundary)
				cacheDir := filepath.Join(l.PluginsDir, "cache")
				if grandparent == cacheDir || strings.HasPrefix(grandparent, cacheDir+string(filepath.Separator)) {
					return NormalizePath(current), true
				}
			}

			// Or directly in an Enterprise directory
			for _, entDir := range l.Enterprise {
				if parent == entDir {
					return NormalizePath(current), true
				}
			}
		}

		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}

	return "", false
}

// ResolveSkillNames resolves a skill name to all matching roots. Returns
// every root whose Name matches exactly; if none, every root whose name's
// segment after the last ':' equals name's segment after its last ':'. An
// ambiguous name therefore checks all candidates instead of none.
func ResolveSkillNames(name string, discovered []Skill) []string {
	// Exact matches first
	var exactMatches []string
	for _, s := range discovered {
		if s.Name == name {
			exactMatches = append(exactMatches, s.Root)
		}
	}
	if len(exactMatches) > 0 {
		return exactMatches
	}

	// Suffix match on the segment after the last colon
	suffix := name
	if idx := strings.LastIndex(name, ":"); idx >= 0 {
		suffix = name[idx+1:]
	}

	var matches []string
	for _, s := range discovered {
		skillSuffix := s.Name
		if idx := strings.LastIndex(s.Name, ":"); idx >= 0 {
			skillSuffix = s.Name[idx+1:]
		}
		if skillSuffix == suffix {
			matches = append(matches, s.Root)
		}
	}

	return matches
}

// ResolveSkill resolves a Skill tool or slash-command name to skill roots.
// In addition to ResolveSkillNames over discovered skills, a
// directory-scoped name "<prefix>:<skill>" whose prefix contains '/' (for
// example "apps/web:deploy") is looked up as
// <cwd>/<prefix>/.claude/skills/<skill> and
// $CLAUDE_PROJECT_DIR/<prefix>/.claude/skills/<skill>; those directories
// are not found by discovery, which only walks up from cwd. When a scoped
// directory exists it is returned together with exact name matches, and
// suffix matching is not used.
func (l Locations) ResolveSkill(name string, discovered []Skill) []string {
	scoped := l.scopedSkillRoots(name)
	if len(scoped) == 0 {
		return ResolveSkillNames(name, discovered)
	}

	seen := make(map[string]bool)
	var out []string
	add := func(root string) {
		if !seen[root] {
			seen[root] = true
			out = append(out, root)
		}
	}
	for _, root := range scoped {
		add(root)
	}
	for _, s := range discovered {
		if s.Name == name {
			add(s.Root)
		}
	}
	return out
}

// scopedSkillRoots returns the existing skill roots for a directory-scoped
// name, or nil if the name is not directory-scoped or is unsafe (absolute
// prefix, ".." components, path separators in the skill segment).
func (l Locations) scopedSkillRoots(name string) []string {
	idx := strings.LastIndex(name, ":")
	if idx <= 0 {
		return nil
	}
	prefix, skill := name[:idx], name[idx+1:]
	if !strings.Contains(prefix, "/") || skill == "" || skill == "." || skill == ".." ||
		strings.ContainsAny(skill, `/\`) {
		return nil
	}
	if strings.HasPrefix(prefix, "/") || filepath.IsAbs(prefix) || filepath.VolumeName(prefix) != "" {
		return nil
	}
	for _, part := range strings.Split(strings.ReplaceAll(prefix, `\`, "/"), "/") {
		if part == ".." {
			return nil
		}
	}

	var out []string
	seen := make(map[string]bool)
	for _, base := range []string{l.Cwd, l.ProjectDir} {
		if base == "" {
			continue
		}
		root := filepath.Join(base, filepath.FromSlash(prefix), ".claude", "skills", skill)
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, "SKILL.md")); err != nil {
			continue
		}
		normalized := NormalizePath(root)
		if !seen[normalized] {
			seen[normalized] = true
			out = append(out, normalized)
		}
	}
	return out
}
