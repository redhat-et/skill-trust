// Package claudecode provides Claude Code hook integration for skill-trust.
//
// This package maps Claude Code hook events onto skill-trust preflight
// decision logic, extracting candidate paths from tool inputs, discovering
// skill roots, managing verification state, and implementing the decision
// table specified in the Claude Code adapter contract.
package claudecode

import (
	"path/filepath"
	"regexp"
	"strings"
)

// NormalizePath returns the absolute, symlink-free path. When the path does
// not exist, the deepest existing ancestor is resolved and the remaining
// components are appended, preventing containment bypass through symlinked
// path prefixes.
func NormalizePath(p string) string {
	abs := p
	if !filepath.IsAbs(p) {
		var err error
		abs, err = filepath.Abs(p)
		if err != nil {
			return p
		}
	}

	// Clean the path first to handle // and ..
	abs = filepath.Clean(abs)

	// Try to resolve the full path
	resolved, err := filepath.EvalSymlinks(abs)
	if err == nil {
		return resolved
	}

	// Path doesn't exist; resolve deepest existing ancestor
	current := abs
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			// Found an existing ancestor; append the rest
			remaining := abs[len(current):]
			return filepath.Join(resolved, remaining)
		}

		parent := filepath.Dir(current)
		if parent == current {
			// Reached root without finding anything
			return abs
		}
		current = parent
	}
}

// expandHome expands a leading "~", "~/", "$HOME/" or "${HOME}/" to home.
// It returns the token unchanged when home is empty or there is no such
// prefix ("~user/..." is not expanded).
func expandHome(token, home string) string {
	if home == "" {
		return token
	}
	switch {
	case token == "~" || token == "$HOME" || token == "${HOME}":
		return home
	case strings.HasPrefix(token, "~/"):
		return filepath.Join(home, token[2:])
	case strings.HasPrefix(token, "$HOME/"):
		return filepath.Join(home, token[len("$HOME/"):])
	case strings.HasPrefix(token, "${HOME}/"):
		return filepath.Join(home, token[len("${HOME}/"):])
	}
	return token
}

// CommandPaths extracts candidate file paths from a shell command string.
// Best-effort and deliberately conservative: quoted or bare tokens that
// contain a path separator are resolved against cwd, after expanding a
// leading "~", "~/", "$HOME/" or "${HOME}/" to home.
func CommandPaths(command, cwd, home string) []string {
	// Token regex matching the TypeScript version
	tokenRegex := regexp.MustCompile(`(?:[^\s"'` + "`" + `]+|"[^"]*"|'[^']*')+`)
	tokens := tokenRegex.FindAllString(command, -1)

	out := []string{}
	for _, raw := range tokens {
		// Strip quotes
		token := strings.Trim(raw, "\"'`")

		// Strip trailing comma/semicolon
		token = strings.TrimRight(token, ",;")

		// Expand home before the variable/separator filters
		if token == "~" || token == "$HOME" || token == "${HOME}" {
			if home != "" {
				out = append(out, home)
			}
			continue
		}
		token = expandHome(token, home)

		// Skip empty, flags, variables
		if token == "" || strings.HasPrefix(token, "-") || strings.HasPrefix(token, "$") {
			continue
		}

		// Skip URLs and redirects
		if strings.HasPrefix(token, "http://") || strings.HasPrefix(token, "https://") {
			continue
		}
		if strings.HasPrefix(token, "<") || strings.HasPrefix(token, ">") || strings.HasPrefix(token, "|") {
			continue
		}

		// Must contain a path separator
		if !strings.Contains(token, "/") {
			continue
		}

		// Strip trailing redirection or background operators
		token = strings.TrimRight(token, "<>|&")

		// Recheck after stripping
		if !strings.Contains(token, "/") {
			continue
		}

		// Resolve path
		resolved := token
		if !filepath.IsAbs(token) {
			resolved = filepath.Join(cwd, token)
		}
		out = append(out, resolved)
	}

	return out
}

// Path and command keys for tool input extraction
var pathKeys = map[string]bool{
	"file_path":     true,
	"path":          true,
	"notebook_path": true,
	"filePath":      true,
	"directory":     true,
	"dir":           true,
	"workdir":       true,
	"cwd":           true,
	"folder":        true,
}

var commandKeys = map[string]bool{
	"command": true,
	"cmd":     true,
	"script":  true,
	"shell":   true,
}

// CandidatePaths recursively extracts candidate filesystem paths from tool
// input. Returns normalized, deduplicated paths. Non-map/non-slice input
// returns just [cwd]. A leading "~" or "$HOME" is expanded to home.
func CandidatePaths(toolInput any, cwd, home string) []string {
	seen := make(map[string]bool)
	var collect func(any)

	collect = func(input any) {
		switch v := input.(type) {
		case map[string]any:
			for key, val := range v {
				if s, ok := val.(string); ok && s != "" {
					if pathKeys[key] {
						resolved := expandHome(s, home)
						if !filepath.IsAbs(resolved) {
							resolved = filepath.Join(cwd, resolved)
						}
						seen[NormalizePath(resolved)] = true
					} else if commandKeys[key] {
						for _, p := range CommandPaths(s, cwd, home) {
							seen[NormalizePath(p)] = true
						}
					}
				}
				// Recurse into nested values
				collect(val)
			}
		case []any:
			for _, item := range v {
				collect(item)
			}
		}
	}

	collect(toolInput)

	// Always include cwd
	seen[NormalizePath(cwd)] = true

	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	return out
}
