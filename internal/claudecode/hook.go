package claudecode

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/redhat-et/skill-trust/pkg/preflight"
)

// HookInput is the JSON structure Claude Code sends to hooks.
type HookInput struct {
	SessionID      string `json:"session_id"`
	Cwd            string `json:"cwd"`
	HookEventName  string `json:"hook_event_name"`
	ToolName       string `json:"tool_name"`
	ToolInput      any    `json:"tool_input"`
	PermissionMode string `json:"permission_mode"`
	Source         string `json:"source"`
	Prompt         string `json:"prompt"`
}

// Config holds the configuration for hook execution.
type Config struct {
	Policy      string                                              // Path to the policy file
	Strict      bool                                                // Strict mode flag
	StateDir    string                                              // Directory for state files
	PluginRoot  string                                              // Plugin root directory (unused currently)
	CLIVersion  string                                              // CLI version string
	Locations   Locations                                           // Skill search locations
	Now         func() time.Time                                    // Time function (for testing)
	NewVerifier func(policyPath string) (preflight.Verifier, error) // Verifier constructor
	Stderr      io.Writer                                           // Where to write SaveState errors (nil = discard)
}

// verifierFailureOutcomes denies every root when the verifier cannot be
// constructed (missing or malformed policy, unavailable trust material).
// This is independent of strict mode: report-only allows skills that fail
// verification, but without a verifier nothing was verified at all, and the
// adapter never fails open on error. State is left untouched.
func verifierFailureOutcomes(roots []string, err error) decideOutcomes {
	var blocked []Outcome
	for _, root := range roots {
		blocked = append(blocked, Outcome{
			Root:    root,
			Allowed: false,
			Block: &preflight.BlockError{
				Code:    preflight.CodeVerifierFailure,
				Message: fmt.Sprintf("skill %s blocked: verifier unavailable: %v", root, err),
			},
		})
	}
	return decideOutcomes{blocked: blocked}
}

// newVerifier constructs the verifier for cfg, treating an empty policy
// path or a nil constructor as an error.
func newVerifier(cfg Config) (preflight.Verifier, error) {
	if cfg.Policy == "" {
		return nil, fmt.Errorf("policy not configured")
	}
	if cfg.NewVerifier == nil {
		return nil, fmt.Errorf("no verifier constructor configured")
	}
	v, err := cfg.NewVerifier(cfg.Policy)
	if err == nil && v == nil {
		err = fmt.Errorf("verifier constructor returned no verifier")
	}
	return v, err
}

// decideOrDeny constructs the verifier and decides roots, or denies all of
// them if the verifier cannot be constructed.
func decideOrDeny(cfg Config, roots []string, sessionID string) decideOutcomes {
	verifier, err := newVerifier(cfg)
	if err != nil {
		return verifierFailureOutcomes(roots, err)
	}
	return decideRoots(cfg, roots, sessionID, verifier)
}

// decideOutcomes holds the results of deciding multiple roots.
type decideOutcomes struct {
	blocked  []Outcome
	warnings []Outcome
}

// decideRoots runs Decide on each root, updates state, and classifies outcomes.
func decideRoots(cfg Config, roots []string, sessionID string, verifier preflight.Verifier) decideOutcomes {
	state := LoadState(cfg.StateDir, sessionID)

	now := time.Now()
	if cfg.Now != nil {
		now = cfg.Now()
	}

	var blocked, warnings []Outcome

	for _, root := range roots {
		prev, hasPrev := state[root]
		var prevPtr *Record
		if hasPrev {
			prevPtr = &prev
		}

		outcome, newRec := Decide(verifier, root, prevPtr, cfg.Strict, now)

		if !outcome.Allowed && outcome.Block != nil {
			blocked = append(blocked, outcome)
		} else if outcome.Allowed && outcome.Warning != "" {
			warnings = append(warnings, outcome)
		}

		// Update state if we got a new record
		if newRec != nil {
			state[root] = *newRec
		}
	}

	// Save updated state
	if err := SaveState(cfg.StateDir, sessionID, state); err != nil && cfg.Stderr != nil {
		fmt.Fprintf(cfg.Stderr, "skill-trust: saving state: %v\n", err)
	}

	return decideOutcomes{blocked: blocked, warnings: warnings}
}

// PreToolUse handles the PreToolUse hook event. Returns nil for allowed tools
// with no output, or JSON for denied/warning outcomes.
func PreToolUse(cfg Config, in HookInput) []byte {
	// Extract candidate paths from tool input
	candidates := CandidatePaths(in.ToolInput, in.Cwd, cfg.Locations.Home)

	// Discover all skills
	discovered := cfg.Locations.Discover()

	// For Skill tool, also resolve the skill name
	if in.ToolName == "Skill" {
		if m, ok := in.ToolInput.(map[string]any); ok {
			if skillName, ok := m["skill"].(string); ok && skillName != "" {
				candidates = append(candidates, cfg.Locations.ResolveSkill(skillName, discovered)...)
			}
		}
	}

	// Find skill roots for all candidates
	var skillRoots []string
	seen := make(map[string]bool)
	for _, candidate := range candidates {
		if root, found := cfg.Locations.RootOf(candidate, discovered); found && !seen[root] {
			skillRoots = append(skillRoots, root)
			seen[root] = true
		}
	}

	// If no skill roots, allow without constructing verifier
	if len(skillRoots) == 0 {
		return nil
	}

	// Construct verifier lazily; failure denies every skill root
	outcomes := decideOrDeny(cfg, skillRoots, in.SessionID)

	// If any blocked, return deny
	if len(outcomes.blocked) > 0 {
		return denyJSON(Reason(outcomes.blocked[0]))
	}

	// If any warnings (report-only mode), return warning
	if len(outcomes.warnings) > 0 {
		var parts []string
		for _, w := range outcomes.warnings {
			parts = append(parts, w.Warning)
		}
		return warningJSON(strings.Join(parts, "\n"))
	}

	// All allowed, no warnings
	return nil
}

// UserPromptSubmit handles the UserPromptSubmit hook event for slash commands.
func UserPromptSubmit(cfg Config, in HookInput) []byte {
	// Check if prompt starts with /
	trimmed := strings.TrimSpace(in.Prompt)
	if !strings.HasPrefix(trimmed, "/") {
		return nil
	}

	// Extract skill name (first token without the /)
	parts := strings.Fields(trimmed)
	if len(parts) == 0 {
		return nil
	}
	skillName := strings.TrimPrefix(parts[0], "/")

	// Discover all skills
	discovered := cfg.Locations.Discover()

	// Resolve skill name to roots
	roots := cfg.Locations.ResolveSkill(skillName, discovered)
	if len(roots) == 0 {
		// Unknown skill - allow
		return nil
	}

	// Construct verifier lazily; failure denies every skill root
	outcomes := decideOrDeny(cfg, roots, in.SessionID)

	// If any blocked, return block
	if len(outcomes.blocked) > 0 {
		return blockPromptJSON(Reason(outcomes.blocked[0]))
	}

	// If any warnings (report-only mode), return warning
	if len(outcomes.warnings) > 0 {
		var parts []string
		for _, w := range outcomes.warnings {
			parts = append(parts, w.Warning)
		}
		return warningPromptJSON(strings.Join(parts, "\n"))
	}

	// All allowed
	return nil
}

// SessionStart handles the SessionStart hook event. It discovers all skills,
// verifies each one, saves fresh state, prunes old state, and returns a system
// message summarizing the results.
func SessionStart(cfg Config, in HookInput) []byte {
	// Prune old state (>7 days)
	if cfg.Now != nil {
		PruneStates(cfg.StateDir, 7*24*time.Hour, cfg.Now())
	} else {
		PruneStates(cfg.StateDir, 7*24*time.Hour, time.Now())
	}

	// Discover all skills
	discovered := cfg.Locations.Discover()

	// Construct verifier. If it cannot be built, every skill is reported
	// blocked, matching what PreToolUse and UserPromptSubmit will do.
	verifier, verifierErr := newVerifier(cfg)

	now := time.Now()
	if cfg.Now != nil {
		now = cfg.Now()
	}

	// Verify all discovered skills (fresh baseline, no previous state).
	// verified: allowed without warning; unverified: allowed with a
	// report-only warning; blocked: denied.
	var verified, unverified int
	var blocked []struct {
		Skill
		Code string
	}

	newState := make(State)

	for _, skill := range discovered {
		if verifierErr != nil {
			blocked = append(blocked, struct {
				Skill
				Code string
			}{skill, string(preflight.CodeVerifierFailure)})
			continue
		}

		outcome, newRec := Decide(verifier, skill.Root, nil, cfg.Strict, now)

		switch {
		case outcome.Allowed && outcome.Warning != "":
			unverified++
		case outcome.Allowed:
			verified++
		case outcome.Block != nil:
			blocked = append(blocked, struct {
				Skill
				Code string
			}{skill, string(outcome.Block.Code)})
		}

		// Save the new record
		if newRec != nil {
			newState[skill.Root] = *newRec
		}
	}

	// Save fresh state (always, even for zero skills - re-baseline)
	if err := SaveState(cfg.StateDir, in.SessionID, newState); err != nil && cfg.Stderr != nil {
		fmt.Fprintf(cfg.Stderr, "skill-trust: saving state: %v\n", err)
	}

	// Build system message: "N skills verified, M blocked", plus
	// "K unverified (report-only)" when report-only allowed K skills that
	// did not verify.
	var msgParts []string
	msgParts = append(msgParts, fmt.Sprintf("skill-trust: %d skills verified, %d blocked",
		verified, len(blocked)))
	if unverified > 0 {
		msgParts = append(msgParts, fmt.Sprintf(", %d unverified (report-only)", unverified))
	}

	if len(blocked) > 0 {
		var names []string
		for _, b := range blocked {
			names = append(names, fmt.Sprintf("%s: %s", b.Name, b.Code))
		}
		msgParts = append(msgParts, fmt.Sprintf(" (%s)", strings.Join(names, ", ")))
	}

	// Add version warning if CLI and plugin versions differ
	if warning := versionWarning(cfg); warning != "" {
		msgParts = append(msgParts, "; "+warning)
	}

	if verifierErr != nil {
		msgParts = append(msgParts, fmt.Sprintf("; %v", verifierErr))
	}

	systemMessage := strings.Join(msgParts, "")

	// Build additional context for blocked skills
	var additionalContext string
	if len(blocked) > 0 {
		var lines []string
		lines = append(lines, "The following skills are blocked and should not be used:")
		for _, b := range blocked {
			lines = append(lines, fmt.Sprintf("  - %s (%s)", b.Name, b.Code))
		}
		additionalContext = strings.Join(lines, "\n")
	}

	return sessionStartJSON(systemMessage, additionalContext)
}

// Helper functions for JSON output

func denyJSON(reason string) []byte {
	out := map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       "deny",
			"permissionDecisionReason": reason,
		},
	}
	data, _ := json.Marshal(out)
	return data
}

func warningJSON(context string) []byte {
	out := map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":     "PreToolUse",
			"additionalContext": context,
		},
	}
	data, _ := json.Marshal(out)
	return data
}

func blockPromptJSON(reason string) []byte {
	out := map[string]any{
		"decision": "block",
		"reason":   reason,
	}
	data, _ := json.Marshal(out)
	return data
}

func warningPromptJSON(context string) []byte {
	out := map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":     "UserPromptSubmit",
			"additionalContext": context,
		},
	}
	data, _ := json.Marshal(out)
	return data
}

func sessionStartJSON(systemMessage, additionalContext string) []byte {
	out := map[string]any{
		"systemMessage": systemMessage,
		"hookSpecificOutput": map[string]any{
			"hookEventName": "SessionStart",
		},
	}
	if additionalContext != "" {
		out["hookSpecificOutput"].(map[string]any)["additionalContext"] = additionalContext
	}
	data, _ := json.Marshal(out)
	return data
}
