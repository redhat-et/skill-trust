package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/redhat-et/skill-trust/internal/claudecode"
	"github.com/redhat-et/skill-trust/pkg/preflight"
	"github.com/redhat-et/skill-trust/pkg/verify"
	"github.com/spf13/cobra"
)

var (
	hookPolicyPath string
	hookStrict     bool
)

var hookCmd = &cobra.Command{
	Use:   "hook",
	Short: "Claude Code hook integration",
	Long: `Hook commands integrate skill-trust into Claude Code's hook system.
These commands are not meant to be invoked directly by users.`,
}

var hookClaudeCodeCmd = &cobra.Command{
	Use:   "claude-code",
	Short: "Claude Code hook adapter",
	Long: `Claude Code hook adapter commands.
Reads JSON input from stdin and writes JSON output to stdout.`,
}

var sessionStartCmd = &cobra.Command{
	Use:   "session-start",
	Short: "Handle SessionStart hook event",
	Run: func(cmd *cobra.Command, args []string) {
		runHookEvent(cmd, "SessionStart")
	},
}

var preToolUseCmd = &cobra.Command{
	Use:   "pre-tool-use",
	Short: "Handle PreToolUse hook event",
	Run: func(cmd *cobra.Command, args []string) {
		runHookEvent(cmd, "PreToolUse")
	},
}

var userPromptSubmitCmd = &cobra.Command{
	Use:   "user-prompt-submit",
	Short: "Handle UserPromptSubmit hook event",
	Run: func(cmd *cobra.Command, args []string) {
		runHookEvent(cmd, "UserPromptSubmit")
	},
}

func init() {
	// Add hook command tree
	rootCmd.AddCommand(hookCmd)
	hookCmd.AddCommand(hookClaudeCodeCmd)
	hookClaudeCodeCmd.AddCommand(sessionStartCmd)
	hookClaudeCodeCmd.AddCommand(preToolUseCmd)
	hookClaudeCodeCmd.AddCommand(userPromptSubmitCmd)

	// Add flags to all hook commands
	for _, cmd := range []*cobra.Command{sessionStartCmd, preToolUseCmd, userPromptSubmitCmd} {
		cmd.Flags().StringVar(&hookPolicyPath, "policy", "", "path to organization policy file")
		cmd.Flags().BoolVar(&hookStrict, "strict", getStrictDefault(), "strict mode (deny unsigned/unverified skills)")
	}
}

func getStrictDefault() bool {
	env := os.Getenv("CLAUDE_PLUGIN_OPTION_STRICT")
	if env == "" {
		return true
	}
	strict, err := strconv.ParseBool(env)
	if err != nil {
		return true // Invalid value defaults to strict
	}
	return strict
}

// runHookEvent handles one hook invocation. The event is fixed by the
// subcommand, never by stdin: hook_event_name may be absent, but if present
// it must agree. Unparseable or non-object input and a mismatched event are
// blocking errors (exit 2, message on stderr).
func runHookEvent(cmd *cobra.Command, event string) {
	input, err := io.ReadAll(cmd.InOrStdin())
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "skill-trust: reading stdin: %v\n", err)
		exitCode = ExitError
		return
	}

	// Require a JSON object; "null", arrays, strings and numbers are
	// rejected (json.Unmarshal of "null" into a struct would succeed).
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(input, &raw); err != nil || raw == nil {
		if err == nil {
			err = fmt.Errorf("expected a JSON object")
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "skill-trust: invalid JSON input: %v\n", err)
		exitCode = ExitError
		return
	}

	var hookInput claudecode.HookInput
	if err := json.Unmarshal(input, &hookInput); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "skill-trust: invalid JSON input: %v\n", err)
		exitCode = ExitError
		return
	}

	if hookInput.HookEventName != "" && hookInput.HookEventName != event {
		fmt.Fprintf(cmd.ErrOrStderr(), "skill-trust: hook_event_name %q does not match subcommand event %q\n",
			hookInput.HookEventName, event)
		exitCode = ExitError
		return
	}
	hookInput.HookEventName = event

	cfg := buildConfig(hookInput.Cwd, cmd.ErrOrStderr())

	var result []byte
	switch event {
	case "SessionStart":
		result = claudecode.SessionStart(cfg, hookInput)
	case "PreToolUse":
		result = claudecode.PreToolUse(cfg, hookInput)
	case "UserPromptSubmit":
		result = claudecode.UserPromptSubmit(cfg, hookInput)
	}

	if result != nil {
		cmd.OutOrStdout().Write(result)
		cmd.OutOrStdout().Write([]byte("\n"))
	}
}

func buildConfig(cwd string, stderr io.Writer) claudecode.Config {
	// Policy path: flag > env > empty
	policyPath := hookPolicyPath
	if policyPath == "" {
		policyPath = os.Getenv("CLAUDE_PLUGIN_OPTION_POLICY")
	}

	// Resolve policy path - make absolute if relative
	if policyPath != "" && !filepath.IsAbs(policyPath) {
		if abs, err := filepath.Abs(policyPath); err == nil {
			policyPath = abs
		}
	}

	return claudecode.Config{
		Policy:     policyPath,
		Strict:     hookStrict,
		StateDir:   claudecode.StateDir(),
		PluginRoot: os.Getenv("CLAUDE_PLUGIN_ROOT"),
		CLIVersion: Version().Version,
		Locations:  claudecode.DefaultLocations(cwd),
		Stderr:     stderr,
		NewVerifier: func(path string) (preflight.Verifier, error) {
			if path == "" {
				return nil, fmt.Errorf("policy path not configured")
			}

			// Read policy JSON and resolve relative paths BEFORE parsing
			// (ParsePolicy loads public keys, so paths must be absolute first)
			policyData, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("reading policy: %w", err)
			}

			// Parse as generic JSON to mutate paths
			var policyJSON map[string]any
			if err := json.Unmarshal(policyData, &policyJSON); err != nil {
				return nil, fmt.Errorf("parsing policy JSON: %w", err)
			}

			// Resolve relative paths in signers
			policyDir := filepath.Dir(path)
			if signers, ok := policyJSON["signers"].([]any); ok {
				for _, signer := range signers {
					if s, ok := signer.(map[string]any); ok {
						if pubKey, ok := s["publicKey"].(map[string]any); ok {
							if keyPath, ok := pubKey["path"].(string); ok && keyPath != "" && !filepath.IsAbs(keyPath) {
								pubKey["path"] = filepath.Join(policyDir, keyPath)
							}
						}
					}
				}
			}

			// Resolve relative paths in trustRoots
			if trustRoots, ok := policyJSON["trustRoots"].(map[string]any); ok {
				for name, root := range trustRoots {
					if r, ok := root.(map[string]any); ok {
						if rootPath, ok := r["path"].(string); ok && rootPath != "" && !filepath.IsAbs(rootPath) {
							r["path"] = filepath.Join(policyDir, rootPath)
							trustRoots[name] = r
						}
					}
				}
			}

			// Re-marshal and parse with verify.ParsePolicy
			modifiedData, err := json.Marshal(policyJSON)
			if err != nil {
				return nil, fmt.Errorf("marshaling modified policy: %w", err)
			}

			p, err := verify.ParsePolicy(modifiedData)
			if err != nil {
				return nil, err
			}

			v, err := verify.New(p)
			if err != nil {
				return nil, err
			}
			return v.PreflightVerifier(), nil
		},
	}
}
