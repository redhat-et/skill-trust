# skill-trust adapter for Claude Code

This adapter enforces signed agent skills inside
[Claude Code](https://claude.com/claude-code). It follows the harness contract from
[`pkg/preflight`](../../pkg/preflight): verify a skill **before** its
instructions are loaded, and **re-verify before any tool executes or reads a
skill file**. The adapter never reimplements manifest or signature logic —
every trust decision comes from the `skill-trust` binary (the CLI surface of
this repository's Go library), invoked as hook commands.

## What it enforces

| Surface | Mechanism | Effect |
|---------|-----------|--------|
| Skill loading | `SessionStart` hook discovers and verifies all skills; Claude is told which are blocked | Claude sees blocked skill names but is instructed not to use them |
| Tool execution | `PreToolUse` hook on all tools re-verifies skill roots before any tool touching a skill file runs | Tool calls touching skill files are blocked before they execute |
| Shell execution | `PreToolUse` hook on `Bash`/`PowerShell` extracts paths from commands (best-effort, see Limitations) | Commands that reference a skill file (or run from inside a skill directory) are checked; modified scripts are blocked before the interpreter starts |
| Slash commands | `UserPromptSubmit` hook blocks `/skill-name` for blocked skills | Typing `/blocked-skill` is denied before the Skill tool runs |
| Drift after load | Every guarded call re-verifies from scratch; session state detects digest changes | Skills modified mid-session are blocked on next use |

Fail-closed is the default: unsigned skills (in strict mode), verifier failures, and stale
digests all block. A missing or unreadable policy blocks every skill in both
modes. Script enforcement is path-containment based — any file
under a verified skill root is guarded — so it covers every helper runtime
(Bash, Python, JavaScript, ...) without parsing per-language command syntax.

On every decision the adapter emits the **expected** (signed) and
**observed** (recomputed) content digests in the deny reason Claude sees:

```text
[ST-PREFLIGHT-CHANGED-AFTER-VERIFY] skill /home/user/.claude/skills/my-skill changed after it was verified
root: /home/user/.claude/skills/my-skill
expected digest 8dd3d110ca16b82c65cf028fc037fec6615f435265b5601a54cf13df2690234a
observed digest e08da135bf1e2d3c4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f
```

## Install

### Via Claude Code marketplace

1. Add the marketplace:
   ```console
   /plugin marketplace add redhat-et/skill-trust
   ```

2. Install the plugin (the marketplace name from [`.claude-plugin/marketplace.json`](../../.claude-plugin/marketplace.json)):
   ```console
   /plugin install skill-trust@skill-trust
   ```

3. Install the matching CLI binary:
   ```console
   go install github.com/redhat-et/skill-trust/cmd/skill-trust@v0.2.0
   ```

4. Configure the policy path (see options below):
   ```console
   /plugin configure skill-trust
   ```
   Set the `policy` field to the **absolute** path of your trust policy JSON,
   for example `/home/you/trust/skills.json`. A relative path (or `~`) is
   resolved against the working directory of the hook process, which changes
   with the project you open; the hook then cannot find the policy and blocks
   every skill.

### Via local directory (development)

1. Clone this repository and install the binary:
   ```console
   git clone https://github.com/redhat-et/skill-trust.git
   cd skill-trust
   go install ./cmd/skill-trust
   ```

2. Install the plugin from the local directory:
   ```console
   /plugin install /path/to/skill-trust/adapters/claude-code
   ```

3. Configure the policy path as above.

For a session-only trial without installing anything, load the plugin with
`--plugin-dir` and pass the options as environment variables (Claude Code
hands them to the hook processes unchanged):

```console
$ CLAUDE_PLUGIN_OPTION_POLICY=/home/you/trust/skills.json \
    claude --plugin-dir /path/to/skill-trust/adapters/claude-code
```

## Options

| Option | Default | Meaning |
|--------|---------|---------|
| `policy` | (required) | Path to the skill-trust policy JSON ([docs/POLICY.md](../../docs/POLICY.md)). Use an absolute path: a relative path is resolved against the hook process's working directory. Relative paths *inside* the policy (public keys, trust roots) are resolved against the policy file's directory. If the policy is missing or malformed, every skill is blocked regardless of `strict`. |
| `binary` | `skill-trust` | skill-trust binary path. The binary must be on `PATH` or this must be an absolute path. |
| `strict` | `true` | Fail closed: every skill that does not verify (unsigned, tampered, or not satisfying the policy) is blocked. With `false` (report-only adoption), any skill that does not verify is allowed with a warning, and only skills that verified earlier in the session are guarded (they are blocked if they change). A missing or malformed policy still blocks every skill. |

## Decision table

Every guarded call runs full verification of the skill root. With `R` = the
session-state record for the root (stored in
`$CLAUDE_PLUGIN_DATA/sessions/state-<session_id>.json`, with unsafe characters
in the session id replaced):

| Verification now | Record `R` | strict=true | strict=false |
|---|---|---|---|
| allow | none or blocked | allow, record digest | allow, record digest |
| allow | allowed, same digest | allow | allow |
| allow | allowed, different digest | **block** `ST-PREFLIGHT-CHANGED-AFTER-VERIFY` | **block** `ST-PREFLIGHT-CHANGED-AFTER-VERIFY` |
| block | allowed | **block** `ST-PREFLIGHT-CHANGED-AFTER-VERIFY` | **block** `ST-PREFLIGHT-CHANGED-AFTER-VERIFY` |
| block | none or blocked | **block** `ST-PREFLIGHT-NOT-VERIFIED` (unsigned) or `ST-PREFLIGHT-VERIFIER-FAILURE` (signed, findings attached) | allow with warning |

**Blocks are sticky for the session**: a change-after-verify deny never
overwrites the recorded digest, so "swap content, take one deny, retry" does
not work. The recorded digest is re-baselined only by a new session
(`SessionStart` on startup, `/clear`, resume, compact). A root that was
blocked earlier but now verifies is admitted and recorded (self-healing).

Removing `.skill-trust/` from a skill that verified earlier is a
change-after-verify block in both modes.

If the verifier cannot be built (policy missing, unreadable, or malformed, or
its trust material unavailable), every skill is blocked with
`ST-PREFLIGHT-VERIFIER-FAILURE` in both modes; report-only never turns a
broken policy into an allow.

## How guarding works

1. **SessionStart** (on startup, `/clear`, resume, compact): discover all skill
   roots from standard locations (see "Skill locations"), verify each, record
   allowed digests in session state, report summary to the user and blocked
   skills to Claude. Check CLI/plugin version lockstep and warn on mismatch.
   The summary reads `skill-trust: N skills verified, M blocked (name: CODE, ...)`;
   in report-only mode, skills allowed despite not verifying are counted
   separately: `skill-trust: N skills verified, M blocked, K unverified (report-only)`.
2. **PreToolUse** (before every tool executes): extract candidate paths from
   `tool_input` (explicit path fields like `file_path`/`path`/`cwd`/`directory`,
   tokens from `Bash`/`PowerShell` commands that look like paths, the hook's
   `cwd`; a leading `~/` or `$HOME/` is expanded). For the `Skill` tool,
   resolve the `skill` name to root(s): exact name matches, otherwise every
   skill with the same name after the last `:`; directory-scoped names such as
   `apps/web:deploy` are also looked up under
   `<cwd>/apps/web/.claude/skills/deploy` and
   `$CLAUDE_PROJECT_DIR/apps/web/.claude/skills/deploy`. Find skill
   roots containing each candidate (longest discovered root first, then
   ancestry walk for `SKILL.md` in valid locations). For every distinct root,
   re-verify; block if unsigned (strict mode), if verification fails, or if
   digest changed since session start.
3. **UserPromptSubmit** (when user types a prompt): if the prompt starts with
   `/skill-name`, resolve the name and verify the skill; block if it does not
   verify or if its digest changed.

**Path resolution and attribution.**
- All paths are resolved to absolute, symlink-free form before comparison (same
  rule as `pkg/preflight`).
- Shell command path extraction is best-effort: paths referenced only through
  shell variables, or relative to a `cd` inside the command, cannot be
  attributed statically. Explicit tool path inputs and commands referencing
  skill files directly by path are covered, and guarding the working directory
  catches helpers run from inside a skill directory.
- Only paths **inside** a skill root trigger verification. A tool call on a
  parent directory (`Grep` with `path: ~/.claude`, `cat ~/.claude/skills/*/SKILL.md`)
  is not attributed to the skills below it.

**Relative paths in the policy.** When the hook loads the policy JSON, relative
paths inside `policy` (for example, `signers[].publicKey.path` or
`trustRoots[name].path`) are resolved **against the policy file's directory**.
This is different from `skill-trust verify`, which resolves them against the
process working directory. The policy file is the anchor for its own trust
material.

**Skill locations.** A directory is treated as a skill root only if it contains
`SKILL.md` **and** sits in a skill location:
- `~/.claude/skills/` (including `~/.claude/skills/synced/`)
- `.claude/skills/` in `cwd` and each parent up to the git repository root
- `$CLAUDE_PROJECT_DIR/.claude/skills/` if set
- Enterprise managed directory (`/etc/claude-code/.claude/skills` on Linux,
  `/Library/Application Support/ClaudeCode/.claude/skills` on macOS)
- `skills/` of each installed plugin (from `~/.claude/plugins/installed_plugins.json`)

A `SKILL.md` outside these locations (for example, `skills/demo-skill` in this
repository, or a cloned repo with `SKILL.md` at its top) is not a skill root
and is not guarded — matching OpenCode, which guards only roots the harness
discovered.

## Version lockstep

The plugin and the CLI carry the same version number (currently `0.2.0`). At
`SessionStart` the hook compares the CLI version (from the binary itself) with
the plugin version (from `.claude-plugin/plugin.json`) and warns when they
differ:

- CLI older than plugin: `skill-trust CLI vX is older than the Claude Code plugin (vY); update with go install ...@vY`
- CLI newer than plugin: warns to update the plugin
- CLI reports `devel`: warns that the version is unknown

Warnings never block enforcement. The comparison uses `major.minor.patch` only.

## Policy examples

Three ready-to-adapt policies ship in [`examples/`](examples/):

- [`policy-trusted-key.json`](examples/policy-trusted-key.json) — a single
  trusted release key. Simplest setup; works fully offline.
- [`policy-sigstore-public.json`](examples/policy-sigstore-public.json) —
  keyless signing by a GitHub Actions workflow, verified against the public
  Sigstore good instance (Fulcio, Rekor, TSA).
- [`policy-rhtas.json`](examples/policy-rhtas.json) — the same workflow
  identity plus a key-based signer, verified against a private
  [RHTAS](https://docs.redhat.com/en/documentation/red_hat_trusted_artifact_signer)
  trusted root. RHTAS is selected purely via the trusted-root JSON — the
  skill format and adapter do not change.

Sign skills in CI with `skill-trust sign` (see
[`examples/key-based-signing.md`](../../examples/key-based-signing.md) and
the repository's `e2e-sign` workflow for a complete live example).

## Limitations

- **Blocked skills still appear in the listing.** Claude Code has no hook to
  remove a skill from the visible list. The adapter blocks loading and
  execution, and tells Claude which skills are blocked, but their names and
  descriptions remain visible.
- **Typing `/skill-name` is blocked.** The `UserPromptSubmit` hook detects and
  blocks prompts starting with `/<blocked-skill>`. Slash commands do **not** go
  through the `Skill` tool, so `PreToolUse` alone would not catch them.
- **Shell path extraction is best-effort.** Paths referenced only through shell
  variables other than a leading `$HOME` (`$HELPER`), globs, or relative to a
  `cd` inside a command, cannot be
  attributed statically. Explicit tool path inputs and commands referencing
  skill files directly by path are covered, and guarding the working directory
  catches helpers run from inside a skill directory.
- **Only paths inside a skill root trigger verification.** A tool call on a
  parent directory (`Grep` with `path: ~/.claude`, `cat ~/.claude/skills/*/SKILL.md`)
  is not attributed to the skills below it — same as OpenCode.
- **Writes into a skill are not denied up front.** A tool call writing to a
  skill file (`Edit`, `Write`) is checked like any other access (the skill must
  verify at that moment) but is not denied before it runs. The modified skill
  is then blocked on its next use. Same as OpenCode.
- **PreToolUse denies are honored even in bypass-permissions mode.** A blocked
  skill is denied regardless of the permission mode (verified with Claude Code
  2.1.322).
- **Skills the adapter cannot find are allowed.** A `Skill` tool name or
  `/name` prompt that resolves to no directory is allowed, because built-in and
  bundled skills have no files on disk to verify. A skill in a location the
  adapter does not discover (for example, a plugin that declares custom skill
  paths instead of `skills/`) falls into this case and is not verified.
- **A missing binary blocks everything; disabling the plugin disables
  enforcement.** The `PreToolUse` and `UserPromptSubmit` hooks set
  `"onFailure": "block"`. With Claude Code 2.1.322 (session-only
  `--plugin-dir` test), when the `skill-trust` binary was not on `PATH`, every
  prompt and every tool call was blocked with
  `failed; blocking because onFailure is "block"`; the `SessionStart` hook
  failed without blocking. A hook timeout should be blocking under the same
  setting, but that case was not tested. Disabling or uninstalling the plugin, or editing hook settings,
  removes enforcement entirely.

A complete walkthrough — session start with allow, tampered script, deny, slash
command block, new session summary — is in
[`examples/claude-code-adapter-demo.md`](../../examples/claude-code-adapter-demo.md).

## Security

The adapter does not judge whether a validly signed skill is benign. Signature
verification proves that the verified bytes match the signed bytes and that the
signature satisfies the configured policy; it is not a safety guarantee.
Runtime isolation, host permissions, secret management, and
malware/prompt-injection analysis remain separate controls. See the
[threat model](../../docs/THREAT-MODEL.md).
