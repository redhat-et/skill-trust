# Harness preflight contract (v1)

This document defines the integration contract between `skill-trust` and an
agent harness. It is implemented by `pkg/preflight` and consumed by the
OpenCode reference adapter and any future harness adapter.

The contract exists to close the gap between "a signature exists" and "the
agent actually ran the signed bytes". A signature is enforced only by a
harness that follows this contract; see the
[threat model](THREAT-MODEL.md) for the boundary this implies.

## Contract overview

```text
                ┌──────────────────────────────────────────────────┐
                │ harness (OpenCode, custom runtime, CI gate)      │
                │                                                  │
 skill path ───►│ 1. VerifyBeforeLoad(path)                        │
                │    allow? ──► 2. load SKILL.md                   │
                │                │                                 │
                │                ▼                                 │
 user request ─►│ 3. skill instructs: run scripts/run.sh           │
                │    harness resolves the file path               │
                │                │                                 │
                │                ▼                                 │
                │ 4. GuardExecution(path)                          │
                │    re-verify skill; allow? ──► execute            │
                │    block? ──► refuse, report expected/observed   │
                └──────────────────────────────────────────────────┘
```

## API

The `preflight.Preflight` type wraps a `preflight.Verifier` (the production
implementation is the `verify` package; `preflight.ManifestVerifier`
provides content-identity-only checks for tests and integrity-only use).

### `VerifyBeforeLoad(dir) (VerifiedSkill, error)`

**Call this before reading `SKILL.md` or any other skill file.** The
harness must not read, parse, or act on skill instructions before this call
returns successfully. On success the skill is registered with its verified
content identity:

```go
type VerifiedSkill struct {
    Root           string    // absolute, symlink-free skill root
    ManifestDigest string    // verified content identity
    VerifiedAt     time.Time
}
```

The harness should associate the *active* skill session with
`ManifestDigest` so that later decisions can be bound to a content
identity, and include the digest in logs.

On failure the returned error is a `*preflight.BlockError` with a stable
machine-readable code, a user-readable message, the expected and observed
digests, and the verifier's findings. The harness must not load the skill.

### `GuardExecution(path) error`

**Call this immediately before executing or reading any file that may
belong to a skill** — before running `bash scripts/run.sh`, invoking
`python scripts/util.py`, `node scripts/helper.js`, sourcing a reference,
or opening an asset. The call happens at execution time, not at load time,
because content may change in between (the TOCTOU window).

Semantics, by path:

| Path | Outcome |
|------|---------|
| Not under any registered skill root | allowed (not skill-trust's business) |
| Under a registered skill root that still verifies to the same digest | allowed |
| Under a registered skill root whose content changed, signature no longer verifies, or policy no longer passes | **blocked** with `ST-PREFLIGHT-CHANGED-AFTER-VERIFY` |

### `GuardSkillPath(path) error`

Like `GuardExecution`, but for paths the harness *knows* are skill paths
(for example, the skill directory on reload). Unregistered skill paths are
blocked with `ST-PREFLIGHT-NOT-VERIFIED` instead of ignored.

### `Forget(dir)`

Remove the verification record when the harness unloads a skill.

## Script execution across runtimes

The contract deliberately does **not** parse command lines or special-case
languages. Enforcement is by **path containment plus digest re-verification**:

1. The harness intercepts the tool call that would execute or read a file
   (for example, the Bash tool in an agent runtime).
2. Every plausible file path in the command is resolved to an absolute,
   symlink-free path.
3. `GuardExecution` checks containment against registered skill roots and
   re-verifies any match.

This covers **Bash, Python, JavaScript, and any other helper runtime**
uniformly, because the check is on *which file is being loaded*, not on the
syntax of the invocation. A modified `scripts/run.sh`, `scripts/util.py`,
or `scripts/helper.js` is blocked before the interpreter starts; a script
added after signing is blocked because it is not in the signed manifest; a
flipped executable bit is blocked because permissions are signed.

Adapters must resolve paths with symlink evaluation so that aliases cannot
evade containment (`pkg/preflight` does this internally).

## Re-verification triggers

A conforming harness re-verifies (calls `GuardExecution`/`VerifyBeforeLoad`
again) whenever:

- a skill-associated script or resource is about to be executed or read
  (always; see above);
- the skill is reloaded or re-entered after any period of time;
- execution crosses a process boundary (for example, a subagent or remote
  harness receives the skill);
- the harness cannot prove the content is unchanged.

Re-verification always recomputes the manifest digest; there is no trusted
mtime shortcut. `Forget` invalidates the record entirely.

## Block reasons

Blocks are structured errors, designed for both machines and humans:

```go
type BlockError struct {
    Code               string   // stable, e.g. ST-PREFLIGHT-CHANGED-AFTER-VERIFY
    Message            string   // user-readable
    ExpectedDigest     string   // digest at load time
    ObservedDigest     string   // digest at guard time
    UnderlyingFindings []Finding
}
```

Preflight-layer codes:

| Code | Meaning |
|------|---------|
| `ST-PREFLIGHT-NOT-VERIFIED` | a known skill path was used without a prior allow |
| `ST-PREFLIGHT-CHANGED-AFTER-VERIFY` | content or verification changed after the allow |
| `ST-PREFLIGHT-VERIFIER-FAILURE` | the verifier failed or blocked the skill |

Verifier-layer codes (`ST-CONTENT-*`, `ST-SIGNATURE-*`, `ST-EVIDENCE-*`,
`ST-POLICY-*`, `ST-TRUST-*`, `ST-METADATA-*`) are passed through in
`UnderlyingFindings`; see [POLICY.md](POLICY.md).

Adapters must surface at minimum the code, the message, and the
expected/observed digests in operator-facing logs.

## Reference implementation notes

`pkg/preflight` is concurrency-safe and has no dependencies beyond
`pkg/manifest`. It never implements a second manifest or signature
algorithm — all trust decisions flow through the injected `Verifier`.

Two reference adapters implement this contract:

- **OpenCode** (`adapters/opencode`): a thin wrapper that calls
  `VerifyBeforeLoad` when a skill is activated and `GuardExecution` in the
  tool pre-execution hook for every Bash call that references a skill path.
- **Claude Code** (`adapters/claude-code`): a plugin adapter using hook
  commands (`skill-trust hook claude-code session-start` /
  `pre-tool-use` / `user-prompt-submit`). The hook logic lives in
  `internal/claudecode` and calls the verifier in-process (no subprocess).
  Session state is stored in
  `$CLAUDE_PLUGIN_DATA/sessions/state-<session_id>.json`. The policy path
  itself should be absolute (a relative path is resolved against the hook
  process's cwd); relative paths inside the policy JSON are resolved against
  the policy file's directory (not the process cwd, as `verify` does).

## References

- [Architecture](ARCHITECTURE.md)
- [Threat model](THREAT-MODEL.md)
- [Verification policy](POLICY.md)
