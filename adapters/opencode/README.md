# skill-trust adapter for OpenCode

This adapter enforces signed agent skills inside
[OpenCode](https://opencode.ai). It follows the harness contract from
[`pkg/preflight`](../../pkg/preflight): verify a skill **before** its
instructions are loaded, and **re-verify before any tool executes or reads a
skill file**. The adapter never reimplements manifest or signature logic —
every trust decision comes from the `skill-trust` binary (the CLI surface of
this repository's Go library), invoked as:

```console
$ skill-trust verify <skill-dir> --policy <policy.json> --json
```

## What it enforces

| Surface | Mechanism | Effect |
|---------|-----------|--------|
| Skill loading | `skill.transform` removes every skill whose root does not verify | OpenCode never loads unverified instructions |
| Tool execution | `tool.hook("execute.before")` re-verifies managed roots | Tool calls touching skill files are blocked before they run |
| Shell execution | `shell.hook("create.before")` re-verifies managed roots | Every shell command OpenCode spawns — the shell tool, session shell endpoints, background shells — is checked before the process starts |
| Drift after load | `skill.updated` events + bounded interval re-verification | Skills modified mid-session are re-checked and dropped from the registry |

Fail-closed is the default: unsigned skills, verifier failures, and stale
digests all block. Script enforcement is path-containment based — any file
under a verified skill root is guarded — so it covers every helper runtime
(Bash, Python, JavaScript, ...) without parsing per-language command syntax.

On every decision the adapter emits the **expected** (signed) and
**observed** (recomputed) content digests, both in the OpenCode server log
and in the error the model sees when a call is blocked:

```text
[skill-trust] allowed /path/to/skill (content digest 8dd3d110…)
[skill-trust] BLOCKED /path/to/skill: [ST-CONTENT-MISMATCH] signed file
  "scripts/util.py" content changed (expected digest 0ca9091e…, observed e08da135…)
```

## Install

1. Put the `skill-trust` binary on `PATH` (or configure `binary` below).
2. Add trust material and a policy JSON to your project, for example:

   ```text
   trust/release.pub               # trusted public key (PEM)
   trust/rhtas-trusted-root.json   # RHTAS TrustedRoot (optional)
   policy/skills.json              # skill-trust policy
   ```

3. Reference the adapter in `opencode.json(c)`:

   ```jsonc
   {
     "plugins": [
       {
         "package": "./adapters/opencode",
         "options": {
           "policy": "./policy/skills.json",
           "binary": "skill-trust",
           "strict": true
         }
       }
     ]
   }
   ```

   See [`examples/opencode.jsonc`](examples/opencode.jsonc).

## Options

| Option | Default | Meaning |
|--------|---------|---------|
| `policy` | (required) | Path to the skill-trust policy JSON ([docs/POLICY.md](../../docs/POLICY.md)). |
| `binary` | `skill-trust` | skill-trust binary path. |
| `strict` | `true` | Fail closed for unsigned skills: they are removed instead of loaded. With `false` (report-only adoption), unsigned skills load with a warning and only previously-verified skills are guarded. |
| `intervalMs` | `30000` | Periodic re-verification interval. |

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

## How guarding works

1. At startup every discovered skill root is verified and recorded with its
   signed manifest digest. The load gate removes skills that do not verify.
   OpenCode replays skill transforms in registration order, and skill
   discovery registers its own transform only after an asynchronous scan —
   so whenever a `skill.updated` event brings roots the gate has not yet
   observed, the adapter re-registers the gate, moving it after the
   discovery transform in the replay chain.
2. Before each tool call or shell command the adapter extracts candidate
   paths: explicit path fields (`path`, `filePath`, `workdir`, ...), tokens
   from shell commands, the working directory, and `skill` tool IDs.
3. Every candidate under a managed root triggers a fresh `verify` run. The
   call is blocked with `ST-PREFLIGHT-CHANGED-AFTER-VERIFY` when the skill
   now fails policy or its digest changed since verification, with
   `ST-PREFLIGHT-NOT-VERIFIED` for roots that never verified, and with
   `ST-PREFLIGHT-VERIFIER-FAILURE` when the verifier itself is unusable.
4. Registry changes fire `skill.updated` events that refresh the
   verification records; a bounded interval re-verifies and reloads as a
   backstop, admitting newly verified skills and dropping newly broken
   ones. (The adapter never reloads per event — a reload itself emits a
   `skill.updated`, which would feed back into the handler.)

**Limitations.** Shell command path extraction is best-effort: paths
referenced only through shell variables, or relative to a `cd` inside the
command, cannot be attributed statically. Explicit tool path inputs and
commands referencing skill files directly are always covered, and guarding
the working directory catches helpers run from inside a skill directory.

A complete live-server walkthrough — load gating, blocked Bash and Python
helpers, drift after load, self-healing — is in
[`examples/opencode-adapter-demo.md`](../../examples/opencode-adapter-demo.md).

## Development

```console
$ cd adapters/opencode
$ npm install
$ npm test     # vitest: pure helper tests + integration against the real binary
$ npm run check
```

The integration tests build `skill-trust` from the repository root, generate
a P-256 key, and prove the load-time and execution-time behavior — including
modified Bash and Python helpers — end to end.
