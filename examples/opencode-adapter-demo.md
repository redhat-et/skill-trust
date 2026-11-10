# Example: enforcing signed skills inside OpenCode

This walkthrough wires the skill-trust OpenCode adapter into a project and
shows every enforcement decision against a live OpenCode server. Commands were
executed with OpenCode 2.0.32 and 2.2.7, and `skill-trust` built from this
repository.

The project contains three skills:

| Skill | State | Expected behavior |
|-------|-------|-------------------|
| `verified` | signed with the trusted release key | loads and executes |
| `tampered` | signed, then `scripts/util.py` modified | never loads; execution blocked |
| `unsigned` | no `.skill-trust/` control files | never loads |

## 1. Lay out the project

```text
demo/
├── policy.json                  # skill-trust policy (trusted key, no tlog)
├── release.key / release.pub    # P-256 signing pair
└── .opencode/
    ├── opencode.json            # plugin wiring
    └── skill/
        ├── verified/            # SKILL.md + scripts/{run.sh,util.py}, signed
        ├── tampered/            # SKILL.md + scripts/{run.sh,util.py}, signed
        └── unsigned/            # SKILL.md + scripts/run.sh
```

```console
$ openssl ecparam -name prime256v1 -genkey -noout -out release.key
$ openssl ec -in release.key -pubout -out release.pub

$ skill-trust sign .opencode/skill/verified --key release.key
$ skill-trust sign .opencode/skill/tampered --key release.key
$ printf 'print("EVIL PAYLOAD")\n' > .opencode/skill/tampered/scripts/util.py
```

`.opencode/opencode.json`:

```json
{
  "plugins": [
    {
      "package": "./adapters/opencode",
      "options": {
        "policy": "./policy.json",
        "binary": "skill-trust",
        "intervalMs": 5000
      }
    }
  ]
}
```

`policy.json` (offline trusted key — see
[`adapters/opencode/examples/`](../adapters/opencode/examples/) for public
Sigstore and RHTAS variants):

```json
{
  "apiVersion": "skill-trust.policy/v1",
  "name": "demo",
  "trustRoots": {},
  "signers": [
    {
      "name": "release-key",
      "mode": "key",
      "publicKey": { "path": "release.pub" },
      "requireTransparencyLog": false
    }
  ]
}
```

## 2. Ground truth from the CLI

Before looking at the adapter, confirm what the verifier itself says:

```console
$ skill-trust verify .opencode/skill/verified --policy policy.json --json | jq -r .decision
allow
$ skill-trust verify .opencode/skill/tampered --policy policy.json --json | jq -r '.decision, .findings[0].code'
block
ST-CONTENT-MISMATCH
$ skill-trust verify .opencode/skill/unsigned --policy policy.json --json | jq -r '.decision, .findings[0].code'
block
ST-METADATA-MISSING
```

## 3. Start the server and list skills

```console
$ opencode serve --port 4599 &
$ curl -s -u opencode:"$PASSWORD" http://localhost:4599/api/skill | jq -r '.data[].id'
verified
```

Only the verified skill is registered. The adapter's server log shows every
decision, with the signed and observed digests:

```text
[skill-trust] BLOCKED /builtin: [ST-METADATA-MISSING] embedded manifest: ...
[skill-trust] BLOCKED /demo/.opencode/skill/tampered: [ST-CONTENT-MISMATCH] signed file "scripts/util.py" content changed (expected sha256:b4489319..., observed sha256:eabbc323...)
[skill-trust] BLOCKED /demo/.opencode/skill/unsigned: [ST-METADATA-MISSING] ...
[skill-trust] allowed /demo/.opencode/skill/verified (content digest fbc9a92e...)
[skill-trust] removed skill tampered: [ST-CONTENT-MISMATCH] signed file "scripts/util.py" content changed ...
[skill-trust] removed skill unsigned: [ST-METADATA-MISSING] ...
```

Skills whose roots never verified — including OpenCode's own built-in skills
and any globally installed skills — are removed fail closed in strict mode.

## 4. Block modified helpers before execution

Create a session and drive shell commands through the server. Every shell
command OpenCode spawns passes the adapter's pre-execution re-verification:

```console
$ curl -s -u opencode:"$PASSWORD" -X POST http://localhost:4599/api/session -d '{}' | jq -r .data.id
ses_e3c96649cffeXcSc0CPvsyNc4x

$ curl -o /dev/null -w "%{http_code}\n" -u opencode:"$PASSWORD" \
    -X POST http://localhost:4599/api/session/$SESSION/shell \
    -d '{"command": "bash /demo/.opencode/skill/tampered/scripts/run.sh"}'
500
$ curl -o /dev/null -w "%{http_code}\n" -u opencode:"$PASSWORD" \
    -X POST http://localhost:4599/api/session/$SESSION/shell \
    -d '{"command": "python3 /demo/.opencode/skill/tampered/scripts/util.py"}'
500
$ curl -o /dev/null -w "%{http_code}\n" -u opencode:"$PASSWORD" \
    -X POST http://localhost:4599/api/session/$SESSION/shell \
    -d '{"command": "bash /demo/.opencode/skill/verified/scripts/run.sh"}'
204
```

The Bash and Python helpers of the tampered skill are rejected (HTTP 500)
before the process spawns; the verified skill's helper runs (HTTP 204). The
server log shows why, with both digests:

```text
[skill-trust] guard blocked /demo/.opencode/skill/tampered/scripts/run.sh:
  [skill-trust] ST-PREFLIGHT-NOT-VERIFIED: skill /demo/.opencode/skill/tampered
  is not verified ([ST-CONTENT-MISMATCH] signed file "scripts/util.py" content
  changed (expected sha256:b4489319..., observed sha256:eabbc323...))
[skill-trust] guard blocked /demo/.opencode/skill/tampered/scripts/util.py:
  [skill-trust] ST-PREFLIGHT-NOT-VERIFIED: ...
```

## 5. Block drift after load

A skill that verified at load time but changed on disk afterwards is caught at
execution time with `ST-PREFLIGHT-CHANGED-AFTER-VERIFY`:

```console
$ printf 'print("INJECTED")\n' > .opencode/skill/verified/scripts/util.py
$ curl -o /dev/null -w "%{http_code}\n" -u opencode:"$PASSWORD" \
    -X POST http://localhost:4599/api/session/$SESSION/shell \
    -d '{"command": "python3 /demo/.opencode/skill/verified/scripts/util.py"}'
500
```

```text
[skill-trust] guard blocked /demo/.opencode/skill/verified/scripts/util.py:
  [skill-trust] ST-PREFLIGHT-CHANGED-AFTER-VERIFY: skill /demo/.opencode/skill/verified
  no longer satisfies policy: [ST-CONTENT-MISMATCH] signed file "scripts/util.py"
  content changed (expected sha256:0114f79e..., observed sha256:503e0003...)
```

Restoring the file heals the state on the next re-verification cycle — the
same command succeeds again (HTTP 204) without restarting the server.

## What this proves

- **Load gating**: only skills that verify under the policy are registered;
  the model never sees unverified instructions.
- **Execution gating** for Bash and Python helpers (and any other runtime —
  enforcement is path-containment based, not language parsing).
- **Digest reporting**: expected and observed digests accompany every block.
- **Fail-closed defaults**: unsigned skills, verifier failures, and drift
  after verification all block.
- **Delegation**: every decision comes from `skill-trust verify --json`; the
  adapter contains no manifest or signature logic.
