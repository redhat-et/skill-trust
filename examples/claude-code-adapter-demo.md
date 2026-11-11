# Claude Code adapter demo walkthrough

This walkthrough demonstrates the skill-trust Claude Code adapter enforcing
signed skills. It shows session start with an allowed skill, tamper detection,
a blocked tool call, a blocked slash command, and a new session summary showing
the blocked skill.

All output below is captured from real hook invocations of the built binary
with piped JSON inputs. Digests in the transcript are abbreviated with "…" for
readability; everything else is verbatim. Commands use a temporary `HOME` to
avoid touching the real `~/.claude`.

## Setup

Build the binary and set up a temporary home directory:

```console
$ cd /path/to/skill-trust
$ go build -o /tmp/st-demo/skill-trust ./cmd/skill-trust

$ export HOME=/tmp/st-demo/home
$ mkdir -p $HOME/.claude/skills
```

Copy a signed skill fixture (the repository's golden fixture: `SKILL.md` plus
Bash and Python helpers, already signed):

```console
$ cp -r testdata/fixtures/valid-complete $HOME/.claude/skills/demo-skill
$ ls -la $HOME/.claude/skills/demo-skill/
drwxr-xr-x. 7  160 .
drwxr-xr-x. 3   60 ..
drwxr-xr-x. 2   60 assets
drwxr-xr-x. 2   60 .hidden
drwxr-xr-x. 2   60 references
drwxr-xr-x. 2  100 scripts
-rw-r--r--. 1  512 SKILL.md
drwxr-xr-x. 2   80 .skill-trust
```

Copy the fixtures public key and create a trust policy:

```console
$ cd /tmp/st-demo
$ cp /path/to/skill-trust/testdata/fixtures/fixtures.pub ./release.pub

$ cat > policy.json << 'EOF'
{
  "apiVersion": "skill-trust.policy/v1",
  "name": "demo-policy",
  "signers": [
    {
      "name": "demo-key",
      "mode": "key",
      "publicKey": {
        "path": "release.pub"
      },
      "requireTransparencyLog": false
    }
  ]
}
EOF
```

Verify the skill:

```console
$ ./skill-trust verify $HOME/.claude/skills/demo-skill --policy policy.json
ALLOW home/.claude/skills/demo-skill
  signer:  rule "demo-key" (key ZfwKbrdt…)
  digest:  e65d911b…7fbc7b51
  rule demo-key (key): matched
```

## Hook invocations

The hook commands read Claude Code hook JSON from stdin and write JSON
responses to stdout. We pipe prepared JSON fixtures to demonstrate each event.

### 1. SessionStart: skill verified

Create the session-start input JSON (Claude Code sends this on startup,
`/clear`, resume, compact):

```console
$ cat > session-start.json << 'EOF'
{
  "session_id": "demo-session-1",
  "cwd": "/tmp/st-demo/home",
  "hook_event_name": "SessionStart",
  "source": "startup"
}
EOF
```

Invoke the hook:

```console
$ HOME=/tmp/st-demo/home \
  CLAUDE_PLUGIN_OPTION_POLICY=/tmp/st-demo/policy.json \
  ./skill-trust hook claude-code session-start < session-start.json
{"hookSpecificOutput":{"hookEventName":"SessionStart"},"systemMessage":"skill-trust: 1 skills verified, 0 blocked"}
```

The skill verified; session state recorded the digest
`e65d911b…7fbc7b51`.

### 2. PreToolUse Read: allowed (empty output)

Create the pre-tool-use input JSON for a `Read` tool call:

```console
$ cat > pretooluse-read.json << 'EOF'
{
  "session_id": "demo-session-1",
  "cwd": "/tmp/st-demo/home",
  "hook_event_name": "PreToolUse",
  "tool_name": "Read",
  "tool_input": {
    "file_path": "/tmp/st-demo/home/.claude/skills/demo-skill/SKILL.md"
  }
}
EOF
```

Invoke the hook:

```console
$ HOME=/tmp/st-demo/home \
  CLAUDE_PLUGIN_OPTION_POLICY=/tmp/st-demo/policy.json \
  ./skill-trust hook claude-code pre-tool-use < pretooluse-read.json
(exit code: 0)
```

No output: the skill root verified, digest matches the session-start record,
tool is allowed. Claude Code proceeds with the normal permission flow.

### 3. Tamper the skill

Modify `scripts/helper.py`:

```console
$ echo "print('evil')" > $HOME/.claude/skills/demo-skill/scripts/helper.py
```

The skill's content digest is now different.

### 4. PreToolUse Bash: deny (tampered skill)

Create the pre-tool-use input JSON for a `Bash` tool call running the tampered
script:

```console
$ cat > pretooluse-bash.json << 'EOF'
{
  "session_id": "demo-session-1",
  "cwd": "/tmp/st-demo/home",
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": {
    "command": "python3 .claude/skills/demo-skill/scripts/helper.py"
  }
}
EOF
```

Invoke the hook:

```console
$ HOME=/tmp/st-demo/home \
  CLAUDE_PLUGIN_OPTION_POLICY=/tmp/st-demo/policy.json \
  ./skill-trust hook claude-code pre-tool-use < pretooluse-bash.json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"[ST-PREFLIGHT-CHANGED-AFTER-VERIFY] skill /tmp/st-demo/home/.claude/skills/demo-skill changed or no longer satisfies policy after it was verified\nroot: /tmp/st-demo/home/.claude/skills/demo-skill\nexpected digest e65d911b…7fbc7b51\nobserved digest b8f7c452…1244f2f\n  [ST-CONTENT-MISMATCH] unsigned file \"scripts/helper.py\" was added"}}
```

The hook returns a deny decision with `ST-PREFLIGHT-CHANGED-AFTER-VERIFY`. The
expected digest (from session start) and observed digest (recomputed now) are
shown, along with the underlying finding: the file was modified (treated as
"added" because the manifest records signed files). Claude Code blocks the tool
call and shows this reason to Claude.

### 5. UserPromptSubmit: block `/demo-skill`

Create the user-prompt-submit input JSON (Claude Code sends this when the user
types a prompt):

```console
$ cat > userpromptsubmit.json << 'EOF'
{
  "session_id": "demo-session-1",
  "cwd": "/tmp/st-demo/home",
  "hook_event_name": "UserPromptSubmit",
  "prompt": "/demo-skill"
}
EOF
```

Invoke the hook:

```console
$ HOME=/tmp/st-demo/home \
  CLAUDE_PLUGIN_OPTION_POLICY=/tmp/st-demo/policy.json \
  ./skill-trust hook claude-code user-prompt-submit < userpromptsubmit.json
{"decision":"block","reason":"[ST-PREFLIGHT-CHANGED-AFTER-VERIFY] skill /tmp/st-demo/home/.claude/skills/demo-skill changed or no longer satisfies policy after it was verified\nroot: /tmp/st-demo/home/.claude/skills/demo-skill\nexpected digest e65d911b…7fbc7b51\nobserved digest b8f7c452…1244f2f\n  [ST-CONTENT-MISMATCH] unsigned file \"scripts/helper.py\" was added"}
```

The hook blocks the prompt with the same reason. Typing `/demo-skill` is denied
before the `Skill` tool runs. (Slash commands do not go through the `Skill`
tool, so the `UserPromptSubmit` hook is needed to catch them.)

### 6. New session start: blocked skill in summary

Start a new session (new `session_id`):

```console
$ cat > session-start-2.json << 'EOF'
{
  "session_id": "demo-session-2",
  "cwd": "/tmp/st-demo/home",
  "hook_event_name": "SessionStart",
  "source": "startup"
}
EOF

$ HOME=/tmp/st-demo/home \
  CLAUDE_PLUGIN_OPTION_POLICY=/tmp/st-demo/policy.json \
  ./skill-trust hook claude-code session-start < session-start-2.json
{"hookSpecificOutput":{"additionalContext":"The following skills are blocked and should not be used:\n  - demo-skill (ST-PREFLIGHT-VERIFIER-FAILURE)","hookEventName":"SessionStart"},"systemMessage":"skill-trust: 0 skills verified, 1 blocked (demo-skill: ST-PREFLIGHT-VERIFIER-FAILURE)"}
```

The new session re-verifies all skills from scratch. The tampered skill now
fails verification (`ST-PREFLIGHT-VERIFIER-FAILURE`), so it is reported as
blocked. The `systemMessage` is shown to the user; the `additionalContext` is
sent to Claude, instructing it not to use the blocked skill.

## Interactive use

To use the adapter interactively in Claude Code:

1. Install via `/plugin marketplace add redhat-et/skill-trust` and
   `/plugin install skill-trust@skill-trust`.
2. Install the matching CLI: `go install github.com/redhat-et/skill-trust/cmd/skill-trust@v0.2.0`.
3. Configure the policy path: `/plugin configure skill-trust` → set `policy` to
   your trust policy JSON.
4. Start a new session: the adapter reports verified/blocked skills.
5. When you use a skill (invoke a tool touching a skill file, or type
   `/skill-name`), the adapter re-verifies before allowing the call.

See [`adapters/claude-code/README.md`](../adapters/claude-code/README.md) for
the full reference.
