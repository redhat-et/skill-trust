// Pure helpers for the skill-trust OpenCode adapter.
//
// The adapter never reimplements manifest or signature logic: every trust
// decision comes from the skill-trust binary (the Go library's CLI surface),
// invoked as `skill-trust verify <dir> --policy <policy> --json`. This module
// only orchestrates: it runs the verifier, tracks verified skill roots and
// their content digests, extracts candidate file paths from tool calls, and
// decides when a guarded path must be blocked (fail closed).

import { spawn } from "node:child_process"
import { realpathSync } from "node:fs"
import * as path from "node:path"

/** One machine-readable verification finding. */
export interface Finding {
  code: string
  message: string
}

/** The skill-trust verify result (see pkg/verify Result JSON). */
export interface VerifyResult {
  decision: "allow" | "block"
  manifestDigest: string
  observedDigest: string
  signer?: string
  findings: Finding[] | null
}

/** A verify run that could not produce a decision (operational failure). */
export interface VerifyError {
  error: string
}

/** Plugin options (passed via the plugins entry in opencode.json(c)). */
export interface Options {
  /** Path to the skill-trust policy JSON. Required. */
  policy: string
  /** skill-trust binary. Default "skill-trust" (from PATH). */
  binary?: string
  /**
   * Fail closed for skills that are not signed: they are removed instead of
   * loaded. Default true. Set false to run in report-only adoption mode.
   */
  strict?: boolean
  /** Periodic re-verification interval in milliseconds. Default 30000. */
  intervalMs?: number
}

/** The adapter's record for one discovered skill root. */
export interface SkillRecord {
  /** Absolute skill root directory. */
  root: string
  /** The signed (expected) manifest digest; empty when blocked. */
  digest: string
  /** Whether the skill satisfied policy at verification time. */
  allowed: boolean
  /** Human-readable summary of the outcome. */
  reason: string
  /** Findings from the verification. */
  findings: Finding[]
}

/**
 * runVerify invokes the skill-trust binary on one skill directory and parses
 * its JSON result. Exit codes: 0 allow, 1 block (decision, JSON on stdout),
 * 2 operational error. Operational failures (including a verifier that hangs
 * past timeoutMs) are returned, not thrown, so callers can fail closed.
 */
export function runVerify(
  binary: string,
  dir: string,
  policy: string,
  timeoutMs = 30_000,
): Promise<VerifyResult | VerifyError> {
  return new Promise((resolve) => {
    const child = spawn(binary, ["verify", dir, "--policy", policy, "--json"], {
      stdio: ["ignore", "pipe", "pipe"],
    })
    let stdout = ""
    let stderr = ""
    let timedOut = false
    const timer = setTimeout(() => {
      timedOut = true
      child.kill("SIGKILL")
    }, timeoutMs)
    child.stdout.on("data", (d) => (stdout += d))
    child.stderr.on("data", (d) => (stderr += d))
    child.on("error", (err) => {
      clearTimeout(timer)
      resolve({ error: `cannot run ${binary}: ${err.message}` })
    })
    child.on("close", (code) => {
      clearTimeout(timer)
      if (timedOut) {
        resolve({ error: `skill-trust verify timed out after ${timeoutMs}ms` })
        return
      }
      if (code !== 0 && code !== 1) {
        resolve({
          error: `skill-trust verify exited ${code}: ${stderr.trim() || stdout.trim()}`,
        })
        return
      }
      try {
        resolve(JSON.parse(stdout) as VerifyResult)
      } catch {
        resolve({ error: `skill-trust verify produced unparseable output: ${stdout.trim()}` })
      }
    })
  })
}

/**
 * normalizePath canonicalizes a path so containment checks cannot be
 * bypassed through symlinked ancestors (for example /tmp vs /private/tmp on
 * macOS, or /bin vs /usr/bin on merged-usr Linux). Symlinks inside a skill
 * directory are already rejected by the manifest format; this closes the
 * aliasing of the *prefix*.
 *
 * The path is resolved to its real path when it exists. When it does not
 * (a command may reference a file that is not on disk), the deepest
 * existing ancestor is resolved and the remaining components appended, so
 * an alias is still collapsed for the part of the path that exists.
 */
export function normalizePath(p: string): string {
  const abs = path.isAbsolute(p) ? p : path.resolve(p)
  try {
    return realpathSync(abs)
  } catch {
    const parts = abs.split(path.sep)
    for (let i = parts.length; i > 1; i--) {
      const prefix = parts.slice(0, i).join(path.sep) || path.sep
      try {
        return path.join(realpathSync(prefix), ...parts.slice(i))
      } catch {
        // try a shorter ancestor
      }
    }
    return abs
  }
}

/** skillRootFromPath maps a SKILL.md path to its canonical skill root. */
export function skillRootFromPath(skillPath: string): string {
  return normalizePath(path.dirname(skillPath))
}

/**
 * commandPaths extracts candidate file paths from a shell command string.
 *
 * Best-effort and deliberately conservative: quoted or bare tokens that
 * contain a path separator are resolved against cwd. Commands that reference
 * skill files through variables or after a cd cannot be resolved statically;
 * guarding the working directory (see the plugin) covers the common case of
 * running helpers from inside a skill directory.
 */
export function commandPaths(command: string, cwd: string): string[] {
  const tokens = command.match(/(?:[^\s"'`]+|"[^"]*"|'[^']*')+/g) ?? []
  const out: string[] = []
  for (const raw of tokens) {
    let token = raw.replace(/^["'`]+|["'`]+$/g, "")
    token = token.replace(/[,;]+$/, "")
    if (!token || token.startsWith("-") || token.startsWith("$")) continue
    if (/^https?:\/\//.test(token) || /^[<>|]/.test(token)) continue
    if (!token.includes("/")) continue
    // Strip a trailing redirection or background operator attached to the token.
    token = token.replace(/[<>|&]+$/, "")
    if (!token.includes("/")) continue
    out.push(path.resolve(cwd, token))
  }
  return out
}

/** Tool input keys that carry a filesystem path. */
const PATH_KEYS = new Set([
  "path",
  "filePath",
  "file_path",
  "directory",
  "dir",
  "workdir",
  "cwd",
  "folder",
])

/** Tool input keys that carry a shell command. */
const COMMAND_KEYS = new Set(["command", "cmd", "script", "shell"])

/**
 * inputPaths extracts candidate filesystem paths from a tool input object:
 * explicit path fields are resolved directly, command fields are tokenized.
 */
export function inputPaths(input: unknown, cwd: string): string[] {
  if (input == null || typeof input !== "object") return []
  const out: string[] = []
  for (const [key, value] of Object.entries(input)) {
    if (typeof value !== "string" || value === "") continue
    if (PATH_KEYS.has(key)) {
      out.push(path.resolve(cwd, value))
    } else if (COMMAND_KEYS.has(key)) {
      out.push(...commandPaths(value, cwd))
    }
  }
  return out
}

/**
 * containingRoot returns the longest known skill root that contains the
 * path (or the root itself), mirroring the preflight contract's
 * longest-match rule. Returns undefined when the path is not managed.
 */
export function containingRoot(
  p: string,
  roots: Iterable<string>,
): string | undefined {
  let best: string | undefined
  for (const root of roots) {
    if (p === root || p.startsWith(root + path.sep)) {
      if (best === undefined || root.length > best.length) best = root
    }
  }
  return best
}

/**
 * Guard outcome for one candidate path.
 */
export interface GuardOutcome {
  allowed: boolean
  code: string
  message: string
  /** The signed (expected) digest recorded at verification time. */
  expectedDigest: string
  /** The digest observed at guard time, when one was computed. */
  observedDigest: string
}

/**
 * guardDecision decides whether a path under a recorded skill root may be
 * used, given the record from verification time and a fresh verify run:
 *
 *   - the verifier could not produce a decision: block (fail closed);
 *   - the skill now fails policy or its content changed (digest differs
 *     from the recorded one): block;
 *   - the root never verified (blocked at load): block;
 *   - otherwise allow.
 */
export function guardDecision(
  record: SkillRecord,
  fresh: VerifyResult | VerifyError,
): GuardOutcome {
  if ("error" in fresh) {
    return {
      allowed: false,
      code: "ST-PREFLIGHT-VERIFIER-FAILURE",
      message: `re-verification of ${record.root} failed: ${fresh.error}`,
      expectedDigest: record.digest,
      observedDigest: "",
    }
  }
  if (!record.allowed) {
    return {
      allowed: false,
      code: "ST-PREFLIGHT-NOT-VERIFIED",
      message: `skill ${record.root} is not verified (${record.reason}); it was blocked at load time`,
      expectedDigest: record.digest,
      observedDigest: fresh.observedDigest,
    }
  }
  if (!allowed(fresh)) {
    const first = fresh.findings?.[0]
    return {
      allowed: false,
      code: "ST-PREFLIGHT-CHANGED-AFTER-VERIFY",
      message: `skill ${record.root} no longer satisfies policy${first ? `: [${first.code}] ${first.message}` : ""}`,
      expectedDigest: record.digest,
      observedDigest: fresh.observedDigest,
    }
  }
  if (fresh.manifestDigest !== record.digest) {
    return {
      allowed: false,
      code: "ST-PREFLIGHT-CHANGED-AFTER-VERIFY",
      message: `skill ${record.root} changed after it was loaded`,
      expectedDigest: record.digest,
      observedDigest: fresh.manifestDigest,
    }
  }
  return {
    allowed: true,
    code: "",
    message: "",
    expectedDigest: record.digest,
    observedDigest: fresh.manifestDigest,
  }
}

function allowed(res: VerifyResult): boolean {
  return res.decision === "allow"
}

/**
 * blockMessage renders a guard outcome (with the expected and observed
 * content digests) as the error the harness and the model see.
 */
export function blockMessage(outcome: GuardOutcome): string {
  let message = `[skill-trust] ${outcome.code}: ${outcome.message}`
  if (outcome.expectedDigest && outcome.observedDigest && outcome.expectedDigest !== outcome.observedDigest) {
    message += ` (expected digest ${outcome.expectedDigest}, observed ${outcome.observedDigest})`
  }
  return message
}

/**
 * toRecord converts a verify run into the adapter's skill record. The digest
 * is the signed (expected) manifest digest even when blocked, so block
 * reporting can show both digests; an unsigned skill has none.
 */
export function toRecord(root: string, res: VerifyResult | VerifyError): SkillRecord {
  if ("error" in res) {
    return {
      root,
      digest: "",
      allowed: false,
      reason: `verifier failure: ${res.error}`,
      findings: [{ code: "ST-PREFLIGHT-VERIFIER-FAILURE", message: res.error }],
    }
  }
  if (allowed(res)) {
    return {
      root,
      digest: res.manifestDigest,
      allowed: true,
      reason: "verified",
      findings: res.findings ?? [],
    }
  }
  const first = res.findings?.[0]
  return {
    root,
    digest: res.manifestDigest,
    allowed: false,
    reason: first ? `[${first.code}] ${first.message}` : "blocked by policy",
    findings: res.findings ?? [],
  }
}
