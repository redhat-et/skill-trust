// Tests for the skill-trust OpenCode adapter.
//
// Two layers:
//
//   1. Pure helper tests: path extraction, containment, guard decisions,
//      block messages — no binary required.
//   2. Integration tests against the real skill-trust binary built from
//      this repository: sign a skill with a local key, then prove the
//      verify-before-load and guard-execution behavior, including modified
//      Bash and Python helpers.

import { execSync } from "node:child_process"
import { generateKeyPairSync } from "node:crypto"
import * as fs from "node:fs"
import * as os from "node:os"
import * as path from "node:path"
import { fileURLToPath } from "node:url"

import { beforeAll, describe, expect, it } from "vitest"

import {
  blockMessage,
  commandPaths,
  containingRoot,
  guardDecision,
  inputPaths,
  runVerify,
  skillRootFromPath,
  toRecord,
  type SkillRecord,
  type VerifyResult,
} from "../lib.ts"

const here = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(here, "..", "..", "..")

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

let tmp = ""
let binary = ""
let pubPem = ""
let keyPath = ""
let policyPath = ""

beforeAll(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "st-adapter-"))
  binary = path.join(tmp, "skill-trust")
  execSync(`go build -o ${JSON.stringify(binary)} ./cmd/skill-trust`, {
    cwd: repoRoot,
    stdio: "pipe",
  })

  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" })
  pubPem = publicKey.export({ type: "spki", format: "pem" }) as string
  keyPath = path.join(tmp, "release.key")
  fs.writeFileSync(keyPath, privateKey.export({ type: "pkcs8", format: "pem" }))
  fs.writeFileSync(path.join(tmp, "release.pub"), pubPem)

  policyPath = path.join(tmp, "policy.json")
  fs.writeFileSync(
    policyPath,
    JSON.stringify({
      apiVersion: "skill-trust.policy/v1",
      name: "adapter-test",
      trustRoots: {},
      signers: [
        {
          name: "release-key",
          mode: "key",
          publicKey: { path: path.join(tmp, "release.pub") },
          // Offline key signing records no transparency log entry.
          requireTransparencyLog: false,
        },
      ],
    }),
  )
}, 240_000)

/** makeSkill creates a skill fixture with a Bash and a Python helper. */
function makeSkill(name: string): string {
  const dir = path.join(tmp, name)
  fs.mkdirSync(path.join(dir, "scripts"), { recursive: true })
  fs.writeFileSync(path.join(dir, "SKILL.md"), `---\nname: ${name}\n---\nTest skill.\n`)
  fs.writeFileSync(path.join(dir, "scripts", "run.sh"), "#!/usr/bin/env bash\necho hello\n")
  fs.chmodSync(path.join(dir, "scripts", "run.sh"), 0o755)
  fs.writeFileSync(path.join(dir, "scripts", "util.py"), 'print("hi")\n')
  return dir
}

/** signSkill signs the fixture with the generated key. */
function signSkill(dir: string): void {
  execSync(`${JSON.stringify(binary)} sign ${JSON.stringify(dir)} --key ${JSON.stringify(keyPath)} --json`, {
    stdio: "pipe",
  })
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

describe("skillRootFromPath", () => {
  it("maps a SKILL.md path to its directory", () => {
    expect(skillRootFromPath("/proj/.opencode/skill/demo/SKILL.md")).toBe(
      "/proj/.opencode/skill/demo",
    )
  })
})

describe("commandPaths", () => {
  const cwd = "/proj"

  it("extracts path-like tokens", () => {
    expect(commandPaths(`bash ${cwd}/scripts/run.sh`, cwd)).toEqual([`${cwd}/scripts/run.sh`])
    expect(commandPaths("python .opencode/skill/demo/scripts/util.py", cwd)).toEqual([
      "/proj/.opencode/skill/demo/scripts/util.py",
    ])
  })

  it("resolves relative tokens against cwd", () => {
    expect(commandPaths("./scripts/run.sh", "/proj/skill")).toEqual(["/proj/skill/scripts/run.sh"])
  })

  it("handles quoted paths", () => {
    expect(commandPaths(`bash "${cwd}/my skill/run.sh"`, cwd)).toEqual([`${cwd}/my skill/run.sh`])
    expect(commandPaths(`bash '${cwd}/my skill/run.sh'`, cwd)).toEqual([`${cwd}/my skill/run.sh`])
  })

  it("ignores flags, URLs, redirects, and variables", () => {
    const out = commandPaths("curl https://example.com/x.py -o out.py > log 2>&1 $SCRIPT", cwd)
    expect(out).toEqual([])
  })

  it("ignores tokens without a path separator", () => {
    expect(commandPaths("echo hello python util.py", cwd)).toEqual([])
  })
})

describe("inputPaths", () => {
  it("resolves path fields and tokenizes command fields", () => {
    const out = inputPaths(
      { path: "src/a.ts", command: "bash scripts/run.sh", timeout: 5 },
      "/proj",
    )
    expect(out).toEqual(["/proj/src/a.ts", "/proj/scripts/run.sh"])
  })

  it("covers the common path key spellings", () => {
    const out = inputPaths({ filePath: "a", workdir: "/w", directory: "d" }, "/proj")
    expect(out).toEqual(["/proj/a", "/w", "/proj/d"])
  })

  it("ignores non-string and empty values", () => {
    expect(inputPaths({ path: 3, command: null, other: "" }, "/proj")).toEqual([])
    expect(inputPaths(null, "/proj")).toEqual([])
    expect(inputPaths("string", "/proj")).toEqual([])
  })
})

describe("containingRoot", () => {
  const roots = ["/proj/.opencode/skill/a", "/proj/.opencode/skill/a/nested"]

  it("matches contained paths with the longest root", () => {
    expect(containingRoot("/proj/.opencode/skill/a/scripts/run.sh", roots)).toBe(
      "/proj/.opencode/skill/a",
    )
    expect(containingRoot("/proj/.opencode/skill/a/nested/x", roots)).toBe(
      "/proj/.opencode/skill/a/nested",
    )
    expect(containingRoot("/proj/.opencode/skill/a", roots)).toBe("/proj/.opencode/skill/a")
  })

  it("does not match sibling directories sharing a prefix", () => {
    expect(containingRoot("/proj/.opencode/skill/ab/scripts/run.sh", roots)).toBeUndefined()
    expect(containingRoot("/proj/other/scripts/run.sh", roots)).toBeUndefined()
  })
})

describe("guardDecision", () => {
  const record: SkillRecord = {
    root: "/skills/demo",
    digest: "aaaa",
    allowed: true,
    reason: "verified",
    findings: [],
  }

  it("allows an unchanged skill", () => {
    const fresh: VerifyResult = {
      decision: "allow",
      manifestDigest: "aaaa",
      observedDigest: "aaaa",
      findings: null,
    }
    const outcome = guardDecision(record, fresh)
    expect(outcome.allowed).toBe(true)
  })

  it("blocks when the verifier fails (fail closed)", () => {
    const outcome = guardDecision(record, { error: "cannot run skill-trust" })
    expect(outcome.allowed).toBe(false)
    expect(outcome.code).toBe("ST-PREFLIGHT-VERIFIER-FAILURE")
  })

  it("blocks a root that never verified", () => {
    const blocked = { ...record, allowed: false, digest: "", reason: "[ST-METADATA-MISSING] no bundle" }
    const outcome = guardDecision(blocked, {
      decision: "block",
      manifestDigest: "",
      observedDigest: "bbbb",
      findings: null,
    })
    expect(outcome.allowed).toBe(false)
    expect(outcome.code).toBe("ST-PREFLIGHT-NOT-VERIFIED")
  })

  it("blocks when the skill now fails policy", () => {
    const fresh: VerifyResult = {
      decision: "block",
      manifestDigest: "aaaa",
      observedDigest: "bbbb",
      findings: [{ code: "ST-CONTENT-MISMATCH", message: 'scripts/util.py: content changed' }],
    }
    const outcome = guardDecision(record, fresh)
    expect(outcome.allowed).toBe(false)
    expect(outcome.code).toBe("ST-PREFLIGHT-CHANGED-AFTER-VERIFY")
    expect(outcome.expectedDigest).toBe("aaaa")
    expect(outcome.observedDigest).toBe("bbbb")
  })

  it("blocks re-signed content that changed after load", () => {
    const fresh: VerifyResult = {
      decision: "allow",
      manifestDigest: "cccc",
      observedDigest: "cccc",
      findings: null,
    }
    const outcome = guardDecision(record, fresh)
    expect(outcome.allowed).toBe(false)
    expect(outcome.code).toBe("ST-PREFLIGHT-CHANGED-AFTER-VERIFY")
    expect(outcome.expectedDigest).toBe("aaaa")
    expect(outcome.observedDigest).toBe("cccc")
  })
})

describe("blockMessage", () => {
  it("emits the expected and observed content digests", () => {
    const message = blockMessage({
      allowed: false,
      code: "ST-PREFLIGHT-CHANGED-AFTER-VERIFY",
      message: "skill /skills/demo changed after it was loaded",
      expectedDigest: "aaaa",
      observedDigest: "bbbb",
    })
    expect(message).toContain("ST-PREFLIGHT-CHANGED-AFTER-VERIFY")
    expect(message).toContain("expected digest aaaa")
    expect(message).toContain("observed bbbb")
  })
})

// ---------------------------------------------------------------------------
// Integration with the real skill-trust binary
// ---------------------------------------------------------------------------

describe("skill-trust integration", () => {
  it("verifies a signed skill before load", async () => {
    const dir = makeSkill("signed-demo")
    signSkill(dir)

    const res = await runVerify(binary, dir, policyPath)
    expect("error" in res).toBe(false)
    if (!("error" in res)) {
      expect(res.decision).toBe("allow")
      expect(res.manifestDigest).toMatch(/^[0-9a-f]{64}$/)
      expect(res.observedDigest).toBe(res.manifestDigest)
    }
    const record = toRecord(dir, res)
    expect(record.allowed).toBe(true)
    expect(record.digest).toBe(!("error" in res) ? res.manifestDigest : "")
  })

  it("blocks a modified skill (cannot be loaded)", async () => {
    const dir = makeSkill("tampered-skill")
    signSkill(dir)
    fs.appendFileSync(path.join(dir, "SKILL.md"), "extra instructions\n")

    const res = await runVerify(binary, dir, policyPath)
    expect("error" in res).toBe(false)
    if (!("error" in res)) {
      expect(res.decision).toBe("block")
      expect(res.findings?.[0]?.code).toBe("ST-CONTENT-MISMATCH")
      expect(res.observedDigest).not.toBe(res.manifestDigest)
    }
    expect(toRecord(dir, res).allowed).toBe(false)
  })

  it("blocks a modified Bash helper before execution", async () => {
    const dir = makeSkill("tampered-bash")
    signSkill(dir)
    const record = toRecord(dir, await runVerify(binary, dir, policyPath))
    expect(record.allowed).toBe(true)

    fs.writeFileSync(path.join(dir, "scripts", "run.sh"), "#!/usr/bin/env bash\necho evil\n")
    const fresh = await runVerify(binary, dir, policyPath)
    const outcome = guardDecision(record, fresh)
    expect(outcome.allowed).toBe(false)
    expect(outcome.code).toBe("ST-PREFLIGHT-CHANGED-AFTER-VERIFY")
    expect(outcome.expectedDigest).toBe(record.digest)
    expect(outcome.observedDigest).not.toBe(record.digest)
    expect(blockMessage(outcome)).toContain("expected digest")
    expect(blockMessage(outcome)).toContain("observed")
  })

  it("blocks a modified Python helper before execution", async () => {
    const dir = makeSkill("tampered-python")
    signSkill(dir)
    const record = toRecord(dir, await runVerify(binary, dir, policyPath))
    expect(record.allowed).toBe(true)

    fs.writeFileSync(path.join(dir, "scripts", "util.py"), 'print("evil")\n')
    const fresh = await runVerify(binary, dir, policyPath)
    const outcome = guardDecision(record, fresh)
    expect(outcome.allowed).toBe(false)
    expect(outcome.code).toBe("ST-PREFLIGHT-CHANGED-AFTER-VERIFY")
  })

  it("covers shell invocations of skill helpers end to end", async () => {
    const dir = makeSkill("shell-path-demo")
    signSkill(dir)
    const record = toRecord(dir, await runVerify(binary, dir, policyPath))

    // A shell tool call referencing the Bash helper by relative path...
    const cwd = path.join(tmp, "work")
    fs.mkdirSync(cwd, { recursive: true })
    const command = `bash ${path.relative(cwd, dir)}/scripts/run.sh`
    const candidates = commandPaths(command, cwd)
    expect(candidates).toEqual([path.join(dir, "scripts", "run.sh")])

    // ...is attributed to the managed root and re-verified.
    const root = containingRoot(candidates[0]!, [record.root])
    expect(root).toBe(record.root)

    fs.chmodSync(path.join(dir, "scripts", "run.sh"), 0o644) // flipped executable bit
    const fresh = await runVerify(binary, dir, policyPath)
    expect(guardDecision(record, fresh).allowed).toBe(false)
  })

  it("fails closed for unsigned skills", async () => {
    const dir = makeSkill("unsigned-demo")
    const res = await runVerify(binary, dir, policyPath)
    expect("error" in res).toBe(false)
    if (!("error" in res)) {
      expect(res.decision).toBe("block")
      expect(res.findings?.[0]?.code).toBe("ST-METADATA-MISSING")
    }
  })

  it("fails closed when the verifier is unusable", async () => {
    const dir = makeSkill("unreachable")
    signSkill(dir)
    const record = toRecord(dir, await runVerify(binary, dir, policyPath))

    const missing = await runVerify("/nonexistent/skill-trust", dir, policyPath)
    expect("error" in missing).toBe(true)
    const outcome = guardDecision(record, missing)
    expect(outcome.allowed).toBe(false)
    expect(outcome.code).toBe("ST-PREFLIGHT-VERIFIER-FAILURE")

    const badPolicy = await runVerify(binary, dir, path.join(tmp, "no-such-policy.json"))
    expect("error" in badPolicy).toBe(true)
    expect(guardDecision(record, badPolicy).allowed).toBe(false)
  })

  it("allows an untouched skill at guard time", async () => {
    const dir = makeSkill("stable-demo")
    signSkill(dir)
    const record = toRecord(dir, await runVerify(binary, dir, policyPath))
    const outcome = guardDecision(record, await runVerify(binary, dir, policyPath))
    expect(outcome.allowed).toBe(true)
  })
})
