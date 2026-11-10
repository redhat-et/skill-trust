// skill-trust adapter for OpenCode.
//
// Verifies signed agent skills before OpenCode loads them and re-verifies
// before any tool executes or reads a skill file. All trust decisions come
// from the skill-trust binary; this adapter never reimplements manifest or
// signature logic (see pkg/preflight for the harness contract it follows).
//
// Configure in opencode.json(c):
//
//   {
//     "plugins": [
//       {
//         "package": "./adapters/opencode",
//         "options": {
//           "policy": "./policy/skills.json",
//           "binary": "skill-trust",
//           "strict": true
//         }
//       }
//     ]
//   }
//
// Options:
//   policy      (required) path to the skill-trust policy JSON
//   binary      skill-trust binary (default: "skill-trust" from PATH)
//   strict      fail closed for unsigned skills (default: true)
//   intervalMs  re-verification backstop interval (default: 30000)
//
// Load gating uses a skill transform that removes skills whose roots do not
// verify. OpenCode replays transforms in registration order onto a fresh
// registry value, and skill discovery registers its own transform only after
// an asynchronous scan — so this adapter re-registers its gate whenever a
// skill.updated event brings roots the gate has not yet seen, which moves it
// after the discovery transform in the replay chain (state.ts keeps
// transforms in an insertion-ordered set). Until the gate observes every
// known root it keeps re-registering; afterwards events only refresh the
// verification records.

import { Plugin } from "@opencode/plugin"

import {
  blockMessage,
  commandPaths,
  containingRoot,
  guardDecision,
  inputPaths,
  normalizePath,
  runVerify,
  skillRootFromPath,
  toRecord,
  type Options,
  type SkillRecord,
} from "./lib.ts"

export default Plugin.define({
  id: "skill-trust",
  async setup(ctx) {
    const opts = ctx.options as Partial<Options>
    if (!opts.policy || typeof opts.policy !== "string") {
      throw new Error(
        '[skill-trust] the "policy" option is required: path to a skill-trust policy JSON (see docs/POLICY.md)',
      )
    }
    const binary = opts.binary ?? "skill-trust"
    const strict = opts.strict !== false
    const intervalMs = opts.intervalMs ?? 30_000

    // root -> record for every discovered skill root; skill id -> root.
    const records = new Map<string, SkillRecord>()
    const rootsBySkillID = new Map<string, string>()
    // Roots observed by the latest gate replay, and roots known from the
    // latest registry read. The gate is settled when it has seen every
    // known root.
    let gateSeenRoots = new Set<string>()
    let knownRoots = new Set<string>()
    let lastRemovals = new Set<string>()
    let settled = false
    let disposed = false

    const log = (...args: unknown[]) => console.log("[skill-trust]", ...args)

    // Discover skill roots and verify each one, recording the signed
    // (expected) digest. Emits expected and observed digests on every
    // decision.
    async function verifyAll(): Promise<void> {
      const list = await ctx.skill.list()
      const roots = new Set<string>()
      for (const skill of list.data) {
        const root = skillRootFromPath(skill.path)
        roots.add(root)
        rootsBySkillID.set(skill.id, root)
        if (records.has(root)) continue
        const res = await runVerify(binary, root, opts.policy!)
        const record = toRecord(root, res)
        records.set(root, record)
        if (record.allowed) {
          log(`allowed ${root} (content digest ${record.digest})`)
        } else if ("error" in res) {
          log(`BLOCKED ${root}: ${record.reason}`)
        } else {
          const suffix =
            res.manifestDigest && res.observedDigest && res.manifestDigest !== res.observedDigest
              ? ` (expected digest ${res.manifestDigest}, observed ${res.observedDigest})`
              : ""
          log(`BLOCKED ${root}: ${record.reason}${suffix}`)
        }
      }
      knownRoots = roots
    }

    // Load gate: remove every skill whose root did not verify, so OpenCode
    // never loads its instructions. Synchronous by contract; reads the
    // records captured by verifyAll. Defensive: an exception inside a
    // transform callback would poison every state rebuild, so failures are
    // contained and logged.
    function gateCallback(editor: {
      list(): readonly { id: string; path: string }[]
      remove(id: string): void
    }): void {
      try {
        const seen = new Set<string>()
        const removed = new Set<string>()
        for (const skill of editor.list()) {
          const root = skillRootFromPath(skill.path)
          seen.add(root)
          const record = records.get(root)
          if (record?.allowed) continue
          if (!strict) {
            log(`warning: ${skill.id} is not verified (${record?.reason ?? "no verification record"})`)
            continue
          }
          editor.remove(skill.id)
          removed.add(skill.id)
          // Rebuilds replay the whole gate; only log newly removed skills so
          // periodic re-verification does not repeat itself.
          if (!lastRemovals.has(skill.id)) {
            log(`removed skill ${skill.id}: ${record?.reason ?? "never verified (fail closed)"}`)
          }
        }
        lastRemovals = removed
        gateSeenRoots = seen
        settled = isSubset(knownRoots, gateSeenRoots)
      } catch (err) {
        console.error("[skill-trust] gate callback failed:", err)
      }
    }

    // Every live gate registration. Re-registering must dispose all of
    // them: a leaked duplicate would also remove skills and would corrupt
    // the settled tracking below.
    const gates = new Set<{ dispose: () => Promise<void> }>()

    async function registerGate(): Promise<void> {
      for (const registration of gates) {
        gates.delete(registration)
        await registration.dispose().catch(() => {})
      }
      const registration = await ctx.skill.transform(gateCallback)
      gates.add(registration)
    }

    // Refresh verification records and reposition the gate when needed.
    // OpenCode's own registry rebuilds (watcher- and config-driven) re-apply
    // the gate with the live records, so this never reloads on events: a
    // reload echoes a skill.updated event, and reloading per event feeds
    // back into this handler. The bounded interval below reloads instead,
    // which also admits newly verified skills that the gate removed fail
    // closed before their first verification. Serialized so the event
    // handler and the interval never interleave.
    let refreshChain: Promise<void> = Promise.resolve()
    function refreshState(): Promise<void> {
      const run = refreshChain.then(() =>
        verifyAll().then(async () => {
          settled = isSubset(knownRoots, gateSeenRoots)
          if (!settled) await registerGate()
        }),
      )
      refreshChain = run.catch(() => {})
      return run
    }

    await verifyAll()
    await registerGate()

    // Execution guard shared by both hook surfaces below: re-verify every
    // managed skill root referenced by the call. This is what blocks
    // modified Bash, Python, or any other helper before execution,
    // regardless of language.
    async function guardPaths(candidates: string[]): Promise<void> {
      const checked = new Set<string>()
      for (const raw of candidates) {
        // Canonicalize so a symlinked prefix (for example /tmp vs
        // /private/tmp) cannot slip a managed path past containment.
        const candidate = normalizePath(raw)
        const root = containingRoot(candidate, records.keys())
        if (!root || checked.has(root)) continue
        checked.add(root)
        const record = records.get(root)!
        if (!record.allowed && !strict) continue // report-only mode
        const fresh = await runVerify(binary, root, opts.policy!)
        const outcome = guardDecision(record, fresh)
        if (!outcome.allowed) {
          log(`guard blocked ${candidate}: ${blockMessage(outcome)}`)
          throw new Error(blockMessage(outcome))
        }
      }
    }

    // Tool calls: extract candidate paths from explicit path fields, shell
    // command tokens, and the working directory. The skill tool loads
    // instructions by ID; re-verify that skill's root before it is expanded
    // into the conversation.
    await ctx.tool.hook("execute.before", async (event) => {
      const input = (event.input ?? {}) as Record<string, unknown>
      const cwd =
        typeof input.workdir === "string" && input.workdir !== ""
          ? input.workdir
          : ctx.location.directory
      const candidates = inputPaths(input, cwd)
      candidates.push(cwd)
      const skillID = input.id ?? input.skillID
      if (typeof skillID === "string") {
        const root = rootsBySkillID.get(skillID)
        if (root) candidates.push(root)
      }
      await guardPaths(candidates)
    })

    // Shell service: every shell command OpenCode itself spawns (the shell
    // tool, session shell endpoints, background shells) goes through
    // Shell.create, which fires create.before before the process starts.
    // Guarding here closes paths that bypass the tool pipeline.
    await ctx.shell.hook("create.before", async (invocation) => {
      const candidates = commandPaths(invocation.command, invocation.cwd)
      candidates.push(invocation.cwd)
      await guardPaths(candidates)
    })

    // React to registry changes: skills discovered, added, or removed fire
    // skill.updated. Each event refreshes records and, while the gate is not
    // yet positioned after every skill-adding transform, re-registers it.
    const events = await ctx.event.subscribe({ types: ["skill.updated"] })
    void (async () => {
      for await (const event of events) {
        if (disposed) break
        const directory = (event as { location?: { directory?: string } }).location?.directory
        if (directory && directory !== ctx.location.directory) continue
        try {
          await refreshState()
        } catch (err) {
          log(`refresh failed: ${String(err)}`)
        }
      }
    })()

    // Backstop on a bounded cadence: refresh records, reposition the gate
    // if needed, and reload once so the gate re-applies with fresh records
    // (admitting newly verified skills, dropping newly broken ones). The
    // reload echoes one skill.updated event; the handler above refreshes
    // records without reloading, so the cycle ends here.
    const timer = setInterval(() => {
      void refreshState()
        .then(() => ctx.skill.reload())
        .catch((err) => log(`re-verification failed: ${String(err)}`))
    }, intervalMs)

    return () => {
      disposed = true
      clearInterval(timer)
      for (const registration of gates) void registration.dispose()
    }
  },
})

function isSubset(small: Set<string>, large: Set<string>): boolean {
  for (const value of small) if (!large.has(value)) return false
  return true
}
