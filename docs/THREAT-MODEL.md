# skill-trust threat model

This document defines what `skill-trust` protects, what it does not protect,
and the enforcement boundary that harness adapters must honor. It is the
security contract for the manifest, signing, verification, and harness
integration work in the implementation backlog.

## Scope

`skill-trust` signs a complete Agent Skill directory and verifies it before a
harness loads or executes the skill. The attacker of interest is anyone who
can modify skill content between the moment an organization signs it and the
moment an agent harness uses it.

The system does not attempt to prove that skill instructions are safe, that a
signer is trustworthy, or that a harness configuration is correct. Those are
separate problems, addressed by separate controls, described below.

## The five claims

A signed skill package supports five distinct claims. They are separate
concepts and must not be conflated:

1. **Content integrity** — the bytes on disk are byte-for-byte identical to
   the bytes that were signed, as described by the canonical manifest.
2. **Signer identity** — the signature was produced by a key or certificate
   belonging to a specific identity, such as a GitHub Actions workflow, a
   service account, or a human's OIDC identity.
3. **Provenance** — where the content came from, expressed through
   certificate claims (issuer, workflow, repository) recorded in the bundle.
4. **Transparency evidence** — the signing event was recorded in an
   append-only transparency log (Rekor), with an inclusion proof that
   verifiers can check offline.
5. **Runtime authorization** — the decision by a deployed policy that this
   signer, this identity, and this provenance are allowed to run *here*.

A signature proves 1 and 2 cryptographically, 3 and 4 through evidence in the
bundle, and 5 is a policy decision made at verification time. Content
integrity without a signer check does not establish who produced the content.
A trusted signer without content integrity does not establish which content
was produced. A valid signature under a policy that was never evaluated
establishes nothing about authorization.

## What a signature does not prove

- It does not prove the skill is **benign**. A malicious author can sign
  malicious instructions.
- It does not detect **prompt injection** or unsafe instructions inside
  `SKILL.md` or its scripts.
- It does not provide **runtime isolation**. Signed scripts execute with the
  permissions of the harness.
- It does not enforce **host permissions**, secret management, or egress
  control.
- It does not perform **malware or static analysis** of skill scripts.
- It does not protect a harness that **bypasses the verifier**.

These are real security requirements. They are addressed by controls that
compose with `skill-trust` (sandboxing, tool permission systems, secret
hygiene, content scanning) and are explicitly out of scope for the signature
itself.

## System model and trust boundaries

```text
+----------+     +-------------+     +------------------+     +---------+
|  Signer  | --> | Distribution | --> | Verifier + Policy | --> | Harness |
| (org CI, |     | (git, tar,   |     | (skill-trust      |     | (agent  |
|  human)  |     |  object store)|    |  library/CLI)     |     |  runner)|
+----------+     +---------------+     +------------------+     +---------+
     |                                       ^                     |
     |  signs manifest digest                | allow / block       | executes
     |  (Sigstore / RHTAS bundle)            | (fail closed)       | skill
     +---------------------------------------+---------------------+
```

Trust boundaries crossed by a skill package:

- **Signer → distribution.** Content may be mirrored, archived, or edited in
  transit. The manifest digest detects any change to signed content.
- **Distribution → verifier.** The verifier consumes the skill directory plus
  the embedded `.skill-trust/` control files. It trusts only its configured
  trust roots (public Sigstore or RHTAS), never self-asserted claims in the
  package. The optional verification report is informational only.
- **Verifier → harness.** The verifier returns an allow/block decision with
  structured findings. The harness must treat block as final.
- **Harness → execution.** The harness associates execution with the verified
  digest and re-verifies if content changed. This boundary is where the model
  is strongest or weakest, depending entirely on adapter discipline.

## Attacker model

The attacker may:

- modify, add, delete, or rename files in a skill directory after signing;
- modify, remove, or forge `.skill-trust/` control files;
- replay an old, valid signature over new content (digest substitution);
- present a valid signature made by an *unrelated* signer;
- tamper with the manifest digest embedded in a bundle;
- modify content between verification and execution (time-of-check to
  time-of-use);
- reconfigure the harness to skip verification.

The attacker is assumed **not** to:

- break SHA-256 or the signature scheme;
- compromise the organization's trust roots (Fulcio/RHTAS keys, TUF root) —
  compromise of a trust root is a catastrophic event handled by rotation
  procedures, not by this format;
- control the machine running the verifier (a compromised host can tamper
  with the verifier itself).

## Threat catalog

| # | Threat | Detection / mitigation | Residual risk |
|---|--------|------------------------|---------------|
| T1 | Signed file modified after signing | Manifest digest mismatch → block | None within format |
| T2 | File added, deleted, or renamed | Manifest covers every entry outside `.skill-trust/` → mismatch → block | None within format |
| T3 | Executable bit flipped | Executable bits are signed → mismatch → block | None within format |
| T4 | Symlink or special file substituted for a regular file | v1 rejects symlinks and special entries at manifest time → block | Later format versions must restate this rule |
| T5 | `.skill-trust/` control files altered or removed | Verifier requires present, well-formed, matching metadata; bundle signature covers the manifest → block | A second, attacker-controlled control directory is not allowed to create a second trust decision |
| T6 | Valid signature from untrusted signer replayed onto modified skill | Digest mismatch → block; if content unchanged but signer untrusted, policy fails → block | None within format |
| T7 | Old signature replayed over rolled-back content | Digest binds content exactly; rollback of content → digest mismatch unless the old content is identical | Availability of "same bytes, old signature" is indistinguishable from re-verification and is not a compromise of integrity |
| T8 | Content changed between verification and execution (TOCTOU) | Harness preflight contract requires re-verification before skill-associated execution and digest association | An adapter that verifies once and never re-checks is out of conformance |
| T9 | Harness bypasses the verifier | Out of scope: the verifier is authoritative only when used; documented as a hard boundary | Explicitly accepted; enforcement is a harness property |
| T10 | Compromised signer identity (stole a workflow or key) | Transparency log makes the abuse discoverable; policy rotation/revocation withdraws authorization | Detection is operational, not cryptographic |
| T11 | Malicious but properly signed skill | Out of scope for signatures; needs content review, scanning, sandboxing | Explicitly accepted |
| T12 | Prompt injection in signed instructions | Out of scope; needs runtime isolation and permission controls | Explicitly accepted |
| T13 | Verifier misconfiguration (e.g., trust-everything policy) | Policy format supports only explicit allow lists; missing evidence blocks by default; documented fail-closed defaults | Operator error remains possible |
| T14 | Compromised trust root | Out of scope; handled by rotation and re-signing procedures | Explicitly accepted |

## Enforcement boundary and fail-closed

`skill-trust` is a file-format and verification system. **A signature is
enforced only by a harness that calls the verifier and obeys the decision.**
An arbitrary agent runtime that loads skill directories without verification
cannot be forced to honor a signature, and nothing in this project claims
otherwise.

Conforming harness adapters must:

1. call the verifier before reading `SKILL.md` or executing any skill file;
2. treat a block decision, a verification error, and missing verification
   material identically: do not load, do not execute;
3. re-verify when skill content changes across a process boundary or reload;
4. surface structured block reasons to operators (expected and observed
   digests, failing check).

This is the **fail-closed requirement**: absent a positive allow decision
produced by a policy-compliant verification, the skill is untrusted.

## Composition with other controls

`skill-trust` is one layer. A complete deployment composes it with:

- **Static analysis / malware scanning** of skill content before signing;
- **Runtime isolation** (sandboxing, containers) for script execution;
- **Host permission systems** (the harness's tool permission model) to bound
  what a skill can touch;
- **Secret management** so skills never hold long-lived credentials;
- **Log monitoring** of transparency logs for unexpected signing events.

The signature gives these controls a stable, verifiable content identity to
bind decisions to: "the skill whose manifest digest is X". Without it, every
other control operates on unstable, unverifiable input.

## Residual risks

- A conforming harness can still be misconfigured to use a permissive policy.
- Transparency log evidence proves inclusion, not good intent.
- Offline verification is only as current as the locally cached trust
  material; organizations must plan trust-root refresh (see the rotation
  guidance).
- The first release rejects symlinks and special files rather than
  defining semantics for them, which trades expressiveness for safety.

## References

- [Architecture and enforcement design](ARCHITECTURE.md)
- [Canonical manifest specification](MANIFEST.md)
- [Verification policy](POLICY.md)
- [Sigstore security model](https://docs.sigstore.dev/about/security/)
- [Sigstore threat model](https://docs.sigstore.dev/about/threat-model/)
