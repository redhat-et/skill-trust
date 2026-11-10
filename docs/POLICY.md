# skill-trust verification policy

This document defines the organization verification policy: the inputs and
evaluation semantics that turn a cryptographically valid signature into an
**allow** or **block** decision.

Policy evaluation is a separate stage from manifest generation and from
cryptographic verification. The pipeline is:

```text
skill directory ──► manifest recomputation ──► bundle verification ──► policy evaluation ──► allow / block
                    (content identity)         (cryptography)          (authorization)
```

Each stage fails independently and fail-closed. A policy never changes how a
manifest is computed and never relaxes cryptographic checks; it only decides
which valid signatures are acceptable.

## Policy file

A policy is a JSON document:

```json
{
  "apiVersion": "skill-trust.policy/v1",
  "name": "example-org-release",
  "trustRoots": {
    "sigstore": { "type": "sigstore-public" },
    "rhtas": { "type": "trusted-root", "path": "trust/rhtas-trusted-root.json" }
  },
  "signers": [
    {
      "name": "release-workflow",
      "mode": "keyless",
      "certificate": {
        "identities": [
          "https://github.com/example-org/skills/.github/workflows/sign-release.yml@refs/heads/main"
        ],
        "issuer": "https://token.actions.githubusercontent.com"
      },
      "trustRoot": "sigstore",
      "requireTransparencyLog": true
    },
    {
      "name": "rhtas-release-workflow",
      "mode": "keyless",
      "certificate": {
        "identityRegexp": "^https://github.com/example-org/.+/.github/workflows/.+@refs/tags/v[0-9.]+$",
        "issuer": "https://token.actions.githubusercontent.com"
      },
      "trustRoot": "rhtas",
      "requireTransparencyLog": true
    },
    {
      "name": "release-key",
      "mode": "key",
      "publicKey": { "path": "trust/release.pub" },
      "trustRoot": "rhtas",
      "requireTransparencyLog": true
    }
  ],
  "defaults": {
    "requireTransparencyLog": true,
    "requireSignedTimestamps": false,
    "maxSignatureAge": "0s"
  }
}
```

## Trust roots

Trust roots are named in `trustRoots` and referenced by signers. Supported
types:

| Type | Meaning |
|------|---------|
| `sigstore-public` | The public Sigstore good instance (Fulcio, Rekor, TSA). Default test configuration. |
| `trusted-root` | A Sigstore `TrustedRoot` JSON document, as published by an RHTAS TUF server. Selects organization Fulcio/Rekor/CT/TSA endpoints without changing the skill format. |
| `ca` | PEM certificate authority bundle (direct Fulcio-style roots for private deployments). |
| `key` | Raw public keys for key-based verification. |

Trust material is loaded from local files or the embedded public Sigstore
root. Verification of a distributed bundle is offline-capable: inclusion
proofs, certificates, and RFC 3161 timestamps carried in the bundle are
verified against the configured trust material without contacting Fulcio,
Rekor, or the TSA at execution time.

## Signer rules

A signer rule constrains who may sign. Two modes exist:

### Keyless signers

`mode: "keyless"` matches signatures whose verification material is a
certificate issued by the configured trust root's certificate authority:

- `certificate.identities` — exact Subject Alternative Name values (email,
  URI, or DNS) accepted for this signer. Exactly one must match.
- `certificate.identityRegexp` — RE2 alternative to `identities`. Either
  `identities` or `identityRegexp` must be present, never both.
- `certificate.issuer` — the exact OIDC issuer recorded in the certificate
  (for example `https://token.actions.githubusercontent.com`).
- `certificate.issuerRegexp` — RE2 alternative to `issuer`.

### Key-based signers

`mode: "key"` matches signatures whose verification material is a public key
hint. The hint is compared against the configured public key's identifier.
A key-based signer rule must provide the expected public key:

- `publicKey.path` — PEM public key file, or
- `publicKey.raw` — inline base64 PEM.

### Provenance constraints

Both modes may add optional provenance constraints evaluated against
certificate extensions (when present):

- `provenance.sourceRepository` — GitHub repository claim.
- `provenance.sourceRef` — git ref claim.
- `provenance.workflowName` — workflow file name claim.
- `provenance.commitSha` — commit SHA claim.

Constraints are compared for equality. A certificate that lacks a constrained
claim fails the rule. Key-based signatures cannot satisfy provenance
constraints (there is no certificate); rules that combine both block.

### Evidence requirements

Per-signer evidence knobs:

- `requireTransparencyLog` (default `true`) — the bundle must carry a valid,
  offline-verifiable inclusion proof from a transparency log trusted by the
  signer's trust root. `false` accepts bundles without log evidence (logged
  with a warning finding; useful for pre-production).
- `requireSignedTimestamps` (default `false`) — the bundle must carry an
  RFC 3161 timestamp from a trusted TSA.
- `maxSignatureAge` (default `0s`, meaning no limit) — reject signatures
  whose evidence is older than the limit. Requires timestamps or log
  integration times.

## Evaluation semantics

Verification of a skill produces an allow decision only when **every** stage
passes:

1. **Content** — the recomputed manifest matches the embedded manifest
   byte-for-byte.
2. **Cryptography** — at least one signature in the bundle verifies against
   the trust material, including any required transparency log and timestamp
   evidence.
3. **Authorization** — that same signature matches at least one signer rule
   in the policy, under the trust root configured for that rule.

Rules for multiple signatures:

- A package may carry multiple signatures. **One policy-compliant, valid
  signature is sufficient** for an allow decision.
- Every discovered signature is evaluated and reported with its own result
  and findings; the overall decision is the only allow/block signal.
- Signatures that fail cryptography or policy do not downgrade an otherwise
  compliant signature, but they are always reported.

Failure semantics (all block, none warn-only):

- no policy supplied;
- policy is malformed, references an unknown trust root, or a signer rule is
  contradictory (for example both `identities` and `identityRegexp`);
- the embedded manifest or bundle is missing, malformed, or duplicated;
- the recomputed manifest does not match the embedded manifest;
- no signature verifies cryptographically;
- no *valid* signature matches any signer rule;
- required evidence (transparency log, timestamp) is missing or unverifiable;
- trust material is unavailable or untrusted.

There is no "unknown signer: allow anyway" mode. Missing or unverifiable
evidence blocks by default.

## Findings

Policy evaluation returns structured findings alongside the decision:

| Field | Meaning |
|-------|---------|
| `decision` | `allow` or `block` |
| `manifestDigest` | expected content identity (SHA-256 of the canonical manifest) |
| `observedDigest` | recomputed digest; differs from expected on tamper |
| `signatureResults[]` | per-signature: verifier mode, signer identity, issuer, matched rule name, evidence checks, pass/fail |
| `findings[]` | machine-readable codes (see below) with human-readable messages |

Machine-readable finding codes (stable, prefixed `ST-`):

- `ST-POLICY-MALFORMED` — policy could not be parsed or validated
- `ST-POLICY-NO-MATCH` — valid signature matched no signer rule
- `ST-POLICY-NO-SIGNERS` — policy defines no usable signer rules
- `ST-CONTENT-MISMATCH` — recomputed manifest differs from embedded manifest
- `ST-CONTENT-INVALID` — skill directory violates package rules (missing `SKILL.md`, symlink, special file)
- `ST-METADATA-MISSING` / `ST-METADATA-MALFORMED` — control files absent or unparseable
- `ST-SIGNATURE-INVALID` — cryptographic verification failed
- `ST-EVIDENCE-TLOG-MISSING` / `ST-EVIDENCE-TLOG-INVALID` — transparency evidence absent or failed
- `ST-EVIDENCE-TSA-MISSING` / `ST-EVIDENCE-TSA-INVALID` — timestamp evidence absent or failed
- `ST-EVIDENCE-STALE` — signature older than `maxSignatureAge`
- `ST-TRUST-UNAVAILABLE` — trust material missing or untrusted
- `ST-PROVENANCE-MISMATCH` — certificate claims did not satisfy provenance constraints

## Separation of concerns

- **Manifest generation** is a pure function of the directory contents. It
  never reads the policy.
- **Bundle verification** checks signatures against trust material. It knows
  certificate validity, key equality, and inclusion proofs. It does not know
  organizational rules.
- **Policy evaluation** consumes verification results and decides
  authorization. It performs no cryptography.

The stages are independently callable as library functions, which is what
makes the harness preflight contract possible without re-implementing any
stage.

## Examples

Example policies for common enterprise cases — public Sigstore workflow
identity, RHTAS issuer and identity, offline-only key verification, and
default-deny — will be maintained in `examples/policy/` with one passing and
one failing fixture each (backlog issue #18).

## References

- [Threat model](THREAT-MODEL.md)
- [Architecture](ARCHITECTURE.md)
- [Canonical manifest specification](MANIFEST.md)
