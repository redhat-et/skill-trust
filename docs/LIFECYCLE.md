# Signer rotation, trust-root updates, and withdrawal

How an organization handles signer changes, trust-root updates, and
withdrawn skills over the lifetime of a skill-trust deployment. The rule
that makes all of this safe: **verification is offline and policy-driven**
— nothing about rotation requires contacting a service at verify time.

## Validity is not authorization

Every verification separates two questions:

1. **Cryptographic validity** — do the verified bytes match the signed
   manifest, does the signature verify, does the certificate chain to a
   trust root, are the recorded claims (identity, issuer, provenance)
   consistent, and is the evidence present (transparency log entry,
   timestamps)?
2. **Current authorization** — does *today's policy* accept that signer,
   that trust root, and evidence within the required bounds?

The verify result keeps these apart: `signatures[]` reports per-rule
matching with per-rule findings (validity and rule fit), while the overall
decision requires a rule to *fully* match. A signature can be — and after
an incident, should be — cryptographically valid and still blocked:

```json
{
  "decision": "block",
  "findings": [{"code": "ST-POLICY-NO-MATCH",
                "message": "the signature did not fully match any signer rule"}],
  "signatures": [{"matched": false,
                  "findings": [{"code": "ST-SIGNATURE-INVALID", "...": "..."}]}]
}
```

Rotation and revocation are therefore **policy operations**, not protocol
operations. Nothing is rewritten on the skill package; the package keeps
proving exactly what it always proved (who signed it, what bytes, when),
and the organization changes what it is willing to run.

## Defined verification results for stale or withdrawn trust

| Situation | Result | Finding code |
|-----------|--------|--------------|
| Signer no longer matches any rule (rotated away, withdrawn) | block | `ST-POLICY-NO-MATCH` |
| Signature older than the policy's freshness window | block | `ST-EVIDENCE-STALE` |
| Policy requires a transparency log entry the bundle lacks | block | `ST-EVIDENCE-TLOG-MISSING` |
| Policy requires an RFC 3161 timestamp the bundle lacks | block | `ST-EVIDENCE-TSA-MISSING` |
| Signature chains to a trust root the policy does not pin (root rotated) | block | `ST-SIGNATURE-INVALID` |
| Identity or issuer claims do not satisfy the rule | block | `ST-SIGNATURE-INVALID` |
| Content changed after signing | block | `ST-CONTENT-MISMATCH` |
| No control files at all | block | `ST-METADATA-MISSING` |

Each of these is exercised by committed fixtures:
[`testdata/fixtures/expected.json`](../testdata/fixtures/expected.json)
(content and metadata failures) and
[`testdata/fixtures/cross-root.json`](../testdata/fixtures/cross-root.json)
(wrong root, wrong identity, modified content, and stale evidence — the
`rhtas-bundle-stale-evidence` case pins `ST-EVIDENCE-STALE` with a
`maxSignatureAge` of one second against a bundle that only ever gets
older).

## Inspectable, not executable

A rejected package is never mutated, deleted, or hidden:

- `skill-trust inspect <dir>` works **without any policy**. It reports the
  recomputed manifest, whether content matches, and the bundle's signer
  identity — useful for incident response and archival.
- `skill-trust verify` blocks with the machine-readable findings above.
- Harness adapters fail closed: the OpenCode adapter removes rejected
  skills from the registry and blocks their execution paths
  (`ST-PREFLIGHT-*`); the GitHub Action exits non-zero.
- Released archives (see [RELEASE.md](RELEASE.md)) remain downloadable and
  inspectable; consumers' policies decide executability.

## Rotating a keyless (workflow) signer

Keyless signers are identified by their OIDC identity
(`...workflows/<file>.yml@<ref>`), so rotation is a workflow/policy change:

1. **Rename or replace the signing workflow** (or move from branch to tag
   signing, as [`release-sign`](../.github/workflows/release-sign.yml)
   does). New signatures carry the new identity.
2. **Update the policy's signer rule** — exact `identities`, or an
   `identityRegexp` that matches the new form (for example
   `...release-sign\.yml@refs/tags/v`). Until then, new signatures block
   with `ST-POLICY-NO-MATCH` — fail closed.
3. **For a transition window**, keep both rules: policies are lists, and a
   signature matching *any* rule is allowed. Old and new signatures
   verify simultaneously.
4. **Withdraw the old rule** when no consumer needs the old signatures.
   Old packages stay inspectable; they stop executing everywhere that
   policy is enforced.

## Rotating a key-based signer

1. Generate the new key pair (`skill-trust keygen` or your KMS).
2. **Add** a second signer rule for the new public key alongside the old
   one — both verify during the transition.
3. Re-sign skills as they are republished; each package carries exactly
   one bundle, so a re-signed skill is simply a new package version.
4. Remove the old rule when the transition is complete. Packages still
   carrying the old signature block with `ST-POLICY-NO-MATCH` but remain
   inspectable.

## Updating a trust root

- **RHTAS**: the instance's Fulcio CA is what consumers pin. When it
  rotates, export the new trusted root from the instance's TUF server and
  swap the `path`/`content` in the policy's `trustRoots` (see
  [RHTAS.md](RHTAS.md)). Bundles signed by the old CA then block with
  `ST-SIGNATURE-INVALID` (chain no longer trusted). Committed fixtures
  pin era-specific roots deliberately —
  `testdata/fixtures/rhtas-trusted-root.json` matches the era of the
  captured bundle and is *not* refreshed when the live instance rotates;
  re-capture both together when you intentionally move eras.
- **Public Sigstore**: the trusted root is embedded at build time via
  TUF; rebuilding the binary refreshes it. Pin explicit
  `trusted-root` files instead when you need long-horizon stability for
  archived bundles.
- A trust-root update never changes the skill package format. It is a
  configuration change (see [TRUST-CONFIG.md](TRUST-CONFIG.md)).

## Withdrawing a skill

There is no revocation registry in v1, by design: verification is offline,
and transparency logs are append-only records of what was signed —
accountability, not revocation. Withdrawal combines the tools above:

- **Withdraw the signer** (remove or narrow its rule) — the strongest
  form; everything that signer ever signed stops executing under that
  policy.
- **Bound trust in time** (`maxSignatureAge`): require re-signing (for
  example, weekly) so authorization lapses unless actively renewed. The
  stale result is `ST-EVIDENCE-STALE`.
- **Require evidence** (`requireTransparencyLog`, timestamps): signatures
  must be publicly recorded, giving auditable history of what a signer
  produced even after withdrawal.
- **Pin provenance** (`sourceRepository`, workflow name, ref shape) so a
  compromised signer cannot silently widen what it signs.

For an incident where content must be withdrawn *now*: update the policy
(the release consumer policy is shipped with every release — publish a new
one), and rely on the fact that every consumer's adapter re-verifies on
load and on execution. There is no cached "once verified, always trusted"
state anywhere in the system.
