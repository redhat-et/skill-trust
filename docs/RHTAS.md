# RHTAS operator guide

How to run skill-trust against [Red Hat Trusted Artifact
Signer](https://github.com/securesign) (RHTAS): a Sigstore-compatible stack
of Fulcio (certificate authority), Rekor (transparency log), and a timestamp
authority, fronted by TUF for trust material distribution. This guide covers
obtaining an instance, extracting its trust material, signing and verifying
with it, and running the project's RHTAS test suites.

The configuration model itself (trust roots vs. services, policy wiring)
is documented in [TRUST-CONFIG.md](TRUST-CONFIG.md); this guide is the
operational companion.

## What you need from an RHTAS instance

| Input | Where it comes from | Used for |
|-------|--------------------|---------|
| Fulcio URL | the instance's Fulcio route | signing (keyless certificates) |
| Rekor URL | the instance's Rekor route | signing (transparency log entries) |
| TSA URL | the instance's timestamp route | signing (RFC 3161 timestamps) |
| Trusted root JSON | the instance's TUF server | verification (offline, pinned) |

The reference instance used by this project's CI (namespace
`skill-trust-rhtas`) exposes, as OpenShift edge-TLS routes:

```text
https://fulcio-server-skill-trust-rhtas.apps.claws.bxz4.p1.openshiftapps.com
https://rekor-server-skill-trust-rhtas.apps.claws.bxz4.p1.openshiftapps.com
https://tsa-server-skill-trust-rhtas.apps.claws.bxz4.p1.openshiftapps.com/api/v1/timestamp
```

### Running your own instance

Install the RHTAS operator on an OpenShift cluster and create a
`TrustedArtifactSigner` custom resource; the operator deploys Fulcio, Rekor,
the TSA, and TUF, and exposes each as a route. After it settles:

1. Collect the route URLs above (`oc get routes -n <namespace>`).
2. Export the trusted root from the instance's TUF server (see
   [TRUST-CONFIG.md](TRUST-CONFIG.md) for the one-liner) and commit it next
   to your policies. This project pins its copy at
   `pkg/trust/testdata/rhtas-trusted-root.json` and mirrors it (pinned to
   the era of the committed fixture bundle) at
   `testdata/fixtures/rhtas-trusted-root.json`.
3. Decide who may sign: with RHTAS the signer identity is still an OIDC
   identity, so pin the workflow identities in your policies (below).

No OCI registry is involved at any point: skills are directories, signing
is Fulcio/Rekor, and distribution is files or release assets.

## Signing against RHTAS

`skill-trust sign --id-token github --services services.json` with:

```json
{
  "name": "rhtas",
  "fulcioURL": "https://fulcio-server-<instance>.apps.example.com",
  "rekorURL": "https://rekor-server-<instance>.apps.example.com",
  "tsaURL": "https://tsa-server-<instance>.apps.example.com/api/v1/timestamp",
  "oidcIssuer": "https://token.actions.githubusercontent.com",
  "trustedRootPath": "pkg/trust/testdata/rhtas-trusted-root.json"
}
```

`trustedRootPath` makes the signer self-verify its output before returning.
Signing requires `id-token: write` in CI (GitHub OIDC); the resulting bundle
carries the RHTAS Fulcio certificate chain, identity claims, and a Rekor
entry with an offline-verifiable inclusion proof.

## Verifying against RHTAS

Verification is fully offline — it needs the trusted root and the policy,
never the live instance. Pin the instance's root and the signer identities:

```json
{
  "apiVersion": "skill-trust.policy/v1",
  "trustRoots": {
    "rhtas": {"type": "trusted-root", "path": "rhtas-trusted-root.json"}
  },
  "signers": [
    {
      "name": "release-workflow",
      "mode": "keyless",
      "certificate": {
        "identityRegexp": "^https://github\\.com/<org>/<repo>/\\.github/workflows/<workflow>\\.yml@refs/tags/v",
        "issuer": "https://token.actions.githubusercontent.com"
      },
      "provenance": {"sourceRepository": "<org>/<repo>"},
      "trustRoot": "rhtas",
      "requireTransparencyLog": true
    }
  ]
}
```

```console
$ skill-trust verify my-skill --policy rhtas-policy.json
```

Because verification recomputes the manifest from the directory, an RHTAS
bundle verifies the same way on a laptop, in CI, and inside a harness
adapter — the shared `pkg/trust/testdata/rhtas-trusted-root.json` is the
only instance-specific input.

## Test suites that exercise RHTAS

| Suite | Where | What it proves |
|-------|-------|----------------|
| `e2e-sign` (RHTAS job) | [`.github/workflows/e2e-sign.yml`](../.github/workflows/e2e-sign.yml) | signs a disposable fixture keyless against the shared instance with GitHub OIDC, verifies with a pinned policy (tlog required), proves tampering blocks, and runs the reusable action with RHTAS trust material |
| `release-sign` (`rhtas` target) | [`.github/workflows/release-sign.yml`](../.github/workflows/release-sign.yml) | the full release flow against RHTAS (dispatch dry run) |
| Cross-root fixtures | [`testdata/fixtures/cross-root.json`](../testdata/fixtures/cross-root.json) | a captured RHTAS-signed bundle verifies offline with the local binary against the pinned root, and **fails closed** against the wrong trust root, the wrong signer identity, or modified content |

The cross-root fixtures run on every platform in `ci.yml` with no network
access: they pin the trusted root to the era of the committed bundle, so
they keep proving the failure modes even if the live instance rotates its
CA. Refresh them (re-capture a bundle and update the mirrored root) when
you intentionally rotate the instance.

## Capturing a fixture bundle from CI

```console
$ gh run download <e2e-sign run id> --name rhtas-evidence -r <owner>/<repo>
```

The artifact contains `demo-skill/.skill-trust/` (manifest + bundle) plus
sign/verify results. See `testdata/fixtures/cross-root.json` for the exact
content reconstruction and expected results.

## Troubleshooting

- **`ST-SIGNATURE-INVALID` with a certificate-chain error**: the policy's
  trusted root does not match the instance that signed the bundle (wrong
  root file, or the instance rotated its CA). Re-pin the root from the
  instance's TUF server.
- **`ST-POLICY-NO-MATCH` with an identity error**: the bundle's OIDC
  identity (workflow path @ ref) or issuer does not satisfy the signer
  rule. Check the identity in the bundle (`skill-trust inspect <dir>`)
  against the policy.
- **Signing fails with a token error**: the workflow lacks
  `id-token: write`, or the services' `oidcIssuer` does not match the
  runtime (GitHub Actions uses
  `https://token.actions.githubusercontent.com`).
- **Verification needs the network?** It does not. Only signing does. If
  offline verification fails, the trust material in the policy is stale or
  mismatched — not the network.
