# skill-trust CI signing material

This directory holds the signing material used by the repository's own
pull-request verification workflow (`.github/workflows/verify-pr.yml`).

- `demo-signing.key` / `demo-signing.pub` — a P-256 key pair that seals the
  committed skill fixtures under `skills/`.
- `pr-policy.json` — the policy the PR workflow verifies against.
- `release-policy.json` — the consumer policy for released skill assets:
  keyless signatures produced by the `release-sign` workflow on tags `v*`,
  on public Sigstore, with a transparency log entry required. The same file
  is shipped with each release. See [docs/RELEASE.md](../../docs/RELEASE.md).

**The private key is committed on purpose.** It is a tamper seal for CI, not
a trust root: anyone with repository write access could re-sign content, so
it proves only that a change was accompanied by a deliberate re-sign, not
that a trusted signer produced it. This keeps the reference setup fully
self-contained and reproducible.

Production deployments must not commit private keys. Hold signing keys in a
trusted release workflow (keyless with GitHub OIDC) or in a KMS/HSM, and let
contributors request signing through that workflow. See
`docs/POLICY.md` and the `e2e-sign` workflow for keyless signing against
public Sigstore and RHTAS.

## Re-signing after a content change

After changing any file under `skills/`, re-sign the skill and commit the
updated `.skill-trust/` control files together with your change:

```console
$ go build -o skill-trust ./cmd/skill-trust   # or install a release binary
$ skill-trust sign skills/demo-skill --key .github/skill-trust/demo-signing.key
$ git add skills/demo-skill
```

The PR workflow fails with `ST-CONTENT-MISMATCH` when content changes
without a replacement signature.
