# Release signing

This document describes how approved skills are signed and published by the
[`release-sign`](../.github/workflows/release-sign.yml) workflow, and how
consumers verify released assets.

## Trust model

Signing is **keyless**: the signer is the GitHub Actions workflow itself,
authenticated by GitHub's OIDC token service. There is no private key to
store or rotate; the signature's identity is cryptographically bound to:

- the **issuer** `https://token.actions.githubusercontent.com`;
- the **identity** (OIDC `sub` claim)
  `https://github.com/redhat-et/skill-trust/.github/workflows/release-sign.yml@<ref>`,
  where `<ref>` is the git ref the workflow ran on;
- the **provenance** claims `sourceRepository=redhat-et/skill-trust` and
  `workflowName=release-sign`;
- a **transparency log entry** (Rekor) with an offline-verifiable inclusion
  proof, required by the policy.

### Where signing may run from

- **Tag pushes** (`v*`): the real release path. The workflow signs, proves
  the signature against the consumer policy, and publishes a GitHub release.
- **`workflow_dispatch` from `main`**: a dry run. It signs and verifies but
  publishes no release. Its signature carries the `refs/heads/main`
  identity, which the consumer policy **rejects by design** — only tag
  identities are trusted.
- The job runs in the `release` **environment**. Maintain protection there
  (repository settings → environments → release): require reviewers and
  restrict deployments to tags matching `v*`, so that publishing a release
  needs explicit approval.
- A runtime guard refuses to sign from any other ref or event.

## Targets: public Sigstore and RHTAS

The signing deployment is selected by the `TARGET` setting:

- `public` (default) — public Sigstore (Fulcio, Rekor, TSA at
  `*.sigstore.dev`). The consumer policy is the committed
  [`.github/skill-trust/release-policy.json`](../.github/skill-trust/release-policy.json).
- `rhtas` — an organization's RHTAS instance (Fulcio, Rekor, TSA behind the
  trusted root in `pkg/trust/testdata/rhtas-trusted-root.json`). The
  consumer policy is generated at release time with the same identity
  constraints and the RHTAS trust root.

Tag pushes read the target from the `SKILL_TRUST_SIGNING_TARGET` repository
variable (falling back to `public`); dispatch runs choose it as an input.
Switching deployments changes configuration, not the skill package format.

## Release assets

Each skill under `skills/` is signed and published as:

| Asset | Meaning |
|-------|---------|
| `<skill>.tar.gz` | the skill package: content plus `.skill-trust/` control files and the verification report |
| `<skill>.manifest.json` | the canonical manifest; its SHA-256 is the signed subject |
| `<skill>.bundle.sigstore.json` | the Sigstore bundle (keyless certificate, signature, transparency log entry) |
| `<skill>.report.json` | the verification report produced by the release workflow |
| `release-policy.json` | the consumer policy for these assets |

The release workflow itself verifies each skill twice before publishing:
once against an exact-identity runtime policy (this run's ref, issuer,
provenance, transparency log) and once against the shipped consumer policy
(tag identities only).

## Verifying a release

```console
$ # from a release page, download <skill>.tar.gz and release-policy.json
$ tar -xzf demo-skill.tar.gz
$ skill-trust verify demo-skill --policy release-policy.json
allow: manifest digest 9a360f71... signed by release workflow
```

Verification recomputes the manifest from the extracted content, so a
modified or partial download fails closed. Executable bits are preserved by
`tar`; extract with `tar -xzf` (or `tar -xpzf` on platforms that apply a
restrictive umask).

## Releasing

Before creating a release tag:

1. Update `adapters/claude-code/.claude-plugin/plugin.json` `version` field to
   match the tag version (without the `v` prefix). For example, for tag
   `v0.2.0`, the plugin version should be `0.2.0`.
2. The `release-sign` workflow enforces this lockstep on tag pushes: it runs
   `go test ./internal/claudecode -run '^TestPluginVersionMatchesTag$'` with
   `SKILL_TRUST_REQUIRE_TAG_CHECK=1` and fails before signing if the plugin
   version does not match the tag, if the tag environment is missing, or if
   the test did not run at all. You can run the same check locally:

   ```console
   $ GITHUB_REF_TYPE=tag GITHUB_REF_NAME=v0.2.0 SKILL_TRUST_REQUIRE_TAG_CHECK=1 \
       go test ./internal/claudecode -run '^TestPluginVersionMatchesTag$' -v
   ```

Then tag and push:

```console
$ git tag v0.1.0
$ git push origin v0.1.0
```

The workflow signs `skills/*`, publishes the assets to a GitHub release
named after the tag, and attaches the verification summary to the run.

To test without publishing, run the workflow via `workflow_dispatch` from
`main` (optionally with the RHTAS target); evidence lands in the run's
artifacts and no release is created.

## What a signature does and does not prove

A valid release signature proves: the content is exactly what the
`release-sign` workflow signed, on a `v*` tag of this repository, recorded
in the transparency log. It does **not** prove the content is useful or
safe — that is the maintainers' review, which the `release` environment's
protection rules can enforce. See the
[threat model](THREAT-MODEL.md).
