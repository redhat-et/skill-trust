# Organization policy examples

Four worked policies for common enterprise cases. Every example has a
machine-checked passing **and** failing fixture
([`suite.json`](suite.json), run by `pkg/verify` in CI), so these cannot
drift from actual behavior. Policy syntax is documented in
[docs/POLICY.md](../../docs/POLICY.md); rotation and withdrawal guidance
in [docs/LIFECYCLE.md](../../docs/LIFECYCLE.md).

| Example | Trusts | Use when |
|---------|--------|----------|
| [`rhtas-signer.json`](rhtas-signer.json) | One exact workflow identity, signed keyless through your RHTAS instance (pinned root, issuer, provenance, transparency log) | You want the narrowest anchor: one signer, one deployment |
| [`github-repository.json`](github-repository.json) | Any workflow of one repository on `refs/heads/main`, through RHTAS | Skills are produced by many workflows of one repo |
| [`offline-key.json`](offline-key.json) | A pinned public key; no log, timestamp, or network use at verify time | Air-gapped or registry-free verification |
| [`mixed-trust.json`](mixed-trust.json) | Both of the above anchors | Signer rotation: old and new signatures verify during the transition |

Unsigned and unknown skills fail closed under **every** policy — the
unsigned cases in `suite.json` demonstrate the defined result
(`ST-METADATA-MISSING`), which precedes signer evaluation entirely.

## Running the examples

```console
$ skill-trust verify testdata/fixtures/cross-root-rhtas --policy examples/policy/github-repository.json
ALLOW testdata/fixtures/cross-root-rhtas
  signer:  rule "repo-workflows" (keyless identity .../e2e-sign.yml@refs/heads/main, ...)
```

Policies reference trust material by repository-root-relative paths, so
run from the repository root. To adapt an example, replace:

- the `trustRoots` path with your instance's trusted root
  ([docs/RHTAS.md](../../docs/RHTAS.md) explains exporting it), or use
  `{"type": "sigstore-public"}` for public Sigstore;
- the identity (or `identityRegexp`) with your signing workflow's OIDC
  identity — for tag-based release signing, pin `@refs/tags/v` shapes as
  [`.github/skill-trust/release-policy.json`](../../.github/skill-trust/release-policy.json)
  does;
- the public key path with your own key.

## The suite

`suite.json` maps each policy to committed fixtures under
[`testdata/fixtures/`](../../testdata/fixtures/) with expected results,
including the failing cases: wrong signature type
(`ST-POLICY-NO-MATCH`), tampered content (`ST-CONTENT-MISMATCH`), and
unsigned skills (`ST-METADATA-MISSING`). The test additionally asserts
every policy file in this directory has at least one passing and one
failing case, so adding a new example requires adding its fixtures.
