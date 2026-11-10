# Signed skill fixtures

A committed, signed fixture suite with expected verification results,
exercising the complete signed boundary.

## Layout

- `valid-complete/` — a skill covering Markdown instructions, Bash,
  Python, and JavaScript helpers, references, assets, a hidden file, and
  executable bits, signed with the fixtures key.
- `fixtures.key` / `fixtures.pub` — the P-256 test signing pair. This is
  **test material with no trust meaning**: it exists only to make the
  committed signature reproducible. Nothing outside these tests trusts it.
- `policy.json` — the policy the suite verifies against (key-based, no
  transparency log: the fixture signature is offline by design).
- `expected.json` — machine-readable expected results: the golden
  manifest digest and one case per mutation class (content changes across
  every file category, added / deleted / renamed files, executable-bit
  flips in both directions, control-file removal, and an embedded-manifest
  forgery).
- `cross-root-rhtas/` — a bundle signed keyless against the shared RHTAS
  instance (captured from a CI `e2e-sign` run), with
  `rhtas-trusted-root.json` pinned to the instance era that signed it.
- `policy-rhtas.json`, `policy-public.json`,
  `policy-rhtas-wrong-identity.json`, `policy-rhtas-stale.json` — pinned
  policies for the cross-root suite (`cross-root.json`), which proves the
  RHTAS bundle verifies offline against the right root and fails closed
  against the wrong trust root, the wrong signer identity, modified
  content, and stale evidence (`maxSignatureAge` exceeded — deterministic,
  since the committed bundle only gets older).

`pkg/verify/fixtures_test.go` copies `valid-complete` (or
`cross-root-rhtas`), applies each mutation, and asserts the documented
decision and finding code. The golden
digest is recomputed from the checked-out bytes, so the test vectors prove
manifest stability across platforms: the suite runs on Linux and macOS
runners in CI (`ci.yml`), and any platform difference in content digests
or executable bits fails the golden check.

## Payload safety

Fixtures contain no real secrets and no harmful payloads. Helpers only
print fixed strings; `TestFixturePayloadsAreSafe` fails the suite if a
fixture gains network, subprocess, environment, or destructive calls.

## Regenerating

After intentionally changing `valid-complete` (content or modes):

```console
$ go build -o skill-trust ./cmd/skill-trust
$ skill-trust sign testdata/fixtures/valid-complete --key testdata/fixtures/fixtures.key
$ skill-trust manifest testdata/fixtures/valid-complete   # new golden digest
```

Update `manifestDigest` in `expected.json` to the new digest. Do not
change fixture content without re-signing — the suite fails closed, which
is the point.
