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

`pkg/verify/fixtures_test.go` copies `valid-complete`, applies each
mutation, and asserts the documented decision and finding code. The golden
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
