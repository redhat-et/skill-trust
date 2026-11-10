# Signed skill package layout (v1)

This document specifies how a signed skill is packaged and distributed, and
how the `.skill-trust/` control directory behaves. It extends the
[architecture](ARCHITECTURE.md) and [manifest specification](MANIFEST.md)
with concrete layout and distribution rules.

## Layout

A signed skill is an ordinary Agent Skills directory plus a control
directory at its root:

```text
my-skill/
├── SKILL.md                      # required skill instructions
├── scripts/                      # executable helpers (Bash, Python, JS, ...)
├── references/
├── assets/
├── ...                           # any additional signed content
└── .skill-trust/                 # reserved control directory
    ├── manifest.json             # canonical manifest (v1)
    ├── bundle.sigstore.json      # Sigstore signature bundle
    └── report.json               # optional verification report
```

Everything outside `.skill-trust/` is signed content described by
`manifest.json`. The control directory itself is excluded from the manifest
to avoid a self-referential digest.

## Control files

### `.skill-trust/manifest.json`

The canonical serialization of the skill manifest, exactly as specified in
[MANIFEST.md](MANIFEST.md). The bytes on disk are the canonical bytes;
SHA-256 of this file is the manifest digest (the signed subject).

### `.skill-trust/bundle.sigstore.json`

A Sigstore bundle as defined by
[protobuf-specs](https://github.com/sigstore/protobuf-specs)
(`dev.sigstore.common.v1.Bundle`), serialized as JSON with media type:

```text
application/vnd.dev.sigstore.bundle.v0.3+json
```

The bundle carries a `messageSignature` whose `messageDigest` is the SHA-256
manifest digest, plus verification material:

- **keyless signatures**: the Fulcio (or RHTAS CA) certificate chain and
  identity claims, transparency log entries with offline-verifiable
  inclusion proofs, and optional RFC 3161 timestamps;
- **key-based signatures**: a public key identifier hint; the expected
  public key itself is supplied by the verifier's trust configuration, not
  by the package.

Bundles of this shape are produced by `skill-trust sign` and are
interoperable with upstream Sigstore tooling (verified with `cosign
sign-blob --bundle` / `cosign verify-blob --bundle --trusted-root`).

### `.skill-trust/report.json` (optional)

A human- and machine-readable record of the last verification: decision,
manifest digest, per-signature results, and findings. The report is
**informational only**. It is never trusted as verification input and its
presence, absence, or modification does not affect verification, because it
is not signed content and is not read to make decisions.

## Control directory rules

1. Only the root `.skill-trust/` is a control directory. A `.skill-trust`
   directory nested under any other path is ordinary signed content.
2. The verifier reads exactly three names: `manifest.json`,
   `bundle.sigstore.json`, and (informationally) `report.json`. Other files
   in the control directory are ignored — they neither extend nor weaken
   the signed boundary.
3. The verifier requires:
   - `manifest.json` present, parseable, structurally valid (v1, sha256,
     normalized sorted paths), and **identical** to the manifest recomputed
     from the directory contents;
   - `bundle.sigstore.json` present, parseable as a supported Sigstore
     bundle, with a signature over the recomputed manifest digest.
4. The verifier rejects:
   - **missing** metadata (either control file absent, or a directory entry
     where a file is expected);
   - **malformed** metadata (invalid JSON, wrong media type, unknown bundle
     or manifest version, structural violations such as unsorted or
     duplicate paths, absolute or `..` paths);
   - **duplicate** metadata (for example a `manifest.json/` directory
     shadowing the file, or multiple bundle files with the reserved name in
     different cases on case-insensitive filesystems);
   - **mismatched** metadata (embedded manifest differs from the recomputed
     manifest; bundle signature covers a different digest than the
     recomputed one).
5. A skill directory with no `.skill-trust/` directory is an unsigned
   skill: under any organization policy that requires signatures
   (the default), verification fails closed with a missing-metadata
   finding. The verifier never treats unsigned content as trusted.

## Distribution

Skills are distributed as directories or portable archives. No OCI registry
is required or used.

### Directory distribution

Copy, clone, or sync the skill directory. Verification recomputes the
manifest from the destination, so partial or modified copies fail closed.
Executable bits must be preserved by the copy mechanism.

### Archive distribution

An archive (`tar`, `zip`) of the skill directory must preserve:

- regular file contents;
- the executable bit (`tar` mode bits; extract with `tar -p` or equivalent);
- the `.skill-trust/` control files at the skill root.

Archive timestamps, ownership, and ordering are not part of skill identity
and may change freely. After extraction, verification behaves exactly as
for directory distribution.

### Out of scope: OCI artifacts

Skill packages are deliberately **not** OCI artifacts, images, or referrers.
The signed object is a filesystem directory, verified locally on a desktop,
a remote harness, or in CI with the same content identity. Registries may
of course *store* archives of skills as opaque blobs, but nothing in the
format depends on or integrates with OCI.

## Worked example

Using the shipped golden fixture:

```console
$ skill-trust manifest ./testdata/demo-skill
9a360f711d6d044b9a4de25c80cdf5035e9293e5d0845230231f7327324824d8

$ skill-trust sign ./testdata/demo-skill --key release.key
wrote .skill-trust/bundle.sigstore.json

$ skill-trust verify ./testdata/demo-skill --policy examples/policy/public-sigstore.json
allow: manifest digest 9a360f71... signed by release workflow
```

After tampering with `scripts/util.py`:

```console
$ skill-trust verify ./testdata/demo-skill --policy examples/policy/public-sigstore.json
block: content mismatch
  scripts/util.py: content changed (expected sha256:aaf9f035..., observed sha256:1f2e3d4c...)
```

## References

- [Canonical manifest specification](MANIFEST.md)
- [Architecture](ARCHITECTURE.md)
- [Verification policy](POLICY.md)
- [Sigstore bundle format](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto)
