# Canonical skill manifest specification (v1)

This document specifies the skill-trust canonical manifest: the complete,
deterministic description of a skill directory whose digest is the signed
subject. It is implemented by `pkg/manifest`.

## Relationship to the Agent Skills specification

skill-trust signs [Agent Skills](https://github.com/agentskills/agentskills)
directories: a directory containing a required `SKILL.md` with YAML
frontmatter (`name`, `description` required; `license`, `compatibility`,
`metadata`, `allowed-tools` optional), and arbitrary additional content
conventionally organized into `scripts/` (executable code — Bash, Python,
JavaScript, and other languages supported by the harness), `references/`, and
`assets/`.

The manifest does **not** interpret `SKILL.md` frontmatter or validate skill
semantics; that is the job of the Agent Skills specification and tools such
as `skills-ref validate`. The manifest signs **bytes**: every file in the
directory, regardless of its role, language, or extension. A Bash script, a
Python module, a JavaScript helper, a Markdown reference, a hidden dotfile,
and a file in a non-conventional directory are all signed content. This is
deliberate: an agent acts on all of it, so all of it is covered.

## Signed boundary

The input is a skill directory. Every regular file below the directory is
included, except files below the root `.skill-trust/` control directory
(reserved for the manifest, signature bundle, and reports — excluding it
avoids a self-referential digest).

Rules:

1. **`SKILL.md` is required** at the skill root as a regular file.
2. **All regular files are included**, including hidden files, files under
   `scripts/`, `references/`, `assets/`, and any other path. VCS metadata
   such as `.git/` is ordinary content: publishers must clean working copies
   before signing (a manifest of a dirty checkout is valid but unstable).
3. **Only the root `.skill-trust/` is excluded.** A `.skill-trust` directory
   nested deeper is ordinary content.
4. **Symlinks are rejected** anywhere in the tree, including inside the
   control directory. A manifest must describe the same object on every
   host; symlinks silently break that property.
5. **Special filesystem entries are rejected**: devices, sockets, FIFOs,
   and anything that is not a regular file or directory.
6. **Directories are implicit.** They are represented only through the
   paths of the files they contain.

## Manifest format

The manifest is a JSON object:

```json
{
  "version": 1,
  "hashAlgorithm": "sha256",
  "entries": [
    {
      "path": "SKILL.md",
      "type": "file",
      "digest": "9fc689ab01291c9812d2b6b449eb3db80f72b5d7e3fb818cb532b75829064906",
      "executable": false
    }
  ]
}
```

| Field | Meaning |
|-------|---------|
| `version` | Manifest format version. Only `1` exists. Unknown versions must fail verification, not be interpreted as equivalent. |
| `hashAlgorithm` | Content hash algorithm. Only `sha256` exists in v1. |
| `entries[]` | One entry per regular file, sorted by path. |
| `entries[].path` | Normalized relative path (see below). |
| `entries[].type` | Entry type. Only `file` exists in v1. |
| `entries[].digest` | Lowercase hex SHA-256 of the file content. |
| `entries[].executable` | `true` iff any execute permission bit is set (`mode & 0o111 != 0`). |

### Path rules

- Slash-separated (`/`), relative to the skill root, never absolute.
- No `.` or `..` components, no empty components, no backslashes.
- Duplicate paths after normalization are rejected.
- Entries are sorted lexicographically by path bytes (UTF-8 byte order).
- Paths are case-sensitive on every platform; verification never lowercases.

### What is not signed

Timestamps, owners, groups, device numbers, absolute paths, and other
host-specific filesystem metadata are excluded. Two checkouts of the same
content on different hosts, users, or clocks produce the same manifest.
The executable bit **is** signed because it changes what a harness can
execute.

## Canonical serialization

The canonical form is the exact byte sequence that gets hashed:

- compact JSON: no insignificant whitespace, no trailing newline;
- key order is fixed by the schema (`version`, `hashAlgorithm`, `entries`;
  per entry `path`, `type`, `digest`, `executable`);
- UTF-8, with HTML escaping disabled (`<`, `>`, `&` appear literally);
- entries in sorted order.

```go
enc := json.NewEncoder(&buf)
enc.SetEscapeHTML(false)
```

The **manifest digest** — the object that signing operates on — is:

```text
digest = SHA-256(canonical JSON bytes)
```

serialized as lowercase hex. `.skill-trust/manifest.json` stores exactly the
canonical bytes, so the digest of the control file equals the manifest
digest.

## Test vector

The repository ships a golden fixture at `testdata/demo-skill`:

```text
testdata/demo-skill/
├── SKILL.md                 (mode 644)
├── .hidden/config           (mode 644)
├── assets/data.txt          (mode 644)
├── references/ref.md        (mode 644)
├── scripts/run.sh           (mode 755, executable)
└── scripts/util.py          (mode 644)
```

Its canonical manifest (single line, shown wrapped for readability):

```json
{"version":1,"hashAlgorithm":"sha256","entries":[
{"path":".hidden/config","type":"file","digest":"d1f95eaf7d431936847daf8517ac54ede46d3465a74746397c4437ba844a01df","executable":false},
{"path":"SKILL.md","type":"file","digest":"9fc689ab01291c9812d2b6b449eb3db80f72b5d7e3fb818cb532b75829064906","executable":false},
{"path":"assets/data.txt","type":"file","digest":"4c868ef8cdcb0a56d4abaaf91dd8d0a6a988d240f51bb1d66199a9878896abbd","executable":false},
{"path":"references/ref.md","type":"file","digest":"4829612c1ad61166ca3077ae244799d0a97528972df7eb1e5267fdf8b7f34922","executable":false},
{"path":"scripts/run.sh","type":"file","digest":"d087ce4ba31bbdd61cac64d1e2d3244ff6810e60dd4cc2dff1c1706dbde578eb","executable":true},
{"path":"scripts/util.py","type":"file","digest":"aaf9f035bf3a9364c1dbf0d1df6ce9e8508e83cfb532b818bfa1b2fc5b6fc3ca","executable":false}]}
```

Manifest digest:

```text
9a360f711d6d044b9a4de25c80cdf5035e9293e5d0845230231f7327324824d8
```

This vector is asserted by `TestVectorDemoSkill` in `pkg/manifest` and is
verified on both darwin/arm64 and linux/amd64 in CI. The fixture's
executable bit travels through git (mode `100755`), so the vector is stable
across supported checkouts.

## Verification semantics

Verification recomputes the manifest from the directory and compares it
with the embedded manifest. Differences are reported with stable kinds:

| Kind | Meaning |
|------|---------|
| `version-mismatch` | embedded manifest version differs from the recomputed one |
| `hash-algorithm-mismatch` | algorithms differ; digests not comparable |
| `file-modified` | signed file content changed |
| `file-added` | unsigned file was added |
| `file-deleted` | signed file is missing |
| `executable-bit-changed` | execute permission changed on a signed file |

Any difference blocks the decision (fail closed). The digest of the
recomputed manifest is what the signature is checked against, so a tampered
file, an added file, a deleted file, or a flipped executable bit all
produce a digest mismatch before policy evaluation runs.

## Cross-platform notes

- Content digests and path rules are identical on every platform.
- The executable bit is a POSIX property. On filesystems that do not
  preserve it (some archive tools, Windows checkouts without `core.filemode`
  equivalents), the recomputed manifest marks files non-executable and
  verification fails with `executable-bit-changed`. Distribution archives
  must preserve modes (for example `tar` with `-p` on extraction).
- Skill publishers should canonicalize line endings before signing; the
  manifest hashes raw bytes and does not normalize CRLF.

## Library API

`pkg/manifest` exposes:

- `manifest.Create(dir)` — build the manifest for a directory (rejects
  unsupported entries, requires `SKILL.md`, never executes content);
- `(*Manifest).Canonical()` / `.Digest()` — canonical bytes and signed
  digest;
- `(*Manifest).Validate()` — structural checks for untrusted input;
- `manifest.Compare(expected, observed)` — content differences;
- `manifest.LoadControlManifest(dir)` / `WriteControlManifest(dir)` —
  control-file I/O.

## References

- [Threat model](THREAT-MODEL.md)
- [Verification policy](POLICY.md)
- [Package layout](PACKAGE-LAYOUT.md)
- [Agent Skills specification](https://github.com/agentskills/agentskills/blob/main/docs/specification.mdx)
