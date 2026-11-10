# skill-trust

`skill-trust` is a signing and verification system for AI agent skills.

The project lets organizations sign a complete skill directory and lets a
desktop or remote agent harness verify that directory before loading or
executing it. The initial implementation is designed around Sigstore
components and Red Hat Trusted Artifact Signer (RHTAS), with a portable Go
binary and library at the center.

The goal is not to put skills into an OCI registry. A skill should remain a
portable directory or package that can be verified locally on a user's
desktop, on a remote harness, or inside CI using the same content identity and
verification policy.

## Why this exists

An Agent Skill is more than its `SKILL.md` file. A skill directory can contain
instructions, Bash/Python/JavaScript scripts, references, assets, hidden files,
and other resources. A change to any of those files can change what an agent
does.

`skill-trust` makes that change detectable:

1. The complete skill directory is converted into a canonical file manifest.
2. The manifest digest is signed using Sigstore or RHTAS.
3. The signature bundle and manifest travel with the skill in `.skill-trust/`.
4. A harness verifies the content, signer, provenance, and trust material
   before loading or executing the skill.
5. Any modification, missing metadata, or policy failure blocks execution.

The project reuses Sigstore signing and verification primitives rather than
creating a new cryptographic protocol. Sigstore supports file/blob signing,
keyless certificates, key-based signatures, bundles, transparency evidence,
and custom service endpoints. See the [Sigstore blob signing
documentation](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/)
and [custom component configuration](https://docs.sigstore.dev/cosign/system_config/custom_components/).

## Project status

The design is complete and the implementation is in progress. The canonical
manifest (spec and Go package with cross-platform test vectors) is shipped;
signing, verification, the CLI, and harness adapters follow the
[backlog order](docs/PROJECT-ISSUES.md).

## Skill format and signed boundary

The project follows the Agent Skills directory model: `SKILL.md` is required,
while directories such as `scripts/`, `references/`, and `assets/` are common
optional content. Other files are allowed and are included in the signed
boundary. See the [Agent Skills specification](https://github.com/agentskills/agentskills/blob/main/docs/specification.mdx).

Example:

```text
my-skill/
├── SKILL.md
├── scripts/
│   ├── collect.py
│   └── validate.sh
├── references/
├── assets/
└── .skill-trust/
    ├── manifest.json
    └── bundle.sigstore.json
```

Everything except `.skill-trust/` is part of the signed content. The reserved
control directory is excluded to avoid a self-referential digest. Symlinks and
special filesystem entries are rejected in the first version.

The canonical manifest includes normalized relative paths, entry types, file
content digests, executable permission bits, the manifest format version, and
the hash algorithm. Host-specific timestamps, owners, absolute paths, and
other unstable filesystem metadata are not signed. The full specification
with test vectors is in [docs/MANIFEST.md](docs/MANIFEST.md).

## Planned command-line interface

The initial Go binary is expected to provide:

```console
skill-trust manifest ./my-skill --output .skill-trust/manifest.json
skill-trust sign ./my-skill --bundle .skill-trust/bundle.sigstore.json
skill-trust verify ./my-skill
skill-trust inspect ./my-skill
```

Keyless signing is the first signing workflow. Public Sigstore is the initial
CI test target, and RHTAS is supported through configurable Fulcio, Rekor,
TUF/trusted-root, and timestamp services. Key-based signing, including KMS or
hardware-backed keys where supported by the underlying Sigstore tooling, is a
planned follow-on mode.

Verification is offline-capable when the distributed bundle and trusted-root
material are available locally. Organization policy can additionally require
specific signer identities, OIDC issuers, source/provenance claims, and trust
roots.

## Harness enforcement

The verifier is authoritative only when a harness uses it. An arbitrary agent
runtime that bypasses the verifier cannot be forced to honor a signature by a
standalone file-format tool.

The first reference integration is OpenCode. OpenCode supports skill loading,
tool permissions, and plugin hooks before tool execution. The planned adapter
will verify a skill before allowing it to load and will re-check the verified
content identity before skill-associated execution. A modified Bash or Python
script must be blocked before it runs.

See the [architecture and enforcement design](docs/ARCHITECTURE.md) for the
trust boundary and adapter contract, and the [threat model](docs/THREAT-MODEL.md)
for what a signature does and does not prove.

## GitHub Actions

The planned workflows will:

- verify all changed skills on pull requests;
- fail when signed content changes without a new signature;
- sign approved skills in trusted release/tag workflows using GitHub OIDC;
- publish the skill package, manifest, bundle, and report as release assets; and
- support switching between public Sigstore and an organization's RHTAS
  endpoints without changing the skill package format.

## Roadmap and issue backlog

The implementation backlog is in
[`docs/PROJECT-ISSUES.md`](docs/PROJECT-ISSUES.md). The implementation order
is:

1. threat model and trust policy;
2. canonical manifest and package rules;
3. Sigstore/RHTAS signing and verification;
4. Go CLI and reusable library;
5. preflight enforcement contract;
6. OpenCode adapter;
7. GitHub Actions and public test signing;
8. tamper and cross-platform test fixtures; and
9. key-based signing and enterprise lifecycle controls.

## Security limitations

A valid signature proves that the verified bytes match the signed bytes and
that the signature satisfies the configured policy. It does not prove that a
skill is benign, that static instructions are safe, or that a harness cannot
be misconfigured to bypass verification. Runtime isolation, host permissions,
secret management, and malware/prompt-injection analysis remain separate
controls.

## Contributing

Start with the design documents and issue drafts. Contributions should include
fixtures for both valid and invalid skills, document analysis limitations, and
avoid implying that signature verification is a complete safety guarantee.

## License

No license has been selected yet.

