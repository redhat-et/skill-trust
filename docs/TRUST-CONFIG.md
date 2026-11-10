# Trust configuration (Sigstore and RHTAS)

This document describes the skill-trust trust configuration layer
(`pkg/trust`): how trust material and signing service endpoints are
configured, loaded, refreshed, and used offline. One configuration model
covers public Sigstore and RHTAS (or any Sigstore-compatible deployment);
switching between them is a configuration change, never a skill format
change.

## Two kinds of configuration

| Kind | Used by | Contents |
|------|---------|----------|
| **Trust material** (verification side) | `skill-trust verify`, harness adapters | Certificate authorities, Rekor/CT log public keys, timestamp authorities, public keys |
| **Services** (signing side) | `skill-trust sign` | Fulcio, Rekor, and TSA endpoint URLs |

Both are plain data (JSON), so they can be reviewed, pinned, and distributed
like any other configuration.

## Trust roots

Trust roots are named inside a verification policy's `trustRoots` map and
referenced by signer rules (see [POLICY.md](POLICY.md)). Four types are
supported:

### `sigstore-public` (default)

```json
{ "type": "sigstore-public" }
```

The public Sigstore good instance. The trusted root is embedded in the
`skill-trust` binary at build time (`pkg/trust/embedded/trusted_root.json`),
vendored from the public TUF repository target `trusted_root.json`.

**Validity semantics.** The public Rekor log is immutable and Fulcio roots
rotate with start-only validity windows, so an older vendored root continues
to verify bundles whose evidence was produced while it was current. New
Fulcio CAs and new log shards require refreshed material.

**Refreshing.** Re-vendor the root (CI job or maintainer):

```go
// one-liner with sigstore-go:
tr, _ := root.FetchTrustedRoot()          // TUF: https://tuf-repo-cdn.sigstore.dev
b, _ := tr.MarshalJSON()
os.WriteFile("pkg/trust/embedded/trusted_root.json", b, 0o644)
```

Rebuild the binary (or the library consumer) afterward. A release signing
workflow should re-vendor before cutting releases so new signatures verify
against the freshest root.

### `trusted-root` (RHTAS and private deployments)

```json
{ "type": "trusted-root", "path": "trust/rhtas-trusted-root.json" }
```

A Sigstore `TrustedRoot` JSON document (`application/vnd.dev.sigstore.trustedroot+json;version=0.1`).
RHTAS publishes this through its TUF server. To fetch it from an RHTAS
instance:

1. List the TUF targets: `https://<tuf-route>/targets/`
2. Download the target whose name ends in `.trusted_root.json`
   (content-addressed, e.g.
   `805dd2d055c57c0d7683....trusted_root.json`).

The document carries the RHTAS Fulcio CA chain, Rekor and CT log keys, and
TSA certificate chain. The verifier uses the keys; the endpoints inside the
document are not contacted during offline verification.

RHTAS also publishes a **signing config**
(`...signing_config.v0.2.json`) with the Fulcio/Rekor/TSA route URLs for
signing; see [Services](#services) below.

### `ca` (private Fulcio-style CA)

```json
{ "type": "ca", "path": "trust/fulcio-ca.pem" }
```

A PEM bundle of CA certificates. Useful for private Fulcio deployments
where a full TrustedRoot document is not available.

### `key` (key-based signers)

```json
{ "type": "key", "path": "trust/release.pub" }
```

A PEM public key (or a concatenation of several) for key-based
verification. Bundles carry only a key *hint* —
`base64(SHA-256(SPKI))` — and the verifier authenticates the signer by
comparing the bundle's hint against the configured keys' hints. This is the
key-based equivalent of certificate chain validation, and it is why an
arbitrary key-signed bundle does not verify: foreign hints are rejected.

## Offline verification

Verification never contacts Fulcio, Rekor, the TSA, or TUF:

- certificates ride in the bundle and are checked against loaded trust
  material;
- transparency log inclusion is proven by the inclusion proof/SET stored in
  the bundle, checked against the log's public key from trust material;
- RFC 3161 timestamps ride in the bundle and are checked against the TSA
  chain from trust material.

Consequently a verifier needs exactly: the skill directory (with
`.skill-trust/` control files) and local trust material. This is what makes
desktop, remote-harness, and air-gapped CI verification identical.

The only networked operations are **opt-in and signing-side**: fetching a
fresh public trusted root, and talking to Fulcio/Rekor/TSA while producing
a signature.

## Services (signing)

Signing endpoints live in a services JSON document (default location
`.skill-trust-services.json` next to the skill being signed, or passed
explicitly):

```json
{
  "name": "rhtas",
  "fulcioURL": "https://fulcio-server-skill-trust-rhtas.apps.example.com",
  "rekorURL": "https://rekor-server-skill-trust-rhtas.apps.example.com",
  "tsaURL": "https://tsa-server-skill-trust-rhtas.apps.example.com/api/v1/timestamp",
  "oidcIssuer": "https://token.actions.githubusercontent.com",
  "trustedRootPath": "trust/rhtas-trusted-root.json"
}
```

Omitting the file selects the public Sigstore instance (the default test
configuration). Key-based signing needs no services at all unless Rekor
upload or a TSA timestamp is wanted.

RHTAS operators: the values above are exactly the routes the RHTAS
Securesign CR exposes (plus the TUF-published trusted root and signing
config). See [RHTAS operator guide](RHTAS.md) for the full walkthrough.

## Library API

- `trust.Config` — the `trustRoots` section of a policy;
  `Config.Material(names...)` loads named roots into a single trusted
  material collection.
- `trust.LoadRoot(RootConfig)` — load one root by type.
- `trust.LoadKeysFromPEM` / `KeyMaterial.TrustedMaterial()` — key-based
  verification material with hint authentication.
- `trust.KeyHint(pub)` — compute the Sigstore key hint for a public key.
- `trust.PublicTrustedRootJSON()` — the embedded public root bytes.
- `trust.Services` / `trust.PublicSigstoreServices()` / `trust.LoadServices(path)`
  — signing-side endpoint configuration.

## References

- [Verification policy](POLICY.md)
- [Architecture](ARCHITECTURE.md)
- [RHTAS operator guide](RHTAS.md)
- [Sigstore custom components](https://docs.sigstore.dev/cosign/system_config/custom_components/)
