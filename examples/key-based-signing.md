# Example: key-based signing and verification

This walkthrough signs a skill with a local key and verifies it with both
`skill-trust` and upstream `cosign`. It demonstrates the complete success
path and the tamper-detection path.

Commands were executed with `skill-trust` from this repository and
`cosign` v3.1.4. The skill used is the repository's golden fixture shape:
`SKILL.md` plus Bash and Python helpers.

## 1. Create a signing key

```console
$ openssl ecparam -name prime256v1 -genkey -noout -out release.key
$ openssl ec -in release.key -pubout -out release.pub
```

skill-trust accepts PEM private keys (PKCS8 or SEC1 ECDSA; PKCS1/PKCS8
RSA). The matching public key is what verifiers configure as trust
material.

## 2. Sign the skill (offline, no services)

```console
$ skill-trust sign ./my-skill --key release.key
```

This produces, without contacting any service:

```text
my-skill/.skill-trust/manifest.json          canonical manifest (v1)
my-skill/.skill-trust/bundle.sigstore.json   Sigstore bundle v0.3
```

The bundle is a protobuf-specs Sigstore bundle:

```json
{
  "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
  "verificationMaterial": {
    "publicKey": { "hint": "+rld0XAipra2sWqlQ5CwdAj/lCNzkYd8Of/c8hmpYDM=" }
  },
  "messageSignature": {
    "messageDigest": { "algorithm": "SHA2_256", "digest": "…" },
    "signature": "…"
  }
}
```

The `hint` is `base64(SHA-256(SPKI(public key)))` — the same identifier
cosign computes. The `messageDigest` is the SHA-256 of the canonical
manifest bytes, i.e. the signed content identity of the whole skill
directory (every file, every executable bit).

## 3. Verify with skill-trust

```console
$ skill-trust verify ./my-skill --key release.pub
allow: manifest digest 8dd3d110ca16b82c65cf028fc037fec6615f435265b5601a54cf13df2690234a signed by trusted key
```

## 4. Verify with cosign (interop)

Because the bundle is the standard Sigstore format, upstream tooling
verifies it directly:

```console
$ cosign verify-blob \
    --key release.pub \
    --bundle my-skill/.skill-trust/bundle.sigstore.json \
    --insecure-ignore-tlog \
    my-skill/.skill-trust/manifest.json
Verified OK
```

`--insecure-ignore-tlog` is only needed because this signature was
produced offline without a transparency log entry (see the RHTAS example
below for a bundle with log evidence).

## 5. Tamper and observe the block

```console
$ echo "print('evil')" > my-skill/scripts/util.py

$ skill-trust verify ./my-skill --key release.pub
block: content mismatch
  ST-CONTENT-MISMATCH scripts/util.py: content changed
    (expected sha256:aaf9f035bf3a9364c1dbf0d1df6ce9e8508e83cfb532b818bfa1b2fc5b6fc3ca,
     observed sha256:1f2e3d4c5b6a798877665544332211ffeeddccbbaa998877665544332211ff)
exit code 1
```

Every mutation of signed content is detected: modified files, added files,
deleted files, renamed files, and flipped executable bits.

## Variant: signing with RHTAS transparency evidence

With a `trust.Services` configuration pointing at an RHTAS instance (or any
Sigstore deployment), the same key-based signing records the signature in
Rekor and adds an RFC 3161 timestamp:

```console
$ skill-trust sign ./my-skill --key release.key \
    --rekor-url https://rekor-server-skill-trust-rhtas.apps.claws.bxz4.p1.openshiftapps.com \
    --tsa-url https://tsa-server-skill-trust-rhtas.apps.claws.bxz4.p1.openshiftapps.com/api/v1/timestamp \
    --trusted-root rhtas-trusted-root.json
signed: 8dd3d110ca16b82c65cf028fc037fec6615f435265b5601a54cf13df2690234a
tlog entry: true
timestamp: true
```

The resulting bundle carries the inclusion proof and timestamp, and
verifies with cosign against the RHTAS trusted root **without** disabling
transparency log checks:

```console
$ cosign verify-blob \
    --key release.pub \
    --bundle my-skill/.skill-trust/bundle.sigstore.json \
    --trusted-root rhtas-trusted-root.json \
    my-skill/.skill-trust/manifest.json
Verified OK
```

The RHTAS trusted root (`trusted_root.json`) is downloaded once from the
RHTAS TUF server's targets listing; see
[the trust configuration guide](../docs/TRUST-CONFIG.md).
