package trust

import (
	// The embedded public Sigstore trusted root. Vendored from the public
	// good TUF repository (target trusted_root.json). See
	// docs/TRUST-CONFIG.md for the refresh procedure and validity
	// semantics.
	_ "embed"
)

//go:embed embedded/trusted_root.json
var publicTrustedRootJSON []byte

// PublicTrustedRootJSON returns the embedded public Sigstore trusted root
// (protobuf-specs TrustedRoot, media type
// application/vnd.dev.sigstore.trustedroot+json;version=0.1).
//
// The embedded root is a snapshot taken at build time. Transparency log
// keys and Fulcio roots remain valid for evidence within their validity
// windows, and public-good logs are immutable, so an older snapshot keeps
// verifying older bundles. New Fulcio certificate authorities and new log
// shards require a refresh (FetchPublicTrustedRoot) or a rebuilt binary.
func PublicTrustedRootJSON() []byte {
	return publicTrustedRootJSON
}
