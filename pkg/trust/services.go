package trust

import (
	"encoding/json"
	"fmt"
	"os"
)

// Services describes the signing service endpoints of a Sigstore
// deployment. It is the signing-side counterpart of trust material: the
// signer talks to these endpoints, the verifier trusts the corresponding
// keys through a trust root.
//
// A Services value plus a trust root is a complete deployment description;
// switching between public Sigstore and RHTAS is a configuration change,
// not a format change.
type Services struct {
	// Name labels the deployment in logs and errors.
	Name string `json:"name,omitempty"`

	// FulcioURL is the base URL of the certificate authority, for example
	// "https://fulcio.sigstore.dev" or an RHTAS Fulcio route.
	FulcioURL string `json:"fulcioURL"`

	// RekorURL is the base URL of the transparency log, for example
	// "https://rekor.sigstore.dev" or an RHTAS Rekor route. Empty
	// disables transparency log upload (key-based signing only; logged
	// with a warning finding at verification when evidence is required).
	RekorURL string `json:"rekorURL,omitempty"`

	// TSAURL is the RFC 3161 timestamp authority endpoint. Optional; when
	// set, signatures carry timestamps that remain verifiable offline.
	TSAURL string `json:"tsaURL,omitempty"`

	// OIDCIssuer is a hint for the OIDC issuer used with keyless signing,
	// for example "https://token.actions.githubusercontent.com". The
	// issuer that actually matters is the one recorded in the Fulcio
	// certificate.
	OIDCIssuer string `json:"oidcIssuer,omitempty"`

	// TrustedRootPath optionally locates the TrustedRoot JSON for this
	// deployment. When set, the signer self-verifies its output before
	// returning.
	TrustedRootPath string `json:"trustedRootPath,omitempty"`
}

// ErrServices is returned for invalid service configurations.
var ErrServices = fmt.Errorf("invalid signing services")

// Validate checks that the services are usable for the intended mode.
func (s Services) Validate(keyless bool) error {
	if keyless && s.FulcioURL == "" {
		return fmt.Errorf("%w: keyless signing requires a Fulcio URL", ErrServices)
	}
	if !keyless && s.FulcioURL != "" {
		// Harmless but almost certainly a misconfiguration.
		return nil
	}
	return nil
}

// LoadServices reads a Services JSON document from a path.
func LoadServices(path string) (Services, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Services{}, fmt.Errorf("%w: %v", ErrServices, err)
	}
	var s Services
	if err := json.Unmarshal(raw, &s); err != nil {
		return Services{}, fmt.Errorf("%w: %v", ErrServices, err)
	}
	return s, nil
}

// PublicSigstoreServices returns the public Sigstore good instance.
// This is the default test configuration.
func PublicSigstoreServices() Services {
	return Services{
		Name:       "sigstore-public",
		FulcioURL:  "https://fulcio.sigstore.dev",
		RekorURL:   "https://rekor.sigstore.dev",
		TSAURL:     "https://timestamp.sigstore.dev/api/v1/timestamp",
		OIDCIssuer: "https://oauth2.sigstore.dev/auth",
	}
}

// DefaultServicesPath is the conventional location of a deployment's
// services file, checked by the CLI when no explicit path is given.
const DefaultServicesPath = ".skill-trust-services.json"
