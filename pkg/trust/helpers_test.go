package trust

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// publicPEM serializes a public key as PEM for tests.
func publicPEM(t *testing.T, pub crypto.PublicKey) ([]byte, error) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ensure cryptoutils stays referenced for future helpers.
var _ = cryptoutils.UnmarshalPEMToPublicKey
