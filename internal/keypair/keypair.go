// Package keypair implements sign.Keypair for a private key loaded from a
// PEM file, so that sign.Bundle() can be used with long-lived keys.
//
// sigstore-go v1.4.0 only ships EphemeralKeypair (a throwaway generated
// key); using your own PEM key requires this small adapter. The wire format
// it produces is identical to cosign's: the bundle's key hint is
// base64(SHA-256(SPKI-encoded public key)).
package keypair

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

type pemKeypair struct {
	privKey     crypto.Signer
	algDetails  signature.AlgorithmDetails
	signingAlgo protocommon.PublicKeyDetails
	hashAlgo    protocommon.HashAlgorithm
	hint        string // base64(SHA-256(SPKI-encoded public key))
}

// LoadFromPEM parses a PEM-encoded private key (PKCS8 or SEC1 ECDSA,
// PKCS1/PKCS8 RSA) and returns a sign.Keypair usable with sign.Bundle.
func LoadFromPEM(pemBytes []byte) (sign.Keypair, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		if priv, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
			return nil, fmt.Errorf("parsing private key: %w", err)
		}
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("private key is not a crypto.Signer")
	}

	var details protocommon.PublicKeyDetails
	switch k := signer.Public().(type) {
	case *ecdsa.PublicKey:
		switch {
		case k.Curve == elliptic.P256():
			details = protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256
		case k.Curve == elliptic.P384():
			details = protocommon.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384
		case k.Curve == elliptic.P521():
			details = protocommon.PublicKeyDetails_PKIX_ECDSA_P521_SHA_512
		default:
			return nil, fmt.Errorf("unsupported ECDSA curve: %v", k.Curve)
		}
	case *rsa.PublicKey:
		switch {
		case k.N.BitLen() >= 4096:
			details = protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_4096_SHA256
		case k.N.BitLen() >= 3072:
			details = protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_3072_SHA256
		default:
			details = protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_2048_SHA256
		}
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", k)
	}

	algDetails, err := signature.GetAlgorithmDetails(details)
	if err != nil {
		return nil, err
	}

	// The "hint" identifies the public key inside the bundle. Both
	// sigstore-go and cosign use base64(SHA-256(SPKI bytes)).
	spki, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(spki)

	return &pemKeypair{
		privKey:     signer,
		algDetails:  algDetails,
		signingAlgo: details,
		hashAlgo:    algDetails.GetProtoHashType(),
		hint:        base64.StdEncoding.EncodeToString(sum[:]),
	}, nil
}

func (p *pemKeypair) GetHashAlgorithm() protocommon.HashAlgorithm { return p.hashAlgo }

func (p *pemKeypair) GetSigningAlgorithm() protocommon.PublicKeyDetails { return p.signingAlgo }

func (p *pemKeypair) GetHint() []byte { return []byte(p.hint) }

func (p *pemKeypair) GetKeyAlgorithm() string {
	switch p.privKey.Public().(type) {
	case *ecdsa.PublicKey:
		return "ECDSA"
	case *rsa.PublicKey:
		return "RSA"
	default:
		return ""
	}
}

func (p *pemKeypair) GetPublicKey() crypto.PublicKey { return p.privKey.Public() }

func (p *pemKeypair) GetPublicKeyPem() (string, error) {
	b, err := cryptoutils.MarshalPublicKeyToPEM(p.privKey.Public())
	return string(b), err
}

// SignData hashes data with the key's hash function and signs the digest.
// Returns (signature, digest, error); the digest becomes the bundle's
// messageSignature.messageDigest.digest.
func (p *pemKeypair) SignData(_ context.Context, data []byte) ([]byte, []byte, error) {
	hf := p.algDetails.GetHashType()
	dataToSign := data
	if hf != crypto.Hash(0) {
		h := hf.New()
		h.Write(data)
		dataToSign = h.Sum(nil)
	}
	sig, err := p.privKey.Sign(rand.Reader, dataToSign, hf)
	if err != nil {
		return nil, nil, err
	}
	return sig, dataToSign, nil
}

// Hint returns the key hint of the loaded key.
func (p *pemKeypair) Hint() string { return p.hint }

// HintFromPublicKey computes the key identifier hint that sign.Bundle and
// cosign put into a bundle's verificationMaterial.publicKey.hint:
// base64(SHA-256(SPKI-encoded public key)).
func HintFromPublicKey(pub crypto.PublicKey) (string, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(spki)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}
