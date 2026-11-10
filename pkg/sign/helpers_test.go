package sign

import "crypto/sha256"

// sha256Sum returns the raw SHA-256 digest of b.
func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
