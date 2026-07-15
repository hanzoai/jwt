// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package jwt

import (
	"fmt"
	"strings"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// Key is the signing/verification material a caller hands this package: PEM text
// plus the algorithm it was generated for. It is storage-agnostic — the fields
// mirror an IAM Cert (Certificate + PrivateKey PEM, CryptoAlgorithm, BitSize) but
// carry no dependency on any schema, so IAM, cloud and the gateway all pass their
// own cert rows through the same seam.
//
// Name is the key id (kid): it is stamped into the JWT header and the JWKS entry
// so a verifier can select the right key. Certificate holds an x509 CERTIFICATE
// PEM (RSA/EC) or an "MLDSA65 PUBLIC KEY" PEM; PrivateKey holds the matching
// private PEM. BitSize is carried for parity with the cert row and is not needed
// to sign or verify.
type Key struct {
	Name            string
	Certificate     string
	PrivateKey      string
	CryptoAlgorithm string
	BitSize         int
}

// Method resolves a Hanzo signing-algorithm name to its JWT signing method,
// mirroring IAM v1 exactly: RS256/RS512, ES256/ES384/ES512, MLDSA65, and an
// empty or unknown name falling back to RS256 (the v1 default).
func Method(algorithm string) gojwt.SigningMethod {
	switch algorithm {
	case "RS256":
		return gojwt.SigningMethodRS256
	case "RS512":
		return gojwt.SigningMethodRS512
	case "ES256":
		return gojwt.SigningMethodES256
	case "ES384":
		return gojwt.SigningMethodES384
	case "ES512":
		return gojwt.SigningMethodES512
	case algMLDSA65:
		return SigningMethodMLDSA65
	default:
		return gojwt.SigningMethodRS256
	}
}

// signingKey parses the private key for signing, dispatching on the algorithm
// family exactly as IAM v1 does: ML-DSA-65 raw key, RSA (PKCS#1/#8), EC (SEC1).
// An empty algorithm defaults to RSA, matching Method's RS256 default.
func (k Key) signingKey() (interface{}, error) {
	switch {
	case k.CryptoAlgorithm == algMLDSA65:
		return parseMLDSA65PrivateKey(k.PrivateKey)
	case k.CryptoAlgorithm == "" || strings.Contains(k.CryptoAlgorithm, "RS"):
		return gojwt.ParseRSAPrivateKeyFromPEM([]byte(k.PrivateKey))
	case strings.Contains(k.CryptoAlgorithm, "ES"):
		return gojwt.ParseECPrivateKeyFromPEM([]byte(k.PrivateKey))
	}
	return nil, fmt.Errorf("jwt: unsupported signing algorithm %q", k.CryptoAlgorithm)
}

// publicKeyFor parses the public key matching a token's signing method from the
// certificate PEM, mirroring IAM v1's verify keyfunc: RSA and EC public keys are
// read from the x509 certificate, ML-DSA-65 from its raw-key PEM.
func (k Key) publicKeyFor(method gojwt.SigningMethod) (interface{}, error) {
	if k.Certificate == "" {
		return nil, fmt.Errorf("jwt: certificate is empty for key %q", k.Name)
	}
	switch method.(type) {
	case *gojwt.SigningMethodRSA:
		return gojwt.ParseRSAPublicKeyFromPEM([]byte(k.Certificate))
	case *gojwt.SigningMethodECDSA:
		return gojwt.ParseECPublicKeyFromPEM([]byte(k.Certificate))
	case *signingMethodMLDSA65:
		return parseMLDSA65PublicKey(k.Certificate)
	}
	return nil, fmt.Errorf("jwt: unexpected signing method %q", method.Alg())
}
