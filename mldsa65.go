// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// mldsa65.go implements a jwt.SigningMethod for ML-DSA-65 (FIPS 204), NIST
// Level 3 (192-bit) post-quantum module-lattice signatures. It delegates to
// github.com/luxfi/crypto/mldsa. Algorithm identifier: "MLDSA65".
//
// Unlike RSA/EC keys, ML-DSA keys are not wrapped in x509 certificates: the
// certificate field carries a PEM block "MLDSA65 PUBLIC KEY" with the raw
// base64 public key, and the private-key field a "MLDSA65 PRIVATE KEY" block
// with the raw base64 private key. See hip-00NN for the identity-token spec.

package jwt

import (
	"encoding/base64"
	"errors"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/luxfi/crypto/mldsa"
)

const algMLDSA65 = "MLDSA65"

var (
	// SigningMethodMLDSA65 is the JWT signing method for ML-DSA-65.
	SigningMethodMLDSA65 *signingMethodMLDSA65

	errMLDSA65KeyType      = errors.New("mldsa65: invalid key type")
	errMLDSA65Verification = errors.New("mldsa65: signature verification failed")
)

func init() {
	SigningMethodMLDSA65 = &signingMethodMLDSA65{}
	gojwt.RegisterSigningMethod(algMLDSA65, func() gojwt.SigningMethod {
		return SigningMethodMLDSA65
	})
}

type signingMethodMLDSA65 struct{}

func (m *signingMethodMLDSA65) Alg() string { return algMLDSA65 }

// Verify checks an ML-DSA-65 signature. key must be *mldsa.PublicKey.
func (m *signingMethodMLDSA65) Verify(signingString string, sig []byte, key interface{}) error {
	pk, ok := key.(*mldsa.PublicKey)
	if !ok {
		return errMLDSA65KeyType
	}

	if !pk.VerifySignature([]byte(signingString), sig) {
		return errMLDSA65Verification
	}
	return nil
}

// Sign produces an ML-DSA-65 signature. key must be *mldsa.PrivateKey.
func (m *signingMethodMLDSA65) Sign(signingString string, key interface{}) ([]byte, error) {
	sk, ok := key.(*mldsa.PrivateKey)
	if !ok {
		return nil, errMLDSA65KeyType
	}

	sig, err := sk.Sign(nil, []byte(signingString), nil)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// GenerateMLDSA65Keys generates an ML-DSA-65 key pair and returns the public
// and private keys as base64-encoded PEM blocks ("MLDSA65 PUBLIC KEY" and
// "MLDSA65 PRIVATE KEY"). These populate a Key's Certificate and PrivateKey.
func GenerateMLDSA65Keys() (certificate string, privateKey string, err error) {
	sk, err := mldsa.GenerateKey(nil, mldsa.MLDSA65)
	if err != nil {
		return "", "", err
	}

	pubB64 := base64.StdEncoding.EncodeToString(sk.PublicKey.Bytes())
	privB64 := base64.StdEncoding.EncodeToString(sk.Bytes())

	certificate = "-----BEGIN MLDSA65 PUBLIC KEY-----\n" + pubB64 + "\n-----END MLDSA65 PUBLIC KEY-----\n"
	privateKey = "-----BEGIN MLDSA65 PRIVATE KEY-----\n" + privB64 + "\n-----END MLDSA65 PRIVATE KEY-----\n"

	return certificate, privateKey, nil
}

// parseMLDSA65PrivateKey parses a PEM-encoded ML-DSA-65 private key.
func parseMLDSA65PrivateKey(pemData string) (*mldsa.PrivateKey, error) {
	b64 := extractPEMPayload(pemData)
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return mldsa.PrivateKeyFromBytes(mldsa.MLDSA65, raw)
}

// parseMLDSA65PublicKey parses a PEM-encoded ML-DSA-65 public key.
func parseMLDSA65PublicKey(pemData string) (*mldsa.PublicKey, error) {
	b64 := extractPEMPayload(pemData)
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return mldsa.PublicKeyFromBytes(raw, mldsa.MLDSA65)
}

// mldsa65JWK creates the JWKS entry for an ML-DSA-65 public key.
func mldsa65JWK(kid string, pk *mldsa.PublicKey) MLDSA65WebKey {
	return MLDSA65WebKey{
		Kty: "MLDSA",
		Alg: algMLDSA65,
		Use: "sig",
		Kid: kid,
		X:   base64.RawURLEncoding.EncodeToString(pk.Bytes()),
	}
}

// extractPEMPayload strips PEM header/footer lines and returns the base64 body.
func extractPEMPayload(pemData string) string {
	var result string
	for _, line := range splitLines(pemData) {
		if line == "" || line[0] == '-' {
			continue
		}
		result += line
	}
	return result
}

// splitLines splits a string into lines, handling both \n and \r\n.
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[start:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			lines = append(lines, line)
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
