// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package jwt

import gojwt "github.com/golang-jwt/jwt/v5"

// Sign mints a signed JWT for claims using key. The algorithm is taken from the
// key (Key.CryptoAlgorithm → Method), and the key id (Key.Name) is stamped into
// the `kid` header so a verifier can select the matching public key from the
// published JWKS. This is the one mint path shared by every issuer: claims are
// serialized exactly as declared, so the wire shape is identical everywhere.
func Sign(key Key, claims *Claims) (string, error) {
	signingKey, err := key.signingKey()
	if err != nil {
		return "", err
	}
	token := gojwt.NewWithClaims(Method(key.CryptoAlgorithm), claims)
	if key.Name != "" {
		token.Header["kid"] = key.Name
	}
	return token.SignedString(signingKey)
}
