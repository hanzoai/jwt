// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package jwt

import (
	"fmt"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// ParseOption tunes verification. By default Parse and ParseJWKS check the
// signature and the time-based claims (exp/nbf) that golang-jwt validates
// automatically; the options add strict issuer/audience enforcement so a caller
// can validate the full security envelope in one call.
type ParseOption func() gojwt.ParserOption

// WithIssuer requires the token `iss` to equal issuer.
func WithIssuer(issuer string) ParseOption {
	return func() gojwt.ParserOption { return gojwt.WithIssuer(issuer) }
}

// WithAudience requires audience to be present in the token `aud`.
func WithAudience(audience string) ParseOption {
	return func() gojwt.ParserOption { return gojwt.WithAudience(audience) }
}

// WithExpiryRequired rejects a token that carries no `exp`.
func WithExpiryRequired() ParseOption {
	return func() gojwt.ParserOption { return gojwt.WithExpirationRequired() }
}

// withValidMethods pins the accepted `alg` values, so a token can only verify
// under the algorithm(s) the verifier expects — closing the algorithm-confusion
// door (e.g. an attacker re-signing under a different family).
func withValidMethods(algs ...string) ParseOption {
	return func() gojwt.ParserOption { return gojwt.WithValidMethods(algs) }
}

// Parse verifies a token against a single known key and returns its claims. The
// public key is selected from key.Certificate by the token's signing method, and
// the accepted algorithm is pinned to the key's own — mirroring IAM v1's
// ParseJwtToken. Use this when the verifier already holds the signing cert (e.g.
// the issuer validating its own token); use ParseJWKS to verify against a
// published key set.
func Parse(raw string, key Key, opts ...ParseOption) (*Claims, error) {
	pinned := append([]ParseOption{withValidMethods(Method(key.CryptoAlgorithm).Alg())}, opts...)
	return parse(raw, func(t *gojwt.Token) (interface{}, error) {
		return key.publicKeyFor(t.Method)
	}, pinned...)
}

// ParseJWKS verifies a token against a published JWKS document (the bytes from a
// /.well-known/jwks endpoint) and returns its claims. The signing key is selected
// by the token's `kid`; a single-key set with no kid is used directly. Handles
// both traditional (RSA/EC) and ML-DSA-65 keys. This is the verify path every
// downstream service shares with the issuer.
func ParseJWKS(raw string, jwksJSON []byte, opts ...ParseOption) (*Claims, error) {
	set, err := parseKeySet(jwksJSON)
	if err != nil {
		return nil, err
	}
	return parse(raw, set.keyfunc, opts...)
}

// parse is the shared verification core: it maps the options to golang-jwt
// parser options, decodes into a Claims, verifies via keyfunc, and returns the
// claims only when the token is valid.
func parse(raw string, keyfunc gojwt.Keyfunc, opts ...ParseOption) (*Claims, error) {
	parserOpts := make([]gojwt.ParserOption, 0, len(opts))
	for _, o := range opts {
		parserOpts = append(parserOpts, o())
	}
	claims := &Claims{}
	token, err := gojwt.ParseWithClaims(raw, claims, keyfunc, parserOpts...)
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("jwt: token is invalid")
	}
	return claims, nil
}
