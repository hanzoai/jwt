// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package jwt is the canonical Hanzo identity-token core: one Claims shape, one
// signer, one verifier, one JWKS builder — shared by the IAM that MINTS tokens
// and by every service (cloud, gateway, …) that VALIDATES them, so the wire
// contract cannot drift between issuer and consumer.
//
// The Claims carry the OIDC registered set (iss/sub/aud/exp/nbf/iat/jti) plus
// Hanzo's authorization envelope: owner (the home org), scope, project, azp and
// tokenType. Signing covers RSA (RS256/RS512), ECDSA (ES256/ES384/ES512) and the
// post-quantum ML-DSA-65 (FIPS 204) method. Key material crosses the boundary as
// PEM inside a Key value, so this package depends on no storage or schema type —
// an issuer and a verifier pass their own cert rows through the same seam.
package jwt

import (
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// RegisteredClaims re-exports the OIDC/JWT registered claim set (iss/sub/aud/
// exp/nbf/iat/jti) so a caller builds and reads Hanzo tokens through this one
// package without also importing golang-jwt.
type RegisteredClaims = gojwt.RegisteredClaims

// ClaimStrings is the audience claim type: a single string or an array, per
// RFC 7519. Re-exported for the same one-import reason as RegisteredClaims.
type ClaimStrings = gojwt.ClaimStrings

// NumericDate is the RFC 7519 numeric-date claim type used for exp/nbf/iat.
type NumericDate = gojwt.NumericDate

// NewNumericDate wraps a time as a JWT numeric date for the exp/nbf/iat claims.
func NewNumericDate(t time.Time) *NumericDate { return gojwt.NewNumericDate(t) }

// User is the identity projection embedded in every Hanzo access token: exactly
// the fields a bearer needs to identify the principal and its home org. Owner is
// the tenant/organization slug — the home-org anchor every downstream authorizes
// and bills against — and is the canonical org claim. Field names match what IAM
// v1 emits, so a token minted by either issuer decodes identically; EmailVerified
// uses the OIDC-standard snake_case `email_verified`.
type User struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`

	Id            string `json:"id"`
	DisplayName   string `json:"displayName"`
	Avatar        string `json:"avatar"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Phone         string `json:"phone"`
}

// Claims is the Hanzo access/refresh-token claim set: the OIDC registered claims
// plus Hanzo's authorization envelope. Field parity with the IAM v1 token is
// mandatory — cloud and the gateway key on Owner (home org, via the embedded
// User), Scope, Project, Azp, aud and iss — so the names and shapes here are the
// wire contract, not an implementation detail. The embedded *User inlines the
// identity fields at the top level of the token; the embedded RegisteredClaims
// inlines the registered claims.
type Claims struct {
	*User
	TokenType string `json:"tokenType,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Tag       string `json:"tag"`
	Scope     string `json:"scope,omitempty"`
	// Azp is the OIDC `azp` (authorized party) — the client the token was minted
	// for. https://openid.net/specs/openid-connect-core-1_0.html#IDToken
	Azp      string `json:"azp,omitempty"`
	Provider string `json:"provider,omitempty"`
	// Project is the caller org's default project (empty ⟹ default scope). The
	// gateway mints X-Project-Id from it, threaded beside the org claim.
	Project string `json:"project,omitempty"`

	SigninMethod string `json:"signinMethod,omitempty"`
	RegisteredClaims
}
