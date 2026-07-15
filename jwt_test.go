// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package jwt_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	jwt "github.com/hanzoai/jwt"
)

// sampleClaims is the fixture every round-trip asserts survives mint→verify: it
// exercises the load-bearing fields cloud and the gateway key on — Owner (home
// org), Scope, Project, Azp, aud and iss — plus identity and token metadata.
func sampleClaims() *jwt.Claims {
	now := time.Now()
	return &jwt.Claims{
		User: &jwt.User{
			Owner:         "acme",
			Name:          "alice",
			Id:            "u-123",
			DisplayName:   "Alice",
			Avatar:        "https://cdn.example/a.png",
			Email:         "alice@acme.example",
			EmailVerified: true,
			Phone:         "+15551234567",
		},
		TokenType:    "access-token",
		Nonce:        "n-once",
		Tag:          "tag-1",
		Scope:        "openid profile email",
		Azp:          "hanzo-console",
		Provider:     "hanzo",
		Project:      "proj-x",
		SigninMethod: "password",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://hanzo.id",
			Subject:   "u-123",
			Audience:  jwt.ClaimStrings{"hanzo-console"},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			NotBefore: jwt.NewNumericDate(now.Add(-time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        "jti-1",
		},
	}
}

// assertClaims verifies the fields whose parity the whole package exists to
// guarantee are present and correct after a verify.
func assertClaims(t *testing.T, got *jwt.Claims) {
	t.Helper()
	if got.User == nil {
		t.Fatal("embedded user is nil after parse")
	}
	if got.Owner != "acme" {
		t.Errorf("owner = %q, want acme", got.Owner)
	}
	if got.Scope != "openid profile email" {
		t.Errorf("scope = %q, want openid profile email", got.Scope)
	}
	if got.Project != "proj-x" {
		t.Errorf("project = %q, want proj-x", got.Project)
	}
	if got.Azp != "hanzo-console" {
		t.Errorf("azp = %q, want hanzo-console", got.Azp)
	}
	if got.TokenType != "access-token" {
		t.Errorf("tokenType = %q, want access-token", got.TokenType)
	}
	if got.SigninMethod != "password" {
		t.Errorf("signinMethod = %q, want password", got.SigninMethod)
	}
	if got.Issuer != "https://hanzo.id" {
		t.Errorf("iss = %q, want https://hanzo.id", got.Issuer)
	}
	if got.Subject != "u-123" {
		t.Errorf("sub = %q, want u-123", got.Subject)
	}
	if len(got.Audience) != 1 || got.Audience[0] != "hanzo-console" {
		t.Errorf("aud = %v, want [hanzo-console]", got.Audience)
	}
	if got.Email != "alice@acme.example" {
		t.Errorf("email = %q, want alice@acme.example", got.Email)
	}
	if !got.EmailVerified {
		t.Error("email_verified was lost")
	}
	if got.Phone != "+15551234567" {
		t.Errorf("phone = %q", got.Phone)
	}
}

// --- round trips: mint → parse against the signing cert ---

func TestRoundTripRS256(t *testing.T) {
	key := rsaKey(t)
	raw, err := jwt.Sign(key, sampleClaims())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := jwt.Parse(raw, key)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	assertClaims(t, got)
}

func TestRoundTripMLDSA65(t *testing.T) {
	key := mldsaKey(t)
	raw, err := jwt.Sign(key, sampleClaims())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := jwt.Parse(raw, key)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	assertClaims(t, got)
}

func TestRoundTripES256(t *testing.T) {
	key := ecKey(t)
	raw, err := jwt.Sign(key, sampleClaims())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := jwt.Parse(raw, key)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	assertClaims(t, got)
}

// --- round trips: mint → publish JWKS → verify against the JWKS ---

func TestJWKSRoundTripRS256(t *testing.T) {
	key := rsaKey(t)
	raw, err := jwt.Sign(key, sampleClaims())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	jwks, err := jwt.BuildJWKS(key)
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}
	got, err := jwt.ParseJWKS(raw, jwks)
	if err != nil {
		t.Fatalf("parse jwks: %v", err)
	}
	assertClaims(t, got)
}

func TestJWKSRoundTripMLDSA65(t *testing.T) {
	key := mldsaKey(t)
	raw, err := jwt.Sign(key, sampleClaims())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	jwks, err := jwt.BuildJWKS(key)
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}
	got, err := jwt.ParseJWKS(raw, jwks)
	if err != nil {
		t.Fatalf("parse jwks: %v", err)
	}
	assertClaims(t, got)
}

// A multi-key JWKS (RSA + ML-DSA) selects the right key by kid.
func TestJWKSMultiKeySelectsByKid(t *testing.T) {
	rsa := rsaKey(t)
	pq := mldsaKey(t)
	jwks, err := jwt.BuildJWKS(rsa, pq)
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}
	for _, key := range []jwt.Key{rsa, pq} {
		raw, err := jwt.Sign(key, sampleClaims())
		if err != nil {
			t.Fatalf("sign %s: %v", key.CryptoAlgorithm, err)
		}
		got, err := jwt.ParseJWKS(raw, jwks)
		if err != nil {
			t.Fatalf("parse jwks %s: %v", key.CryptoAlgorithm, err)
		}
		assertClaims(t, got)
	}
}

// --- enforcement + negative paths ---

func TestParseEnforcesIssuerAndAudience(t *testing.T) {
	key := rsaKey(t)
	raw, err := jwt.Sign(key, sampleClaims())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := jwt.Parse(raw, key, jwt.WithIssuer("https://hanzo.id"), jwt.WithAudience("hanzo-console")); err != nil {
		t.Fatalf("expected valid with matching issuer+audience: %v", err)
	}
	if _, err := jwt.Parse(raw, key, jwt.WithAudience("evil-app")); err == nil {
		t.Fatal("expected audience mismatch to be rejected")
	}
	if _, err := jwt.Parse(raw, key, jwt.WithIssuer("https://evil.example")); err == nil {
		t.Fatal("expected issuer mismatch to be rejected")
	}
}

func TestParseRejectsWrongKey(t *testing.T) {
	raw, err := jwt.Sign(rsaKey(t), sampleClaims())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := jwt.Parse(raw, rsaKey(t)); err == nil {
		t.Fatal("expected verification against a different key to fail")
	}
}

func TestParseRejectsExpired(t *testing.T) {
	key := rsaKey(t)
	c := sampleClaims()
	c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
	raw, err := jwt.Sign(key, c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := jwt.Parse(raw, key); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
}

// --- key material helpers (self-signed test certs) ---

func rsaKey(t *testing.T) jwt.Key {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return jwt.Key{
		Name:            "rsa-test",
		Certificate:     certPEM(t, priv, &priv.PublicKey),
		PrivateKey:      string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})),
		CryptoAlgorithm: "RS256",
		BitSize:         2048,
	}
}

func ecKey(t *testing.T) jwt.Key {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return jwt.Key{
		Name:            "ec-test",
		Certificate:     certPEM(t, priv, &priv.PublicKey),
		PrivateKey:      string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})),
		CryptoAlgorithm: "ES256",
	}
}

func mldsaKey(t *testing.T) jwt.Key {
	t.Helper()
	cert, priv, err := jwt.GenerateMLDSA65Keys()
	if err != nil {
		t.Fatal(err)
	}
	return jwt.Key{
		Name:            "mldsa-test",
		Certificate:     cert,
		PrivateKey:      priv,
		CryptoAlgorithm: "MLDSA65",
	}
}

func certPEM(t *testing.T, signer crypto.Signer, pub interface{}) string {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test", Organization: []string{"hanzo"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
