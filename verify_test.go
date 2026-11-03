// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	jwt "github.com/hanzoai/jwt"
)

// The verify path is the security boundary every downstream service shares:
// these pin what it must REJECT, and how strictly it selects keys.

// ecPrivPEM marshals an EC private key as SEC1 PEM, matching ecKey's format.
func ecPrivPEM(t *testing.T, priv *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

// A token whose payload was altered after signing must not verify.
func TestParseRejectsTamperedPayload(t *testing.T) {
	key := rsaKey(t)
	raw, err := jwt.Sign(key, sampleClaims())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("token shape: %d parts", len(parts))
	}
	p := []byte(parts[1])
	if p[len(p)/2] == 'A' {
		p[len(p)/2] = 'B'
	} else {
		p[len(p)/2] = 'A'
	}
	tampered := parts[0] + "." + string(p) + "." + parts[2]
	if _, err := jwt.Parse(tampered, key); err == nil {
		t.Fatal("a tampered payload verified")
	}
}

// Parse pins the accepted alg to the key's own family, so a token signed under
// one family can never be pushed through a verifier holding another family's
// key. This is the algorithm-confusion door; it must stay shut.
func TestParseRejectsAlgorithmMismatch(t *testing.T) {
	rsa := rsaKey(t)
	ec := ecKey(t)

	rsaToken, err := jwt.Sign(rsa, sampleClaims())
	if err != nil {
		t.Fatalf("sign rsa: %v", err)
	}
	if _, err := jwt.Parse(rsaToken, ec); err == nil {
		t.Fatal("an RS256 token verified against an EC key")
	}

	ecToken, err := jwt.Sign(ec, sampleClaims())
	if err != nil {
		t.Fatalf("sign ec: %v", err)
	}
	if _, err := jwt.Parse(ecToken, rsa); err == nil {
		t.Fatal("an ES256 token verified against an RSA key")
	}
}

// A kid that matches nothing in the set must fail closed, never fall back to
// any key the set happens to hold.
func TestParseJWKSRejectsUnknownKid(t *testing.T) {
	key := rsaKey(t)
	jwks, err := jwt.BuildJWKS(key)
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}
	other := rsaKey(t)
	other.Name = "attacker-kid"
	raw, err := jwt.Sign(other, sampleClaims())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := jwt.ParseJWKS(raw, jwks); err == nil {
		t.Fatal("a token with an unknown kid verified against the set")
	}
}

// Without a kid there is nothing to select on, so a multi-key set must refuse
// rather than guess.
func TestParseJWKSNoKidMultiKeyRefuses(t *testing.T) {
	anon := rsaKey(t)
	anon.Name = ""
	raw, err := jwt.Sign(anon, sampleClaims())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	jwks, err := jwt.BuildJWKS(rsaKey(t), mldsaKey(t))
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}
	if _, err := jwt.ParseJWKS(raw, jwks); err == nil {
		t.Fatal("a kid-less token verified against a multi-key set")
	}
}

// The one deliberate fallback: a single-key set answers a kid-less token.
func TestParseJWKSSingleKeyAnswersKidlessToken(t *testing.T) {
	anon := rsaKey(t)
	anon.Name = ""
	raw, err := jwt.Sign(anon, sampleClaims())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	jwks, err := jwt.BuildJWKS(anon)
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}
	got, err := jwt.ParseJWKS(raw, jwks)
	if err != nil {
		t.Fatalf("parse jwks: %v", err)
	}
	assertClaims(t, got)
}

// WithExpiryRequired is the option callers reach for when a token without exp
// must not pass; by default such a token is accepted (golang-jwt semantics).
func TestWithExpiryRequired(t *testing.T) {
	key := rsaKey(t)
	c := sampleClaims()
	c.ExpiresAt = nil
	raw, err := jwt.Sign(key, c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := jwt.Parse(raw, key); err != nil {
		t.Fatalf("exp-less token should parse by default: %v", err)
	}
	if _, err := jwt.Parse(raw, key, jwt.WithExpiryRequired()); err == nil {
		t.Fatal("an exp-less token passed WithExpiryRequired")
	}
}

// A token that is not valid yet must be rejected.
func TestParseRejectsFutureNotBefore(t *testing.T) {
	key := rsaKey(t)
	c := sampleClaims()
	c.NotBefore = jwt.NewNumericDate(time.Now().Add(time.Hour))
	raw, err := jwt.Sign(key, c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := jwt.Parse(raw, key); err == nil {
		t.Fatal("a token with nbf in the future verified")
	}
}

// The remaining algorithm names on Method's switch must round-trip too:
// RS512 and the wider ECDSA curves.
func TestRoundTripRemainingAlgorithms(t *testing.T) {
	rsa512 := rsaKey(t)
	rsa512.CryptoAlgorithm = "RS512"

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	es384 := jwt.Key{Name: "es384", Certificate: certPEM(t, p384, &p384.PublicKey), PrivateKey: ecPrivPEM(t, p384), CryptoAlgorithm: "ES384"}

	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	es512 := jwt.Key{Name: "es512", Certificate: certPEM(t, p521, &p521.PublicKey), PrivateKey: ecPrivPEM(t, p521), CryptoAlgorithm: "ES512"}

	for _, key := range []jwt.Key{rsa512, es384, es512} {
		raw, err := jwt.Sign(key, sampleClaims())
		if err != nil {
			t.Fatalf("sign %s: %v", key.CryptoAlgorithm, err)
		}
		got, err := jwt.Parse(raw, key)
		if err != nil {
			t.Fatalf("parse %s: %v", key.CryptoAlgorithm, err)
		}
		assertClaims(t, got)
	}
}

// A repeated kid collapses to one entry: a duplicate kid makes key selection
// ambiguous, and BuildJWKS promises one entry per kid.
func TestBuildJKWSCollapsesDuplicateKid(t *testing.T) {
	a := rsaKey(t)
	b := rsaKey(t) // same Name as a
	jwks, err := jwt.BuildJWKS(a, b)
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &doc); err != nil {
		t.Fatalf("parse jwks: %v", err)
	}
	if len(doc.Keys) != 1 {
		t.Fatalf("duplicate kid produced %d entries, want 1", len(doc.Keys))
	}
	if doc.Keys[0].Kid != a.Name {
		t.Errorf("kid = %q, want %q", doc.Keys[0].Kid, a.Name)
	}
}

// An ML-DSA-65 token must not verify under a different ML-DSA-65 key.
func TestParseRejectsWrongMLDSAKey(t *testing.T) {
	raw, err := jwt.Sign(mldsaKey(t), sampleClaims())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := jwt.Parse(raw, mldsaKey(t)); err == nil {
		t.Fatal("an ML-DSA-65 token verified under a different ML-DSA-65 key")
	}
}

// Expiry is enforced on the JWKS path too, not only on Parse.
func TestParseJWKSRejectsExpired(t *testing.T) {
	key := rsaKey(t)
	c := sampleClaims()
	c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
	raw, err := jwt.Sign(key, c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	jwks, err := jwt.BuildJWKS(key)
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}
	if _, err := jwt.ParseJWKS(raw, jwks); err == nil {
		t.Fatal("an expired token verified against the JWKS")
	}
}
