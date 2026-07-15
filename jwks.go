// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package jwt

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/luxfi/crypto/mldsa"
)

// JSONWebKeySet is a JWKS document that carries both traditional (RSA/EC) keys
// and post-quantum ML-DSA-65 keys. Traditional keys serialize via go-jose;
// ML-DSA-65 keys use the IETF draft PQ-JWK form (kty=MLDSA, alg=MLDSA65).
type JSONWebKeySet struct {
	Keys []interface{} `json:"keys"`
}

// MLDSA65WebKey is the JWK form of an ML-DSA-65 public key, following the IETF
// draft convention for post-quantum JWK.
type MLDSA65WebKey struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	X   string `json:"x"` // base64url-encoded raw public key
}

// BuildJWKS renders the public JWKS document for keys — the bytes IAM publishes
// at /.well-known/jwks. Each key contributes one entry keyed by its Name (kid);
// a duplicate kid is collapsed to one entry (a repeated kid makes go-jose key
// selection ambiguous and fails verification). Mirrors IAM v1 GetJsonWebKeySet
// over an explicit key list rather than a DB query.
func BuildJWKS(keys ...Key) ([]byte, error) {
	set := JSONWebKeySet{Keys: []interface{}{}}
	seen := make(map[string]bool, len(keys))
	for _, k := range keys {
		if k.Name != "" && seen[k.Name] {
			continue
		}
		seen[k.Name] = true

		if k.Certificate == "" {
			return nil, fmt.Errorf("jwt: certificate is empty for key %q", k.Name)
		}

		// ML-DSA-65 keys use raw key material, not x509.
		if k.CryptoAlgorithm == algMLDSA65 {
			pk, err := parseMLDSA65PublicKey(k.Certificate)
			if err != nil {
				return nil, err
			}
			set.Keys = append(set.Keys, mldsa65JWK(k.Name, pk))
			continue
		}

		block, _ := pem.Decode([]byte(k.Certificate))
		if block == nil {
			return nil, fmt.Errorf("jwt: certificate for key %q is not valid PEM", k.Name)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		set.Keys = append(set.Keys, jose.JSONWebKey{
			Key:          cert.PublicKey,
			Certificates: []*x509.Certificate{cert},
			KeyID:        k.Name,
			Algorithm:    k.CryptoAlgorithm,
			Use:          "sig",
		})
	}
	return json.Marshal(set)
}

// keySet is a parsed JWKS: the public keys indexed by kid, plus the full list
// for the single-key fallback. Verification keys are the concrete public-key
// types the signing methods expect (*rsa.PublicKey, *ecdsa.PublicKey,
// *mldsa.PublicKey).
type keySet struct {
	byKid map[string]interface{}
	all   []interface{}
}

// keyfunc selects the verification key for a token from the parsed set: by kid
// when the header carries one, else the sole key of a single-key set.
func (s *keySet) keyfunc(t *gojwt.Token) (interface{}, error) {
	if kid, ok := t.Header["kid"].(string); ok && kid != "" {
		if key, ok := s.byKid[kid]; ok {
			return key, nil
		}
		return nil, fmt.Errorf("jwt: no key in JWKS matches kid %q", kid)
	}
	if len(s.all) == 1 {
		return s.all[0], nil
	}
	return nil, fmt.Errorf("jwt: token has no kid and JWKS has %d keys", len(s.all))
}

// parseKeySet decodes a JWKS document into verification keys, handling both
// traditional keys (via go-jose) and ML-DSA-65 keys (kty=MLDSA) in one pass.
func parseKeySet(jwksJSON []byte) (*keySet, error) {
	var raw struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(jwksJSON, &raw); err != nil {
		return nil, fmt.Errorf("jwt: parse JWKS: %w", err)
	}

	set := &keySet{byKid: make(map[string]interface{}, len(raw.Keys))}
	for _, rk := range raw.Keys {
		var head struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
		}
		if err := json.Unmarshal(rk, &head); err != nil {
			return nil, fmt.Errorf("jwt: parse JWKS entry: %w", err)
		}

		var pub interface{}
		if head.Kty == "MLDSA" {
			var wk MLDSA65WebKey
			if err := json.Unmarshal(rk, &wk); err != nil {
				return nil, err
			}
			rawPub, err := base64.RawURLEncoding.DecodeString(wk.X)
			if err != nil {
				return nil, fmt.Errorf("jwt: decode MLDSA JWK: %w", err)
			}
			pk, err := mldsa.PublicKeyFromBytes(rawPub, mldsa.MLDSA65)
			if err != nil {
				return nil, err
			}
			pub = pk
		} else {
			var jwk jose.JSONWebKey
			if err := json.Unmarshal(rk, &jwk); err != nil {
				return nil, fmt.Errorf("jwt: parse JWK: %w", err)
			}
			pub = jwk.Key
		}

		if head.Kid != "" {
			set.byKid[head.Kid] = pub
		}
		set.all = append(set.all, pub)
	}
	return set, nil
}
