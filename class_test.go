package jwt_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/jwt"
)

// A verifier that files two identity classes in two places needs the issuer to
// say which class it minted. These pin that the answer survives the wire.

func TestAProgramSaysSoOnTheWire(t *testing.T) {
	key := rsaKey(t)
	raw, err := jwt.Sign(key, &jwt.Claims{
		User: &jwt.User{Owner: "hanzo", Name: "hanzo-egress"},
		Type: jwt.Program,
		Azp:  "hanzo-egress",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "admin/hanzo-egress",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := jwt.Parse(raw, key)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Type != jwt.Program {
		t.Errorf("type = %q, want %q", got.Type, jwt.Program)
	}
}

// A person carries no class at all, so the claim must be absent rather than
// present-and-empty: a verifier reading it is asking "is this a program", and an
// empty string answers no only if it is the ONE spelling of no.
func TestAPersonCarriesNoClass(t *testing.T) {
	key := rsaKey(t)
	raw, err := jwt.Sign(key, &jwt.Claims{
		User: &jwt.User{Owner: "hanzo", Name: "z"},
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "b474eaa5-e000-474d-b317-c37bbd9a6945",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := jwt.Parse(raw, key)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Type != "" {
		t.Errorf("a person's token carried type %q", got.Type)
	}

	body, err := json.Marshal(&jwt.Claims{User: &jwt.User{Owner: "hanzo"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), `"type"`) {
		t.Errorf("an empty class was emitted anyway: %s", body)
	}
}

// The claim reaches this package under the name the issuer writes. A rename on
// either side is a verifier that silently reads every program as a person.
func TestTheClassIsReadUnderTheIssuersName(t *testing.T) {
	var c jwt.Claims
	if err := json.Unmarshal([]byte(`{"type":"application","owner":"hanzo"}`), &c); err != nil {
		t.Fatal(err)
	}
	if c.Type != jwt.Program {
		t.Fatalf("type = %q — the wire name and the field disagree", c.Type)
	}
}
