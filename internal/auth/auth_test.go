package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestTokenRoundTrip(t *testing.T) {
	secret := []byte("secret")
	id := uuid.New()
	raw, err := IssueToken(secret, id)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseToken(secret, raw)
	if err != nil {
		t.Fatal(err)
	}
	if got != id {
		t.Errorf("got %v, want %v", got, id)
	}
}

func TestParseTokenRejects(t *testing.T) {
	secret := []byte("secret")
	sign := func(m jwt.SigningMethod, key any, c jwt.RegisteredClaims) string {
		raw, err := jwt.NewWithClaims(m, c).SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	sub := uuid.NewString()
	future := jwt.NewNumericDate(time.Now().Add(time.Hour))
	past := jwt.NewNumericDate(time.Now().Add(-time.Hour))

	tests := []struct {
		name string
		raw  string
	}{
		{"wrong secret", sign(jwt.SigningMethodHS256, []byte("other"), jwt.RegisteredClaims{Subject: sub, ExpiresAt: future})},
		{"expired", sign(jwt.SigningMethodHS256, secret, jwt.RegisteredClaims{Subject: sub, ExpiresAt: past})},
		{"no expiry", sign(jwt.SigningMethodHS256, secret, jwt.RegisteredClaims{Subject: sub})},
		{"alg none", sign(jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, jwt.RegisteredClaims{Subject: sub, ExpiresAt: future})},
		{"subject not a user", sign(jwt.SigningMethodHS256, secret, jwt.RegisteredClaims{Subject: "x", ExpiresAt: future})},
		{"garbage", "abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseToken(secret, tt.raw); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestHasRole(t *testing.T) {
	tests := []struct {
		role, min Role
		want      bool
	}{
		{RoleOwner, RoleAdmin, true},
		{RoleAdmin, RoleAdmin, true},
		{RoleMember, RoleAdmin, false},
		{RoleViewer, RoleViewer, true},
		{"", RoleViewer, false},
		{"root", RoleViewer, false},
	}
	for _, tt := range tests {
		if got := HasRole(tt.role, tt.min); got != tt.want {
			t.Errorf("HasRole(%q, %q) = %v, want %v", tt.role, tt.min, got, tt.want)
		}
	}
}

func TestPassword(t *testing.T) {
	hash, err := HashPassword("pw")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(hash, "pw") {
		t.Error("correct password rejected")
	}
	if CheckPassword(hash, "other") || CheckPassword("", "pw") {
		t.Error("wrong password accepted")
	}
}
