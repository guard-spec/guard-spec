package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestTokenRoundTrip(t *testing.T) {
	secret := []byte("secret")
	id, sid := uuid.New(), uuid.New()
	raw, err := IssueSessionToken(secret, id, sid, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	got, gotSID, err := ParseSessionToken(secret, raw)
	if err != nil {
		t.Fatal(err)
	}
	if got != id || gotSID != sid {
		t.Errorf("got %v %v, want %v %v", got, gotSID, id, sid)
	}
	// A session token is not an mfa_token, and the other way round.
	if _, _, _, err := ParseMFAToken(secret, raw); err == nil {
		t.Error("session token accepted as mfa_token")
	}
	mfa, err := IssueMFAToken(secret, id, uuid.New(), PurposeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ParseSessionToken(secret, mfa); err == nil {
		t.Error("mfa_token accepted as session token")
	}
	u, _, purpose, err := ParseMFAToken(secret, mfa)
	if err != nil || u != id || purpose != PurposeEnroll {
		t.Errorf("mfa token: %v %v %v", u, purpose, err)
	}
}

func TestParseTokenRejects(t *testing.T) {
	secret := []byte("secret")
	type cl struct {
		jwt.RegisteredClaims
		SID string `json:"sid,omitempty"`
	}
	sign := func(m jwt.SigningMethod, key any, c cl) string {
		raw, err := jwt.NewWithClaims(m, c).SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	sub, sid := uuid.NewString(), uuid.NewString()
	future := jwt.NewNumericDate(time.Now().Add(time.Hour))
	past := jwt.NewNumericDate(time.Now().Add(-time.Hour))
	aud := jwt.ClaimStrings{"session"}
	rc := func(sub string, exp *jwt.NumericDate, aud jwt.ClaimStrings) jwt.RegisteredClaims {
		return jwt.RegisteredClaims{Subject: sub, ExpiresAt: exp, Audience: aud}
	}

	tests := []struct {
		name string
		raw  string
	}{
		{"wrong secret", sign(jwt.SigningMethodHS256, []byte("other"), cl{rc(sub, future, aud), sid})},
		{"expired", sign(jwt.SigningMethodHS256, secret, cl{rc(sub, past, aud), sid})},
		{"no expiry", sign(jwt.SigningMethodHS256, secret, cl{rc(sub, nil, aud), sid})},
		{"alg none", sign(jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, cl{rc(sub, future, aud), sid})},
		{"subject not a user", sign(jwt.SigningMethodHS256, secret, cl{rc("x", future, aud), sid})},
		{"no session id (pre-013 token)", sign(jwt.SigningMethodHS256, secret, cl{rc(sub, future, aud), ""})},
		{"no audience", sign(jwt.SigningMethodHS256, secret, cl{rc(sub, future, nil), sid})},
		{"mfa audience", sign(jwt.SigningMethodHS256, secret, cl{rc(sub, future, jwt.ClaimStrings{"mfa"}), sid})},
		{"garbage", "abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := ParseSessionToken(secret, tt.raw); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestCheckOrgSecurity(t *testing.T) {
	now := time.Now()
	pw := Session{Method: MethodPassword, CreatedAt: now.Add(-time.Hour)}
	pwMFA := Session{Method: MethodPassword, MFA: true, CreatedAt: now.Add(-time.Hour)}
	google := Session{Method: MethodGoogle, CreatedAt: now.Add(-time.Hour)}
	old := Session{Method: MethodPassword, CreatedAt: now.Add(-3 * time.Hour)}
	tests := []struct {
		name          string
		s             Session
		requireMFA    bool
		ssoSatisfies  bool
		allowed       []string
		lifetimeHours int
		want          string
	}{
		{"defaults", pw, false, false, nil, 12, ""},
		{"mfa required, none", pw, true, false, nil, 12, "mfa_required"},
		{"mfa required, verified", pwMFA, true, false, nil, 12, ""},
		{"sso satisfies", google, true, true, nil, 12, ""},
		{"sso does not satisfy", google, true, false, nil, 12, "mfa_required"},
		{"sso satisfies only sso", pw, true, true, nil, 12, "mfa_required"},
		{"method not allowed", pw, false, false, []string{"google"}, 12, "login_method_not_allowed"},
		{"method allowed", google, false, false, []string{"password", "google"}, 12, ""},
		{"empty list allows nothing", pw, false, false, []string{}, 12, "login_method_not_allowed"},
		{"lifetime passed", old, false, false, nil, 2, "session_expired"},
		{"lifetime ok", old, false, false, nil, 4, ""},
	}
	for _, tt := range tests {
		got, _ := checkOrgSecurity(tt.s, tt.requireMFA, tt.ssoSatisfies, tt.allowed, tt.lifetimeHours, now)
		if got != tt.want {
			t.Errorf("%s: got %q, want %q", tt.name, got, tt.want)
		}
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
