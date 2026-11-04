package auth

import (
	"bytes"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The SHA-1 test vectors of RFC 6238, appendix B.
func TestTOTPVectors(t *testing.T) {
	key := []byte("12345678901234567890")
	secret := b32.EncodeToString(key)
	vectors := []struct {
		unix int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, v := range vectors {
		step := TOTPStep(time.Unix(v.unix, 0))
		if got := hotp(key, uint64(step), 8); got != v.want {
			t.Errorf("T=%d: got %s, want %s", v.unix, got, v.want)
		}
		got, err := TOTPCode(secret, step)
		if err != nil || got != v.want[2:] {
			t.Errorf("T=%d 6 digits: got %s %v, want %s", v.unix, got, err, v.want[2:])
		}
	}
}

func TestMatchTOTP(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_015, 0)
	step := TOTPStep(now)
	for d := int64(-1); d <= 1; d++ {
		code, _ := TOTPCode(secret, step+d)
		got, ok := MatchTOTP(secret, code, now)
		if !ok || got != step+d {
			t.Errorf("skew %d: %d %v", d, got, ok)
		}
	}
	for _, d := range []int64{-2, 2} {
		code, _ := TOTPCode(secret, step+d)
		if _, ok := MatchTOTP(secret, code, now); ok {
			t.Errorf("skew %d accepted", d)
		}
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef"} {
		if _, ok := MatchTOTP(secret, bad, now); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestOTPAuthURL(t *testing.T) {
	raw := OTPAuthURL("Guard Spec", "a@example.com", "ABC")
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "otpauth" || u.Host != "totp" {
		t.Fatalf("%s %v", raw, err)
	}
	if u.Query().Get("secret") != "ABC" || u.Query().Get("issuer") != "Guard Spec" ||
		!strings.Contains(u.Path, "Guard Spec:a@example.com") {
		t.Errorf("%s", raw)
	}
}

func TestSecretBox(t *testing.T) {
	if _, err := NewSecretBox(""); err != ErrNoMFAKey {
		t.Errorf("empty key: %v", err)
	}
	if _, err := NewSecretBox(base64.StdEncoding.EncodeToString(make([]byte, 16))); err == nil {
		t.Error("16-byte key accepted")
	}
	box, err := NewSecretBox(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := box.Seal([]byte("secret"), []byte("user-a"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("secret")) {
		t.Error("plaintext in ciphertext")
	}
	if got, err := box.Open(sealed, []byte("user-a")); err != nil || string(got) != "secret" {
		t.Errorf("open: %q %v", got, err)
	}
	if _, err := box.Open(sealed, []byte("user-b")); err == nil {
		t.Error("ciphertext opened for another user")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := box.Open(sealed, []byte("user-a")); err == nil {
		t.Error("tampered ciphertext opened")
	}
}
