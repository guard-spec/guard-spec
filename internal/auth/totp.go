package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP uses HMAC-SHA1, which authenticator apps expect
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP (RFC 6238): HMAC-SHA1, 6 digits, 30-second steps, one step of skew
// either way. Codes are compared in constant time; refusing a code a second
// time is the caller's job (user_mfa.last_used_step).

const (
	totpDigits = 6
	totpPeriod = 30
	totpSkew   = 1
	// totpSecretBytes is the length RFC 4226 recommends (160 bits).
	totpSecretBytes = 20
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a random secret, base32 without padding.
func NewTOTPSecret() (string, error) {
	buf := make([]byte, totpSecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return b32.EncodeToString(buf), nil
}

// TOTPStep is the time step of t.
func TOTPStep(t time.Time) int64 { return t.Unix() / totpPeriod }

// TOTPCode returns the code of secret (base32) at step.
func TOTPCode(secret string, step int64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimRight(secret, "=")))
	if err != nil {
		return "", fmt.Errorf("totp secret: %w", err)
	}
	return hotp(key, uint64(step), totpDigits), nil
}

// hotp is RFC 4226 with SHA-1.
func hotp(key []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}

// MatchTOTP checks code against the steps around now and returns the step it
// matched. All candidate steps are compared, so the time taken does not tell
// which one matched.
func MatchTOTP(secret, code string, now time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return 0, false
	}
	cur := TOTPStep(now)
	matched, ok := int64(0), false
	for d := int64(-totpSkew); d <= totpSkew; d++ {
		want, err := TOTPCode(secret, cur+d)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 && !ok {
			matched, ok = cur+d, true
		}
	}
	return matched, ok
}

// OTPAuthURL is the provisioning URI authenticator apps read from a QR code.
func OTPAuthURL(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(totpPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// SecretBox encrypts 2FA secrets with AES-256-GCM. The key is MFA_ENC_KEY;
// the additional data (the user id) binds a ciphertext to its row.
type SecretBox struct{ aead cipher.AEAD }

// ErrNoMFAKey means MFA_ENC_KEY is not set.
var ErrNoMFAKey = errors.New("MFA_ENC_KEY is not set")

// NewSecretBox parses MFA_ENC_KEY: 32 bytes, standard or URL-safe base64.
// An empty value returns ErrNoMFAKey.
func NewSecretBox(b64 string) (*SecretBox, error) {
	b64 = strings.TrimSpace(b64)
	if b64 == "" {
		return nil, ErrNoMFAKey
	}
	var key []byte
	var err error
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if key, err = enc.DecodeString(b64); err == nil {
			break
		}
	}
	if err != nil || len(key) != 32 {
		return nil, errors.New("MFA_ENC_KEY must be 32 random bytes in base64 (for example: openssl rand -base64 32)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &SecretBox{aead: aead}, nil
}

// Seal encrypts plain; the result is nonce || ciphertext.
func (b *SecretBox) Seal(plain, ad []byte) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return b.aead.Seal(nonce, nonce, plain, ad), nil
}

// Open decrypts what Seal returned with the same additional data.
func (b *SecretBox) Open(sealed, ad []byte) ([]byte, error) {
	n := b.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("ciphertext too short")
	}
	return b.aead.Open(nil, sealed[:n], sealed[n:], ad)
}
