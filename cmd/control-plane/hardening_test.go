package main

import (
	"net"
	"testing"
	"time"
)

func TestResolveClientIP(t *testing.T) {
	nets, err := parseTrustedProxies("10.0.0.0/8, 192.168.1.5")
	if err != nil {
		t.Fatal(err)
	}
	proxy := net.ParseIP("10.1.2.3")
	tests := []struct {
		name   string
		nets   bool
		remote net.IP
		xff    string
		want   string
	}{
		{"no trusted proxies: header ignored", false, proxy, "1.2.3.4", "10.1.2.3"},
		{"untrusted remote: header ignored", true, net.ParseIP("8.8.8.8"), "1.2.3.4", "8.8.8.8"},
		{"trusted proxy", true, proxy, "1.2.3.4", "1.2.3.4"},
		// A client cannot choose its address by sending the header: the
		// rightmost untrusted hop wins.
		{"spoofed left entry", true, proxy, "6.6.6.6, 1.2.3.4", "1.2.3.4"},
		{"chain of trusted proxies", true, proxy, "1.2.3.4, 192.168.1.5, 10.9.9.9", "1.2.3.4"},
		{"garbage hop", true, proxy, "1.2.3.4, nonsense", "10.1.2.3"},
		{"empty header", true, proxy, "", "10.1.2.3"},
	}
	for _, tt := range tests {
		n := nets
		if !tt.nets {
			n = nil
		}
		if got := resolveClientIP(n, tt.remote, tt.xff); got != tt.want {
			t.Errorf("%s: got %s, want %s", tt.name, got, tt.want)
		}
	}
	for _, bad := range []string{"10.0.0.0/33", "not-an-ip", "1.2.3"} {
		if _, err := parseTrustedProxies(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestMaskEmail(t *testing.T) {
	for in, want := range map[string]string{
		"Alice@Example.com": "a***@example.com",
		"  bob@corp.io ":    "b***@corp.io",
		"hunter2-password":  "(not an email)",
		"@nouser.com":       "(not an email)",
		"has space@x.com":   "(not an email)",
	} {
		if got := maskEmail(in); got != want {
			t.Errorf("maskEmail(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMFALockFor(t *testing.T) {
	for failures, want := range map[int]time.Duration{
		1: 0, 9: 0, 10: 15 * time.Minute, 11: 0, 15: 30 * time.Minute, 20: time.Hour,
		45: 24 * time.Hour, 100: 24 * time.Hour,
	} {
		if got := mfaLockFor(failures); got != want {
			t.Errorf("mfaLockFor(%d) = %v, want %v", failures, got, want)
		}
	}
}
