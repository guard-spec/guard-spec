package proxy

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestValidateBaseURL(t *testing.T) {
	for _, ok := range []string{"https://api.openai.com/v1", "http://ollama:11434/v1", "http://10.0.0.5:8000",
		"http://127.0.0.1:11434/v1", "https://[2001:db8::1]/v1"} {
		if err := ValidateBaseURL(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "ftp://x/v1", "/v1", "http://", "http://user:pw@host/v1", "http://host/v1?key=1",
		"http://host/v1#x", "http://169.254.169.254/latest", "http://[fe80::1]/", "http://0.0.0.0:80/",
		"http://metadata.google.internal/", "http://224.0.0.1/", "https://x/" + strings.Repeat("a", 2100)} {
		if err := ValidateBaseURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestDialControl(t *testing.T) {
	allow, deny := dialControl(false), dialControl(true)
	for _, addr := range []string{"169.254.169.254:80", "[fd00:ec2::254]:80", "100.100.100.200:80", "192.0.0.192:80",
		"0.0.0.0:80", "[fe80::1]:80", "224.0.0.1:80"} {
		if allow("tcp", addr, nil) == nil || deny("tcp", addr, nil) == nil {
			t.Errorf("%s allowed", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:11434", "[::1]:80", "10.1.2.3:80", "172.16.0.1:80", "192.168.1.1:80",
		"[fd12::1]:80", "100.64.0.1:80", "100.127.255.254:80"} {
		if err := allow("tcp", addr, nil); err != nil {
			t.Errorf("%s refused without DenyPrivate: %v", addr, err)
		}
		if deny("tcp", addr, nil) == nil {
			t.Errorf("%s allowed with DenyPrivate", addr)
		}
	}
	for _, addr := range []string{"93.184.216.34:443", "[2606:4700::1]:443", "100.128.0.1:80"} {
		if err := deny("tcp", addr, nil); err != nil {
			t.Errorf("public %s refused: %v", addr, err)
		}
	}
}

// With DenyPrivate a loopback upstream is refused at dial time.
func TestDenyPrivateLoopback(t *testing.T) {
	p, err := New(Config{BaseURL: "http://127.0.0.1:1/v1", Timeout: time.Second, DenyPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Forward(context.Background(), "/chat/completions", []byte(`{}`))
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("err = %v", err)
	}
}

// The dialer refuses link-local addresses even when the URL passed New, as a
// name that resolves to one would.
func TestDialRefusesLinkLocal(t *testing.T) {
	p, err := New(Config{BaseURL: "http://169.254.169.254/v1", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Forward(context.Background(), "/chat/completions", []byte(`{}`))
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("err = %v", err)
	}
}
