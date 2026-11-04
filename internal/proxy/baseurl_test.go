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
