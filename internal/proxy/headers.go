package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
)

// Extra headers an organization sets on an upstream (upstreams.headers,
// migration 014). They are for non-secret values such as OpenAI-Organization;
// keys go in api_key_env. The control plane refuses invalid ones when they
// are saved, and the gateway drops any that slipped into the database.

const (
	maxExtraHeaders     = 20
	maxHeaderValueBytes = 512
)

var headerNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)

// reservedHeaders are set by the gateway or the transport, or carry
// credentials; an organization cannot set them.
var reservedHeaders = map[string]bool{
	"authorization": true, "proxy-authorization": true, "cookie": true, "set-cookie": true,
	"host": true, "content-length": true, "content-type": true, "content-encoding": true,
	"transfer-encoding": true, "connection": true, "upgrade": true, "te": true, "trailer": true,
	"keep-alive": true, "forwarded": true, "via": true, "traceparent": true, "tracestate": true,
	"baggage": true, "user-agent": true, "accept-encoding": true, "expect": true,
}

// secretNameWords mark a header that carries a credential.
var secretNameWords = []string{"key", "token", "secret", "auth", "password", "passwd", "cookie",
	"signature", "credential", "session"}

// secretValuePrefixes are the forms of common API keys and tokens.
var secretValuePrefixes = []string{"sk-", "sk_", "bearer ", "basic ", "xox", "ghp_", "gho_", "ghs_",
	"github_pat_", "aiza", "akia", "asia", "eyj", "glpat-", "hf_", "pk_live_", "rk_live_"}

// looksSecret reports a value that is probably a credential: a known key
// prefix, or a long run of letters and digits with no spaces.
func looksSecret(value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	for _, p := range secretValuePrefixes {
		if strings.HasPrefix(v, p) {
			return true
		}
	}
	if len(v) < 32 || strings.ContainsAny(v, " \t") {
		return false
	}
	var letters, digits int
	for _, r := range v {
		switch {
		case unicode.IsLetter(r):
			letters++
		case unicode.IsDigit(r):
			digits++
		}
	}
	return letters > 0 && digits > 0
}

// ValidateHeaders checks an upstream's extra headers.
func ValidateHeaders(h map[string]string) error {
	if len(h) > maxExtraHeaders {
		return fmt.Errorf("at most %d headers", maxExtraHeaders)
	}
	names := make([]string, 0, len(h))
	for k := range h {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := checkHeader(name, h[name]); err != nil {
			return err
		}
	}
	return nil
}

func checkHeader(name, value string) error {
	if !headerNameRe.MatchString(name) {
		return fmt.Errorf("header name %q is not valid", name)
	}
	lower := strings.ToLower(name)
	if reservedHeaders[lower] || strings.HasPrefix(lower, "x-forwarded-") || strings.HasPrefix(lower, "proxy-") {
		return fmt.Errorf("header %s is set by the gateway and cannot be configured", name)
	}
	for _, w := range secretNameWords {
		if strings.Contains(lower, w) {
			return fmt.Errorf("header %s looks like a credential; put keys in api_key_env", name)
		}
	}
	if len(value) > maxHeaderValueBytes || strings.IndexFunc(value, func(r rune) bool {
		return r < 0x20 || r == 0x7f
	}) >= 0 {
		return fmt.Errorf("header %s: the value must be at most %d bytes without control characters", name, maxHeaderValueBytes)
	}
	if looksSecret(value) {
		return fmt.Errorf("header %s: the value looks like a secret; put keys in api_key_env", name)
	}
	return nil
}

// safeHeaders returns the headers that pass checkHeader.
func safeHeaders(h map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range h {
		if checkHeader(k, v) == nil {
			out[k] = v
		}
	}
	return out
}

// maxModelsBytes bounds the body a models probe reads.
const maxModelsBytes = 1 << 20

// ProbeResult is the outcome of Probe. It never carries the upstream's body,
// only the model ids found in it.
type ProbeResult struct {
	OK        bool     `json:"ok"`
	LatencyMs int64    `json:"latency_ms"`
	Status    int      `json:"status"`
	Models    []string `json:"models_found"`
	Error     string   `json:"error"`
	// KeySent reports whether the upstream's key went with the request; the
	// caller sets it and Note.
	KeySent bool   `json:"key_sent"`
	Note    string `json:"note,omitempty"`
}

// Probe sends GET {base}/models with the upstream's credentials and headers,
// through the same dialer rules as Forward, and lists the model ids it
// returns. Errors are summarized, never echoed.
func (p *Proxy) Probe(ctx context.Context) ProbeResult {
	start := time.Now()
	res := ProbeResult{Models: []string{}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url("/models"), nil)
	if err != nil {
		res.Error = "invalid upstream url"
		return res
	}
	p.setHeaders(req)
	resp, err := p.client.Do(req)
	res.LatencyMs = time.Since(start).Milliseconds()
	if err != nil {
		var e *Error
		switch {
		case errors.As(classify(err), &e) && e.Code == "upstream_timeout":
			res.Error = "timed out"
		case strings.Contains(err.Error(), "is not allowed"):
			res.Error = "the upstream address is not allowed (private or reserved network)"
		default:
			res.Error = "could not connect to the upstream"
		}
		return res
	}
	defer func() { _ = resp.Body.Close() }()
	res.Status = resp.StatusCode
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		res.Error = fmt.Sprintf("the upstream rejected the credentials (status %d)", resp.StatusCode)
		return res
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		res.Error = fmt.Sprintf("the upstream answered status %d", resp.StatusCode)
		return res
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxModelsBytes))
	if err != nil {
		res.Error = "could not read the upstream's answer"
		return res
	}
	res.OK = true
	res.Models = ModelIDs(data)
	return res
}

// ModelIDs reads the ids of the OpenAI list shape {"data":[{"id":...}]}, which
// Anthropic's list has too, and Ollama's {"models":[{"name":...}]}; anything
// else gives none.
func ModelIDs(data []byte) []string {
	var body struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	ids := []string{}
	if json.Unmarshal(data, &body) != nil {
		return ids
	}
	add := func(id string) {
		if id != "" && len(id) <= 256 && len(ids) < 500 && strings.IndexFunc(id, unicode.IsControl) < 0 {
			ids = append(ids, id)
		}
	}
	for _, m := range body.Data {
		add(m.ID)
	}
	for _, m := range body.Models {
		add(m.Name)
	}
	return ids
}
