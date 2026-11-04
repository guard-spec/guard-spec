// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package channels

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testPayload() Payload {
	project := "11111111-1111-1111-1111-111111111111"
	return Payload{
		Schema: SchemaV1, EventID: "gs1_key", AlertID: "a1", Rule: RuleRef{ID: "r1", Name: "Jailbreak burst (prod)."},
		State: "firing", Severity: "critical", OrgID: "o1", ProjectID: &project, Count: 7, WindowSeconds: 300,
		FirstAt: time.Unix(1700000000, 0).UTC(), LastAt: time.Unix(1700000100, 0).UTC(),
		Group:   map[string]string{"attrs.category": "jailbreak"},
		Samples: []Sample{{EventID: "e1", Type: "detection.blocked", Attrs: map[string]any{"score": 0.97}}},
		Links:   Links{Alert: "https://guard.example.com/ui/alerts/history?id=a1", Requests: "https://guard.example.com/ui/requests"},
	}
}

// capture is a fake receiver that records requests.
type capture struct {
	mu      sync.Mutex
	reqs    []*http.Request
	bodies  [][]byte
	handler func(w http.ResponseWriter, r *http.Request, body []byte)
}

func newCapture(t *testing.T, h func(w http.ResponseWriter, r *http.Request, body []byte)) (*capture, *httptest.Server) {
	c := &capture{handler: h}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.reqs, c.bodies = append(c.reqs, r), append(c.bodies, body)
		c.mu.Unlock()
		if c.handler != nil {
			c.handler(w, r, body)
			return
		}
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)
	return c, srv
}

func (c *capture) last(t *testing.T) (*http.Request, []byte) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.reqs) == 0 {
		t.Fatal("no request received")
	}
	return c.reqs[len(c.reqs)-1], c.bodies[len(c.bodies)-1]
}

func privateGuard() Guard { return Guard{AllowPrivate: true} }

func TestWebhookSignatureVerifies(t *testing.T) {
	const secret = "whsec-test-0123456789"
	c, srv := newCapture(t, nil)
	w := &Webhook{Guard: privateGuard()}
	m := &Message{Kind: KindWebhook, Config: map[string]any{"url": srv.URL + "/hook?token=abc", "allow_private": true},
		Secret: secret, Payload: testPayload(), IdempotencyKey: "gs1_key"}
	if _, err := w.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	r, body := c.last(t)
	if r.Header.Get(HeaderEventID) != "gs1_key" {
		t.Fatalf("event id header %q", r.Header.Get(HeaderEventID))
	}
	if err := Verify([]byte(secret), r.Header.Get(HeaderTimestamp), r.Header.Get(HeaderSignature), body, time.Now()); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
	if err := Verify([]byte("other"), r.Header.Get(HeaderTimestamp), r.Header.Get(HeaderSignature), body, time.Now()); err == nil {
		t.Fatal("wrong secret verified")
	}
	if err := Verify([]byte(secret), r.Header.Get(HeaderTimestamp), r.Header.Get(HeaderSignature), body,
		time.Now().Add(6*time.Minute)); err == nil {
		t.Fatal("stale timestamp verified")
	}
	tampered := append([]byte{}, body...)
	tampered[len(tampered)-2] = 'x'
	if err := Verify([]byte(secret), r.Header.Get(HeaderTimestamp), r.Header.Get(HeaderSignature), tampered, time.Now()); err == nil {
		t.Fatal("tampered body verified")
	}
	var p Payload
	if err := json.Unmarshal(body, &p); err != nil || p.Schema != SchemaV1 || p.Count != 7 || p.Group["attrs.category"] != "jailbreak" {
		t.Fatalf("payload %s", body)
	}
}

func TestSignKnownVector(t *testing.T) {
	// Same vector as docs/alerts.md.
	got := Sign([]byte("secret"), 1700000000, []byte(`{"a":1}`))
	if got != "v1=49f24e537407743fa4a0242bb63b94b9a47ee99cbbe071ccd8a22550ae411686" {
		t.Fatal(got)
	}
}

func TestWebhookRefusesUnsafeTargets(t *testing.T) {
	_, srv := newCapture(t, nil)
	cases := []struct {
		name  string
		cfg   map[string]any
		guard Guard
	}{
		{"http without allow_private", map[string]any{"url": srv.URL}, privateGuard()},
		{"private not allowed by the instance", map[string]any{"url": srv.URL, "allow_private": true}, Guard{}},
		{"metadata address", map[string]any{"url": "https://169.254.169.254/latest", "allow_private": true}, privateGuard()},
		{"credentials", map[string]any{"url": "https://u:p@example.com/x"}, Guard{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &Webhook{Guard: tc.guard}
			_, err := w.Send(context.Background(), &Message{Config: tc.cfg, Secret: "s3cret-value", Payload: testPayload()})
			var ce *Error
			if !errors.As(err, &ce) || !ce.Permanent {
				t.Fatalf("err %v, want a permanent refusal", err)
			}
		})
	}
	// An https URL that resolves to loopback is refused by the dialer.
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer tls.Close()
	w := &Webhook{Guard: NewGuard(false)}
	_, err := w.Send(context.Background(), &Message{Config: map[string]any{"url": tls.URL + "/hook?sig=SECRETQUERY"},
		Secret: "s3cret-value", Payload: testPayload()})
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("loopback over https: %v", err)
	}
	if strings.Contains(err.Error(), "SECRETQUERY") || strings.Contains(err.Error(), "/hook") {
		t.Fatalf("error leaks the url: %v", err)
	}
}

func TestWebhookStatusClasses(t *testing.T) {
	cases := []struct {
		status    int
		retry     string
		permanent bool
		after     time.Duration
	}{
		{400, "", true, 0},
		{404, "", true, 0},
		{408, "", false, 0},
		{429, "7", false, 7 * time.Second},
		{500, "", false, 0},
		{302, "", true, 0},
	}
	for _, tc := range cases {
		_, srv := newCapture(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
			if tc.retry != "" {
				w.Header().Set("Retry-After", tc.retry)
			}
			if tc.status == 302 {
				w.Header().Set("Location", "http://169.254.169.254/")
			}
			w.WriteHeader(tc.status)
		})
		w := &Webhook{Guard: privateGuard()}
		_, err := w.Send(context.Background(), &Message{Config: map[string]any{"url": srv.URL, "allow_private": true},
			Secret: "s3cret-value", Payload: testPayload()})
		var ce *Error
		if !errors.As(err, &ce) || ce.Permanent != tc.permanent || ce.Status != tc.status || ce.RetryAfter != tc.after {
			t.Fatalf("status %d: %+v", tc.status, ce)
		}
	}
}

func TestTelegramSendEscapesMarkdownV2(t *testing.T) {
	const token = "123456:ABCdefGhIJKlmnoPQRstuVWXyz0123456789"
	c, srv := newCapture(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		_, _ = io.WriteString(w, `{"ok":true,"result":{"message_id":42}}`)
	})
	tg := &Telegram{Base: srv.URL, Client: srv.Client()}
	res, err := tg.Send(context.Background(), &Message{Kind: KindTelegram, Target: "987", Secret: token, Payload: testPayload()})
	if err != nil || res.RemoteID != "42" {
		t.Fatalf("%v %+v", err, res)
	}
	r, body := c.last(t)
	if r.URL.Path != "/bot"+token+"/sendMessage" {
		t.Fatalf("path %s", r.URL.Path)
	}
	var sent struct {
		ChatID    string `json:"chat_id"`
		Text      string `json:"text"`
		ParseMode string `json:"parse_mode"`
	}
	_ = json.Unmarshal(body, &sent)
	if sent.ChatID != "987" || sent.ParseMode != "MarkdownV2" {
		t.Fatalf("%+v", sent)
	}
	if !strings.Contains(sent.Text, `Jailbreak burst \(prod\)\.`) || !strings.Contains(sent.Text, `\[CRITICAL\]`) {
		t.Fatalf("not escaped: %s", sent.Text)
	}
	if got := EscapeMarkdownV2("a_b*c[d]e(f)g~h`i>j#k+l-m=n|o{p}q.r!s\\"); got !=
		`a\_b\*c\[d\]e\(f\)g\~h\`+"`"+`i\>j\#k\+l\-m\=n\|o\{p\}q\.r\!s\\` {
		t.Fatalf("escape: %s", got)
	}
}

func TestTelegramErrorsAreRedacted(t *testing.T) {
	const token = "123456:ABCdefGhIJKlmnoPQRstuVWXyz0123456789"
	_, srv := newCapture(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		w.WriteHeader(429)
		_, _ = io.WriteString(w, `{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 9","parameters":{"retry_after":9}}`)
	})
	tg := &Telegram{Base: srv.URL, Client: srv.Client()}
	_, err := tg.Send(context.Background(), &Message{Target: "1", Secret: token, Payload: testPayload()})
	var ce *Error
	if !errors.As(err, &ce) || ce.Permanent || ce.RetryAfter != 9*time.Second {
		t.Fatalf("%+v", ce)
	}
	// A connection error names the URL, which holds the token.
	dead := &Telegram{Base: "http://127.0.0.1:1", Client: &http.Client{Timeout: time.Second}}
	_, err = dead.Send(context.Background(), &Message{Target: "1", Secret: token, Payload: testPayload()})
	if err == nil || strings.Contains(err.Error(), "ABCdef") || strings.Contains(err.Error(), "/bot") {
		t.Fatalf("token leaked: %v", err)
	}
}

func TestTelegramStartCode(t *testing.T) {
	var u TelegramUpdate
	_ = json.Unmarshal([]byte(`{"update_id":1,"message":{"text":"/start abc123","chat":{"id":555,"type":"private"}}}`), &u)
	if chat, code := u.StartCode(); chat != "555" || code != "abc123" {
		t.Fatal(chat, code)
	}
	_ = json.Unmarshal([]byte(`{"update_id":2,"message":{"text":"/start abc123","chat":{"id":-5,"type":"group"}}}`), &u)
	if _, code := u.StartCode(); code != "" {
		t.Fatal("group chats cannot link")
	}
}

func TestSlackBotAndWebhook(t *testing.T) {
	c, srv := newCapture(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		switch r.URL.Path {
		case "/chat.postMessage":
			_, _ = io.WriteString(w, `{"ok":true,"ts":"1700.1"}`)
		case "/users.lookupByEmail":
			if r.URL.Query().Get("email") == "a@example.com" {
				_, _ = io.WriteString(w, `{"ok":true,"user":{"id":"U123"}}`)
				return
			}
			_, _ = io.WriteString(w, `{"ok":false,"error":"users_not_found"}`)
		case "/hook":
			_, _ = io.WriteString(w, "ok")
		}
	})
	s := &Slack{Base: srv.URL, Client: srv.Client(), Guard: privateGuard()}
	res, err := s.Send(context.Background(), &Message{Kind: KindSlack, Target: "U123", Secret: "xoxb-test-token",
		Config: map[string]any{"mode": "bot"}, Payload: testPayload()})
	if err != nil || res.RemoteID != "1700.1" {
		t.Fatalf("%v %+v", err, res)
	}
	r, body := c.last(t)
	if r.Header.Get("Authorization") != "Bearer xoxb-test-token" {
		t.Fatal("no bearer token")
	}
	var msg struct {
		Channel string           `json:"channel"`
		Blocks  []map[string]any `json:"blocks"`
	}
	_ = json.Unmarshal(body, &msg)
	if msg.Channel != "U123" || len(msg.Blocks) < 2 || msg.Blocks[0]["type"] != "header" {
		t.Fatalf("%s", body)
	}
	id, err := s.LookupByEmail(context.Background(), "xoxb-test-token", "a@example.com")
	if err != nil || id != "U123" {
		t.Fatal(id, err)
	}
	if _, err := s.LookupByEmail(context.Background(), "xoxb-test-token", "b@example.com"); err == nil {
		t.Fatal("unknown email found")
	}
	// Incoming webhook: http://127.0.0.1 passes only because the instance
	// allows private URLs.
	if _, err := s.Send(context.Background(), &Message{Kind: KindSlack, Secret: srv.URL + "/hook",
		Config: map[string]any{"mode": "webhook"}, Payload: testPayload()}); err != nil {
		t.Fatal(err)
	}
	strict := &Slack{Base: srv.URL, Client: srv.Client(), Guard: Guard{}}
	_, err = strict.Send(context.Background(), &Message{Kind: KindSlack, Secret: srv.URL + "/hook/T000/B000/XXXX",
		Config: map[string]any{"mode": "webhook"}, Payload: testPayload()})
	if err == nil || strings.Contains(err.Error(), "XXXX") {
		t.Fatalf("strict webhook: %v", err)
	}
}

func TestSlackRateLimited(t *testing.T) {
	_, srv := newCapture(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(429)
		_, _ = io.WriteString(w, `{"ok":false,"error":"ratelimited"}`)
	})
	s := &Slack{Base: srv.URL, Client: srv.Client()}
	_, err := s.Send(context.Background(), &Message{Target: "C1", Secret: "xoxb-x", Payload: testPayload()})
	var ce *Error
	if !errors.As(err, &ce) || ce.Permanent || ce.RetryAfter != 30*time.Second {
		t.Fatalf("%+v", ce)
	}
}

func TestTeamsAdaptiveCard(t *testing.T) {
	c, srv := newCapture(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) { w.WriteHeader(202) })
	tm := &Teams{Guard: privateGuard()}
	if _, err := tm.Send(context.Background(), &Message{Secret: srv.URL + "/workflows/x?sig=abc", Payload: testPayload()}); err != nil {
		t.Fatal(err)
	}
	_, body := c.last(t)
	var msg struct {
		Type        string `json:"type"`
		Attachments []struct {
			ContentType string         `json:"contentType"`
			Content     map[string]any `json:"content"`
		} `json:"attachments"`
	}
	_ = json.Unmarshal(body, &msg)
	if msg.Type != "message" || len(msg.Attachments) != 1 ||
		msg.Attachments[0].ContentType != "application/vnd.microsoft.card.adaptive" ||
		msg.Attachments[0].Content["type"] != "AdaptiveCard" {
		t.Fatalf("%s", body)
	}
}

func TestA2A(t *testing.T) {
	for _, version := range []string{"1.0", "0.3"} {
		t.Run(version, func(t *testing.T) {
			var cardHits atomic.Int32
			var srvURL string
			c, srv := newCapture(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
				if r.URL.Path == "/.well-known/agent-card.json" {
					cardHits.Add(1)
					if version == "1.0" {
						_, _ = io.WriteString(w, `{"name":"sec","supportedInterfaces":[{"url":"`+srvURL+`/rpc","protocolBinding":"JSONRPC","protocolVersion":"1.0"}],
						"securitySchemes":{"key":{"apiKeySecurityScheme":{"location":"header","name":"X-Agent-Key"}}}}`)
						return
					}
					_, _ = io.WriteString(w, `{"name":"sec","url":"`+srvURL+`/rpc","protocolVersion":"0.3.0","preferredTransport":"JSONRPC",
					"securitySchemes":{"bearer":{"type":"http","scheme":"bearer"}}}`)
					return
				}
				if version == "1.0" {
					_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":"x","result":{"task":{"id":"task-1","contextId":"c"}}}`)
					return
				}
				_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":"x","result":{"kind":"task","id":"task-03"}}`)
			})
			srvURL = srv.URL
			a := &A2A{Guard: privateGuard()}
			m := &Message{Kind: KindA2A, Config: map[string]any{"agent_card_url": srv.URL, "allow_private": true},
				Secret: "agent-secret", Payload: testPayload(), IdempotencyKey: "gs1_key"}
			for i := 0; i < 2; i++ {
				res, err := a.Send(context.Background(), m)
				if err != nil {
					t.Fatal(err)
				}
				want := map[string]string{"1.0": "task-1", "0.3": "task-03"}[version]
				if res.RemoteID != want {
					t.Fatalf("task id %q", res.RemoteID)
				}
			}
			if cardHits.Load() != 1 {
				t.Fatalf("agent card fetched %d times, want 1 (cached)", cardHits.Load())
			}
			r, body := c.last(t)
			var rpc struct {
				Method string `json:"method"`
				Params struct {
					Message struct {
						MessageID string           `json:"messageId"`
						Role      string           `json:"role"`
						Parts     []map[string]any `json:"parts"`
					} `json:"message"`
				} `json:"params"`
			}
			_ = json.Unmarshal(body, &rpc)
			if rpc.Params.Message.MessageID != "gs1_key" || len(rpc.Params.Message.Parts) != 2 {
				t.Fatalf("%s", body)
			}
			if version == "1.0" {
				if rpc.Method != "SendMessage" || r.Header.Get("X-Agent-Key") != "agent-secret" ||
					r.Header.Get("A2A-Version") != "1.0" || rpc.Params.Message.Role != "ROLE_USER" {
					t.Fatalf("v1.0 request %s %v", body, r.Header)
				}
				if _, ok := rpc.Params.Message.Parts[1]["data"].(map[string]any); !ok {
					t.Fatal("no data part")
				}
			} else if rpc.Method != "message/send" || r.Header.Get("Authorization") != "Bearer agent-secret" ||
				rpc.Params.Message.Parts[0]["kind"] != "text" || rpc.Params.Message.Parts[1]["kind"] != "data" {
				t.Fatalf("v0.3 request %s", body)
			}
		})
	}
}

func TestA2AErrorIsPermanent(t *testing.T) {
	var srvURL string
	_, srv := newCapture(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if strings.HasSuffix(r.URL.Path, ".json") {
			_, _ = io.WriteString(w, `{"supportedInterfaces":[{"url":"`+srvURL+`/rpc","protocolBinding":"JSONRPC","protocolVersion":"1.0"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":"x","error":{"code":-32601,"message":"Method not found"}}`)
	})
	srvURL = srv.URL
	a := &A2A{Guard: privateGuard()}
	_, err := a.Send(context.Background(), &Message{Config: map[string]any{"agent_card_url": srv.URL + "/.well-known/agent-card.json",
		"allow_private": true}, Payload: testPayload()})
	var ce *Error
	if !errors.As(err, &ce) || !ce.Permanent || !strings.Contains(ce.Msg, "-32601") {
		t.Fatalf("%v", err)
	}
}

// fakeSMTP accepts one message and records it.
func fakeSMTP(t *testing.T) (string, chan string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	got := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		say := func(s string) { _, _ = io.WriteString(conn, s+"\r\n") }
		say("220 fake ESMTP")
		var data strings.Builder
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if inData {
				if line == ".\r\n" {
					inData = false
					got <- data.String()
					say("250 queued")
					continue
				}
				data.WriteString(line)
				continue
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(cmd, "EHLO"):
				say("250-fake")
				say("250 AUTH PLAIN")
			case strings.HasPrefix(cmd, "AUTH"):
				say("235 ok")
			case strings.HasPrefix(cmd, "DATA"):
				inData = true
				say("354 go")
			case strings.HasPrefix(cmd, "QUIT"):
				say("221 bye")
				return
			default:
				say("250 ok")
			}
		}
	}()
	return ln.Addr().String(), got
}

func TestEmailEnglishAndVietnamese(t *testing.T) {
	for _, lang := range []string{"en", "vi"} {
		addr, got := fakeSMTP(t)
		e := &Email{SMTP: SMTPConfig{URL: "smtp://alerts:smtp-pass-123@" + addr, From: "Guard Spec <alerts@example.com>"}}
		if _, err := e.Send(context.Background(), &Message{Kind: KindEmail, Target: "sec@example.com", Lang: lang,
			Payload: testPayload(), IdempotencyKey: "gs1_key"}); err != nil {
			t.Fatal(err)
		}
		msg := <-got
		parts := strings.SplitN(msg, "\r\n\r\n", 2)
		body, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(parts[1], "\r\n", ""))
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]string{"en": "Open the alert", "vi": "Mở cảnh báo"}[lang]
		if !strings.Contains(string(body), want) || !strings.Contains(parts[0], "Subject: ") {
			t.Fatalf("%s: %s\n%s", lang, parts[0], body)
		}
	}
}

func TestEmailFailureIsRedacted(t *testing.T) {
	e := &Email{SMTP: SMTPConfig{URL: "smtp://alerts:smtp-pass-123@127.0.0.1:1", From: "alerts@example.com"}}
	_, err := e.Send(context.Background(), &Message{Target: "sec@example.com", Payload: testPayload()})
	if err == nil || strings.Contains(err.Error(), "smtp-pass-123") {
		t.Fatalf("%v", err)
	}
	// Header injection through the recipient is refused.
	_, err = e.Send(context.Background(), &Message{Target: "a@example.com\r\nBcc: x@example.com", Payload: testPayload()})
	var ce *Error
	if !errors.As(err, &ce) || !ce.Permanent {
		t.Fatalf("%v", err)
	}
}

func TestRedact(t *testing.T) {
	in := `Post "https://hooks.slack.com/services/T0/B0/SECRET?x=1": dial tcp: bot 123456:ABCdefGhIJKlmnoPQRstuVWXyz0123456789 xoxb-1-2-abc mysecretvalue`
	out := Redact(in, "mysecretvalue")
	for _, leak := range []string{"SECRET", "services", "ABCdef", "xoxb-1", "mysecretvalue", "x=1"} {
		if strings.Contains(out, leak) {
			t.Fatalf("%q leaks %q", out, leak)
		}
	}
	if !strings.Contains(out, "https://hooks.slack.com/[redacted]") {
		t.Fatalf("%q", out)
	}
}

func TestRenderHasNoUnknownText(t *testing.T) {
	p := testPayload()
	for _, lang := range []string{"en", "vi"} {
		s := Render(&p, lang)
		if !strings.Contains(s.Title, "CRITICAL") || len(s.Lines) < 3 {
			t.Fatalf("%+v", s)
		}
	}
}
