// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package main

// Regression tests of the security review of PR #32 (alerts backend).

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/giaplee/guard-spec/internal/alerts"
	"github.com/giaplee/guard-spec/internal/auth"
	"github.com/giaplee/guard-spec/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// fakeMailer is an SMTP server that keeps every message.
type fakeMailer struct {
	addr string
	mu   sync.Mutex
	msgs []mailMsg
}

type mailMsg struct {
	to   []string
	body string // decoded text
}

func newFakeMailer(t *testing.T) *fakeMailer {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	m := &fakeMailer{addr: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go m.serve(conn)
		}
	}()
	return m
}

func (m *fakeMailer) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	say := func(s string) { _, _ = io.WriteString(conn, s+"\r\n") }
	say("220 fake ESMTP")
	var to []string
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
				parts := strings.SplitN(data.String(), "\r\n\r\n", 2)
				body, _ := base64.StdEncoding.DecodeString(strings.ReplaceAll(parts[len(parts)-1], "\r\n", ""))
				m.mu.Lock()
				m.msgs = append(m.msgs, mailMsg{to: to, body: string(body)})
				m.mu.Unlock()
				to, data = nil, strings.Builder{}
				say("250 queued")
				continue
			}
			data.WriteString(line)
			continue
		}
		cmd := strings.TrimSpace(line)
		switch up := strings.ToUpper(cmd); {
		case strings.HasPrefix(up, "EHLO"):
			say("250 fake")
		case strings.HasPrefix(up, "RCPT TO:"):
			to = append(to, strings.Trim(cmd[len("RCPT TO:"):], "<> "))
			say("250 ok")
		case strings.HasPrefix(up, "DATA"):
			inData = true
			say("354 go")
		case strings.HasPrefix(up, "QUIT"):
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

// to returns the messages sent to addr.
func (m *fakeMailer) to(addr string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, msg := range m.msgs {
		for _, t := range msg.to {
			if strings.EqualFold(t, addr) {
				out = append(out, msg.body)
			}
		}
	}
	return out
}

func (h *alertsHarness) telegramUpdate(chat int64, chatType, text string) int {
	h.t.Helper()
	body := fmt.Sprintf(`{"update_id":1,"message":{"text":%q,"chat":{"id":%d,"type":%q}}}`, text, chat, chatType)
	req := httptest.NewRequest("POST", "/v1/integrations/telegram/webhook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Telegram-Bot-Api-Secret-Token", telegramHookKey)
	resp, err := h.app.Test(req, -1)
	if err != nil {
		h.t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// M1: a shared Telegram channel on the instance bot posts only to a chat
// that sent its /link code.
func TestTelegramChannelNeedsLink(t *testing.T) {
	h := newAlertsHarness(t)
	org, _, admin := h.org(auth.RoleAdmin)
	base := "/v1/organizations/" + org.String()
	if code, out := h.do("POST", base+"/notification-channels", admin,
		`{"name":"tg","kind":"telegram","config":{"chat_id":"987654321"}}`); code != 400 {
		t.Fatalf("instance-bot channel with a chosen chat_id: %d %v", code, out)
	}
	ch := h.expect(201, "POST", base+"/notification-channels", admin, `{"name":"tg","kind":"telegram","config":{}}`)
	id := ch["id"].(string)
	if ch["verified"] != false {
		t.Fatalf("new channel verified: %v", ch)
	}
	test := h.expect(200, "POST", base+"/notification-channels/"+id+"/test", admin, "")
	if test["ok"] != false || !strings.Contains(fmt.Sprint(test["error"]), "not verified") {
		t.Fatalf("unverified test: %v", test)
	}
	if h.fake.count("telegram", "") != 0 {
		t.Fatal("posted to an unverified chat")
	}
	link := h.expect(200, "POST", base+"/notification-channels/"+id+"/telegram-link", admin, "")
	code := link["code"].(string)
	if link["command"] != "/link@guard_test_bot "+code {
		t.Fatalf("link %v", link)
	}
	h.telegramUpdate(-100555, "supergroup", "/link@guard_test_bot "+code)
	ch = h.expect(200, "GET", base+"/notification-channels/"+id, admin, "")
	if ch["verified"] != true || ch["config"].(map[string]any)["chat_id"] != "-100555" {
		t.Fatalf("after /link: %v", ch)
	}
	// Single use: another chat cannot take the channel over.
	h.telegramUpdate(-100777, "group", "/link "+code)
	ch = h.expect(200, "GET", base+"/notification-channels/"+id, admin, "")
	if ch["config"].(map[string]any)["chat_id"] != "-100555" {
		t.Fatal("a used /link code worked again")
	}
	before := h.fake.count("telegram", "-100555") // the bot's "Linked" reply
	if test := h.expect(200, "POST", base+"/notification-channels/"+id+"/test", admin, ""); test["ok"] != true {
		t.Fatalf("verified test: %v", test)
	}
	if h.fake.count("telegram", "-100555") != before+1 {
		t.Fatal("verified chat got nothing")
	}
	// Another org cannot redeem codes or see the channel.
	_, _, adminB := h.org(auth.RoleAdmin)
	if c, _ := h.do("POST", base+"/notification-channels/"+id+"/telegram-link", adminB, ""); c != 403 {
		t.Fatalf("other org started a link: %d", c)
	}
}

var linkRe = regexp.MustCompile(`https://guard\.example\.com/v1/integrations/email/confirm\?token=([A-Za-z0-9_-]+)`)

// M2: a shared mailbox gets alerts only after it confirmed (double opt-in).
func TestEmailChannelDoubleOptIn(t *testing.T) {
	h := newAlertsHarness(t)
	org, _, admin := h.org(auth.RoleAdmin)
	base := "/v1/organizations/" + org.String()
	a, b := "soc-"+uuid.NewString()[:8]+"@example.com", "victim-"+uuid.NewString()[:8]+"@example.net"
	ch := h.expect(201, "POST", base+"/notification-channels", admin,
		`{"name":"soc","kind":"email","config":{"to":["`+a+`","`+b+`"]}}`)
	id := ch["id"].(string)
	if ch["verified"] != false || len(ch["addresses"].([]any)) != 2 {
		t.Fatalf("channel %v", ch)
	}
	waitFor(t, 5*time.Second, "confirmation mails", func() bool { return len(h.smtp.to(a)) == 1 && len(h.smtp.to(b)) == 1 })
	if strings.Contains(h.smtp.to(b)[0], "CRITICAL") {
		t.Fatal("the confirmation mail carries an alert")
	}
	token := linkRe.FindStringSubmatch(h.smtp.to(a)[0])
	if token == nil {
		t.Fatalf("no link in %q", h.smtp.to(a)[0])
	}
	confirm := func(tok string) int {
		resp, err := h.app.Test(httptest.NewRequest("GET", "/v1/integrations/email/confirm?token="+tok, nil), -1)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if c := confirm(token[1]); c != 200 {
		t.Fatalf("confirm: %d", c)
	}
	if c := confirm(token[1]); c != 404 {
		t.Fatalf("second confirm: %d", c)
	}
	ch = h.expect(200, "GET", base+"/notification-channels/"+id, admin, "")
	if ch["verified"] != true {
		t.Fatalf("after confirm %v", ch)
	}
	// The test goes to the confirmed address only.
	h.expect(200, "POST", base+"/notification-channels/"+id+"/test", admin, "")
	waitFor(t, 5*time.Second, "the alert mail", func() bool { return len(h.smtp.to(a)) == 2 })
	if len(h.smtp.to(b)) != 1 {
		t.Fatal("an unconfirmed address got an alert")
	}

	// The per-org daily cap (50 in the harness) stops sending.
	err := tenant.WithOrg(context.Background(), h.db, org, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(),
			`INSERT INTO notification_outbox (org_id, channel_kind, payload, state, idempotency_key, target)
			 SELECT $1, 'email', '{}', 'sent', 'cap-' || g || '-' || $2, 'x' FROM generate_series(1, 60) g`, org, org.String())
		if err == nil {
			err = alerts.PruneOrg(context.Background(), h.db, org, time.Now())
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	test := h.expect(200, "POST", base+"/notification-channels/"+id+"/test", admin, "")
	if test["ok"] != false || !strings.Contains(fmt.Sprint(test["error"]), "daily email limit") {
		t.Fatalf("over the cap: %v", test)
	}
}

var codeRe = regexp.MustCompile(`code is ([A-Z0-9]{8})`)

// L4: the personal email address needs the code mailed to it.
func TestPersonalEmailConfirmation(t *testing.T) {
	h := newAlertsHarness(t)
	_, _, token := h.org(auth.RoleMember)
	addr := "me-" + uuid.NewString()[:8] + "@elsewhere.example.org"
	start := h.expect(202, "PUT", "/v1/me/channel-links/email", token, `{"address":"`+addr+`"}`)
	if start["verified"] != false {
		t.Fatalf("start %v", start)
	}
	links := h.expect(200, "GET", "/v1/me/channel-links", token, "")
	items := links["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["verified"] != false {
		t.Fatalf("pending link %v", links)
	}
	if c, _ := h.do("PUT", "/v1/me/channel-links/email", token, `{"address":"`+addr+`"}`); c != 429 {
		t.Fatalf("second code within a minute: %d", c)
	}
	mails := h.smtp.to(addr)
	if len(mails) != 1 {
		t.Fatalf("mails %v", mails)
	}
	code := codeRe.FindStringSubmatch(mails[0])[1]
	for i := 0; i < 2; i++ {
		if c, _ := h.do("POST", "/v1/me/channel-links/email/confirm", token, `{"code":"WRONGWRO"}`); c != 400 {
			t.Fatalf("wrong code: %d", c)
		}
	}
	link := h.expect(200, "POST", "/v1/me/channel-links/email/confirm", token, `{"code":"`+code+`"}`)
	if link["verified"] != true || link["address"] != addr {
		t.Fatalf("link %v", link)
	}
	if c, _ := h.do("POST", "/v1/me/channel-links/email/confirm", token, `{"code":"`+code+`"}`); c != 400 {
		t.Fatalf("code reused: %d", c)
	}
}

// M3: only orgs in ALERTS_PRIVATE_ORGS may reach private addresses.
func TestPrivateURLsPerOrg(t *testing.T) {
	h := newAlertsHarness(t)
	org, _, admin := h.org(auth.RoleAdmin)
	priv, privAdmin := h.privateOrg()
	body := `{"name":"hook","kind":"webhook","config":{"url":"` + h.fake.URL + `/hook","allow_private":true},"secret_env":"WEBHOOK_SECRET_SEC"}`
	if c, out := h.do("POST", "/v1/organizations/"+org.String()+"/notification-channels", admin, body); c != 400 {
		t.Fatalf("unlisted org: %d %v", c, out)
	}
	h.expect(201, "POST", "/v1/organizations/"+priv.String()+"/notification-channels", privAdmin, body)
	caps := h.expect(200, "GET", "/v1/alerts/capabilities?org_id="+priv.String(), privAdmin, "")
	if caps["allow_private_urls"] != true {
		t.Fatalf("listed org: %v", caps)
	}
	// Not a member of the listed org: false, and nothing learned.
	caps = h.expect(200, "GET", "/v1/alerts/capabilities?org_id="+priv.String(), admin, "")
	if caps["allow_private_urls"] != false {
		t.Fatalf("non-member: %v", caps)
	}
	if caps := h.expect(200, "GET", "/v1/alerts/capabilities", privAdmin, ""); caps["allow_private_urls"] != false {
		t.Fatalf("without org_id: %v", caps)
	}
}

// L3: notifications of an org whose security policy the session does not
// meet (here: 2FA required) are hidden.
func TestNotificationsFollowOrgSecurity(t *testing.T) {
	h := newAlertsHarness(t)
	org, user, token := h.org(auth.RoleAdmin)
	base := "/v1/organizations/" + org.String()
	rule := h.expect(201, "POST", base+"/alert-rules", token, jsonBody(map[string]any{
		"name": "me", "event_types": []string{"upstream.error"}, "recipients": map[string]any{"user_ids": []uuid.UUID{user}}}))
	h.expect(200, "POST", base+"/alert-rules/"+rule["id"].(string)+"/test", token, "")
	if n := h.expect(200, "GET", "/v1/notifications?unread=1&limit=1", token, ""); n["total"].(float64) != 1 {
		t.Fatalf("before: %v", n)
	}
	h.setSecurity(org, `INSERT INTO org_security (org_id, require_mfa) VALUES ($1, true)`)
	if n := h.expect(200, "GET", "/v1/notifications?unread=1&limit=1", token, ""); n["total"].(float64) != 0 {
		t.Fatalf("2FA required, session without 2FA: %v", n)
	}
	h.expect(200, "POST", "/v1/notifications/read", token, `{"all":true}`)
	h.setSecurity(org, `UPDATE org_security SET require_mfa = false WHERE org_id = $1`)
	if n := h.expect(200, "GET", "/v1/notifications?unread=1&limit=1", token, ""); n["total"].(float64) != 1 {
		t.Fatalf("a read by a session that could not see it marked it: %v", n)
	}
}
