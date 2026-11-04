// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/giaplee/guard-spec/internal/alerts"
	"github.com/giaplee/guard-spec/internal/alerts/channels"
	"github.com/giaplee/guard-spec/internal/auth"
	"github.com/giaplee/guard-spec/internal/events"
	"github.com/giaplee/guard-spec/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	fakeTelegramToken = "424242:TESTtokenTESTtokenTESTtokenTESTtoken"
	fakeSlackToken    = "xoxb-test-slack-token"
	webhookSecret     = "whsec-integration-0123456789"
	telegramHookKey   = "tg-webhook-secret-0123"
	promptMarker      = "IGNORE-ALL-PREVIOUS-INSTRUCTIONS-MARKER"
)

// received is one request a fake receiver got.
type received struct {
	kind   string // telegram, slack, webhook
	target string
	body   []byte
	header http.Header
	at     time.Time
}

// fakeReceivers is Telegram's Bot API, Slack's Web API and a webhook
// receiver in one server.
type fakeReceivers struct {
	*httptest.Server
	mu   sync.Mutex
	got  []received
	sigs []error
}

func newFakeReceivers(t *testing.T) *fakeReceivers {
	f := &fakeReceivers{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec := received{body: body, header: r.Header.Clone(), at: time.Now()}
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		switch {
		case strings.HasSuffix(r.URL.Path, "/sendMessage"):
			rec.kind, rec.target = "telegram", fmt.Sprint(m["chat_id"])
			_, _ = io.WriteString(w, `{"ok":true,"result":{"message_id":1}}`)
		case strings.HasSuffix(r.URL.Path, "/getMe"):
			_, _ = io.WriteString(w, `{"ok":true,"result":{"username":"guard_test_bot"}}`)
			return
		case r.URL.Path == "/chat.postMessage":
			rec.kind, rec.target = "slack", fmt.Sprint(m["channel"])
			_, _ = io.WriteString(w, `{"ok":true,"ts":"1.2"}`)
		case r.URL.Path == "/users.lookupByEmail":
			_, _ = io.WriteString(w, `{"ok":true,"user":{"id":"USLACK1"}}`)
			return
		case r.URL.Path == "/hook":
			rec.kind = "webhook"
			err := channels.Verify([]byte(webhookSecret), r.Header.Get(channels.HeaderTimestamp),
				r.Header.Get(channels.HeaderSignature), body, time.Now())
			f.mu.Lock()
			f.sigs = append(f.sigs, err)
			f.mu.Unlock()
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
			return
		}
		f.mu.Lock()
		f.got = append(f.got, rec)
		f.mu.Unlock()
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeReceivers) snapshot() []received {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.got)
}

func (f *fakeReceivers) count(kind, target string) int {
	n := 0
	for _, r := range f.snapshot() {
		if r.kind == kind && (target == "" || r.target == target) {
			n++
		}
	}
	return n
}

// waitFor polls cond until it holds or d passes.
func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

type alertsHarness struct {
	*cpHarness
	rt   *alertsRuntime
	fake *fakeReceivers
	em   *events.Emitter
}

// newAlertsHarness starts the control plane with fake Telegram and Slack
// APIs, private URLs allowed (the fakes listen on loopback), and the worker
// and SSE hub running.
func newAlertsHarness(t *testing.T) *alertsHarness {
	t.Helper()
	fake := newFakeReceivers(t)
	env := map[string]string{"WEBHOOK_SECRET_SEC": webhookSecret}
	getenv := func(k string) string { return env[k] }
	cfg := alertsConfig{
		getenv: getenv, allowPrivate: true,
		telegramToken: fakeTelegramToken, telegramBot: "guard_test_bot", telegramSecret: telegramHookKey,
		slackToken: fakeSlackToken, lang: "en", telegramAPI: fake.URL, slackAPI: fake.URL,
	}
	var err error
	if cfg.secretOrgs, err = alerts.ParseSecretOrgs("WEBHOOK_SECRET_SEC=*;A2A_ONLY_B=" + uuid.Nil.String()); err != nil {
		t.Fatal(err)
	}
	var settings *appSettings
	h := newCPHarness(t, func(s *appSettings) {
		s.alertsCfg = &cfg
		s.publicURL = "https://guard.example.com"
		settings = s
	})
	rt := settings.alertsRT
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); rt.worker().Run(ctx) }()
	go rt.hub.Run(ctx, h.db)
	em := events.New(h.db, events.Config{Source: "test"})
	t.Cleanup(func() {
		em.Close(context.Background())
		cancel()
		<-done
	})
	return &alertsHarness{cpHarness: h, rt: rt, fake: fake, em: em}
}

func (h *alertsHarness) member(org uuid.UUID, role auth.Role) (uuid.UUID, string) {
	h.t.Helper()
	token, id := h.user("member-password-123")
	h.addMember(org, id, role)
	return id, token
}

func (h *alertsHarness) link(user uuid.UUID, kind, address string) {
	h.t.Helper()
	err := withUser(context.Background(), h.db, user, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(),
			`INSERT INTO user_channel_links (user_id, kind, address, verified_at) VALUES ($1, $2, $3, NOW())`, user, kind, address)
		return err
	})
	if err != nil {
		h.t.Fatal(err)
	}
}

func (h *alertsHarness) project(org uuid.UUID) uuid.UUID {
	h.t.Helper()
	id := uuid.New()
	err := tenant.WithOrg(context.Background(), h.db, org, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO projects (id, org_id, name, slug) VALUES ($1, $2, 'x', $3)`,
			id, org, id.String())
		return err
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return id
}

func jsonBody(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func (h *alertsHarness) blocked(org, project uuid.UUID, category string) {
	h.em.Emit(events.Event{OrgID: org, ProjectID: &project, Type: events.DetectionBlocked, Severity: events.Warning,
		Attrs: map[string]any{"request_id": uuid.NewString(), "categories": []string{category}, "score": 0.97,
			"layer": "l1", "decision": "block", "api_key_id": "gs_12345678", "model": "gpt-x",
			// Never produced by the gateway; here to prove payloads drop it.
			"prompt": promptMarker}})
}

// TestAlertsAcceptance: "≥5 detection.blocked in 5 min in project X →
// critical → group Security via telegram + slack + webhook".
func TestAlertsAcceptance(t *testing.T) {
	h := newAlertsHarness(t)
	org, _, admin := h.org(auth.RoleAdmin)
	base := "/v1/organizations/" + org.String()
	projectX, projectY := h.project(org), h.project(org)
	alice, _ := h.member(org, auth.RoleMember)
	bob, _ := h.member(org, auth.RoleMember)
	h.link(alice, "telegram", "1001")
	h.link(alice, "slack", "UALICE")
	h.link(bob, "telegram", "1002")

	group := h.expect(201, "POST", base+"/user-groups", admin, `{"name":"Security","description":"on call"}`)
	gid := group["id"].(string)
	h.expect(200, "PUT", base+"/user-groups/"+gid+"/members", admin, jsonBody(map[string]any{"user_ids": []uuid.UUID{alice, bob}}))
	ch := h.expect(201, "POST", base+"/notification-channels", admin, jsonBody(map[string]any{
		"name": "SIEM", "kind": "webhook", "config": map[string]any{"url": h.fake.URL + "/hook", "allow_private": true},
		"secret_env": "WEBHOOK_SECRET_SEC"}))
	if ch["secret_set"] != true || ch["secret_env"] != "WEBHOOK_SECRET_SEC" {
		t.Fatalf("channel %v", ch)
	}
	rule := h.expect(201, "POST", base+"/alert-rules", admin, jsonBody(map[string]any{
		"name": "Injection burst in X", "event_types": []string{"detection.blocked"},
		"condition": `project_id == "` + projectX.String() + `"`, "threshold": 5, "window_seconds": 300,
		"severity": "critical", "throttle_seconds": 900,
		"recipients": map[string]any{"group_ids": []string{gid}}, "channel_ids": []string{ch["id"].(string)}}))
	ruleID := rule["id"].(string)

	// Noise in another project and only four in X: nothing fires.
	for i := 0; i < 6; i++ {
		h.blocked(org, projectY, "jailbreak")
	}
	for i := 0; i < 4; i++ {
		h.blocked(org, projectX, "jailbreak")
	}
	time.Sleep(1500 * time.Millisecond)
	if n := len(h.fake.snapshot()); n != 0 {
		t.Fatalf("%d deliveries below the threshold", n)
	}

	start := time.Now()
	h.blocked(org, projectX, "jailbreak")
	want := func() bool {
		return h.fake.count("telegram", "1001") == 1 && h.fake.count("telegram", "1002") == 1 &&
			h.fake.count("slack", "UALICE") == 1 && h.fake.count("webhook", "") == 1
	}
	deadline := time.Now().Add(5 * time.Second)
	for !want() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !want() {
		for _, r := range h.fake.snapshot() {
			t.Logf("got %s %s", r.kind, r.target)
		}
		t.Log(h.expect(200, "GET", base+"/notification-deliveries", admin, ""))
		t.Log(h.expect(200, "GET", base+"/alerts", admin, ""))
		t.Fatal("timed out waiting for telegram, slack and webhook deliveries")
	}
	var worst time.Duration
	for _, r := range h.fake.snapshot() {
		worst = max(worst, r.at.Sub(start))
	}
	t.Logf("acceptance: event to last delivery %s", worst)
	if worst >= 5*time.Second {
		t.Fatalf("end-to-end latency %s", worst)
	}

	// Signed, metadata only.
	h.fake.mu.Lock()
	for _, err := range h.fake.sigs {
		if err != nil {
			t.Errorf("webhook signature: %v", err)
		}
	}
	h.fake.mu.Unlock()
	var payload channels.Payload
	for _, r := range h.fake.snapshot() {
		if strings.Contains(string(r.body), promptMarker) {
			t.Fatalf("%s payload carries prompt text: %s", r.kind, r.body)
		}
		if r.kind == "webhook" {
			if err := json.Unmarshal(r.body, &payload); err != nil {
				t.Fatal(err)
			}
			if r.header.Get(channels.HeaderEventID) != payload.EventID {
				t.Fatal("event id header differs from the payload")
			}
		}
	}
	if payload.Schema != channels.SchemaV1 || payload.Count != 5 || payload.Severity != "critical" ||
		payload.State != "firing" || payload.Rule.ID != ruleID || payload.ProjectID == nil ||
		*payload.ProjectID != projectX.String() || len(payload.Samples) != 5 ||
		!strings.HasPrefix(payload.Links.Alert, "https://guard.example.com/ui/alerts/history?id=") {
		t.Fatalf("payload %+v", payload)
	}

	// A repeat inside the throttle window updates the alert but sends nothing.
	for i := 0; i < 5; i++ {
		h.blocked(org, projectX, "jailbreak")
	}
	time.Sleep(3 * time.Second)
	if !want() {
		t.Fatalf("repeat inside the throttle delivered again: %d deliveries", len(h.fake.snapshot()))
	}
	list := h.expect(200, "GET", base+"/alerts?state=firing", admin, "")
	items := list["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["count"].(float64) != 10 {
		t.Fatalf("alerts %v", list)
	}
	if list["total"].(float64) != 1 || list["total_capped"] != false {
		t.Fatalf("envelope %v", list)
	}

	// In-app notifications for both recipients, and the delivery log.
	_, aliceTok := h.member(org, auth.RoleViewer) // a third user sees none
	notes := h.expect(200, "GET", "/v1/notifications?unread=1", aliceTok, "")
	if notes["total"].(float64) != 0 {
		t.Fatalf("a non-recipient got notifications: %v", notes)
	}
	deliveries := h.expect(200, "GET", base+"/notification-deliveries?state=sent", admin, "")
	if deliveries["total"].(float64) != 4 {
		t.Fatalf("deliveries %v", deliveries)
	}
	for _, d := range deliveries["items"].([]any) {
		if tgt := d.(map[string]any)["target"].(string); strings.Contains(tgt, "/hook") {
			t.Fatalf("delivery target shows the URL path: %s", tgt)
		}
	}

	// A removed member stops receiving: the next alert of the rule (a test)
	// goes to alice only.
	h.expect(204, "DELETE", base+"/members/"+bob.String(), admin, "")
	before1001, before1002 := h.fake.count("telegram", "1001"), h.fake.count("telegram", "1002")
	h.expect(200, "POST", base+"/alert-rules/"+ruleID+"/test", admin, "")
	waitFor(t, 5*time.Second, "the test alert", func() bool { return h.fake.count("telegram", "1001") == before1001+1 })
	time.Sleep(500 * time.Millisecond)
	if h.fake.count("telegram", "1002") != before1002 {
		t.Fatal("a removed member still receives alerts")
	}
	g := h.expect(200, "GET", base+"/user-groups/"+gid, admin, "")
	if g["member_count"].(float64) != 1 {
		t.Fatalf("removed member still in the group: %v", g)
	}
}

// TestAlertsLatency measures event to delivery attempt over 20 alerts.
func TestAlertsLatency(t *testing.T) {
	h := newAlertsHarness(t)
	org, _, admin := h.org(auth.RoleAdmin)
	base := "/v1/organizations/" + org.String()
	project := h.project(org)
	ch := h.expect(201, "POST", base+"/notification-channels", admin, jsonBody(map[string]any{
		"name": "hook", "kind": "webhook", "config": map[string]any{"url": h.fake.URL + "/hook", "allow_private": true},
		"secret_env": "WEBHOOK_SECRET_SEC"}))
	h.expect(201, "POST", base+"/alert-rules", admin, jsonBody(map[string]any{
		"name": "every category", "event_types": []string{"detection.blocked"}, "group_by": []string{"attrs.category"},
		"severity": "warning", "channel_ids": []string{ch["id"].(string)}}))
	var lat []time.Duration
	for i := 0; i < 20; i++ {
		n := h.fake.count("webhook", "")
		start := time.Now()
		h.blocked(org, project, fmt.Sprintf("cat_%d", i))
		waitFor(t, 5*time.Second, "delivery", func() bool { return h.fake.count("webhook", "") == n+1 })
		got := h.fake.snapshot()
		lat = append(lat, got[len(got)-1].at.Sub(start))
	}
	slices.Sort(lat)
	p50, p95 := lat[len(lat)/2], lat[int(0.95*float64(len(lat)))-1]
	t.Logf("event to delivery: p50 %s, p95 %s, max %s", p50, p95, lat[len(lat)-1])
	if p95 >= 5*time.Second {
		t.Fatalf("p95 %s", p95)
	}
}

func TestAlertsRolesAndIsolation(t *testing.T) {
	h := newAlertsHarness(t)
	orgA, _, adminA := h.org(auth.RoleAdmin)
	orgB, _, adminB := h.org(auth.RoleAdmin)
	a, b := "/v1/organizations/"+orgA.String(), "/v1/organizations/"+orgB.String()
	_, viewer := h.member(orgA, auth.RoleViewer)
	userA, member := h.member(orgA, auth.RoleMember)

	ruleBody := `{"name":"r","event_types":["upstream.error"]}`
	rule := h.expect(201, "POST", a+"/alert-rules", adminA, ruleBody)
	ruleA := rule["id"].(string)
	chA := h.expect(201, "POST", a+"/notification-channels", adminA,
		`{"name":"mail","kind":"email","config":{"to":["sec@example.com"]}}`)["id"].(string)
	groupA := h.expect(201, "POST", a+"/user-groups", adminA, `{"name":"g"}`)["id"].(string)

	// A viewer cannot write (nor read: reads need member).
	for _, w := range []struct{ method, path, body string }{
		{"POST", a + "/alert-rules", ruleBody},
		{"PATCH", a + "/alert-rules/" + ruleA, `{"enabled":false}`},
		{"DELETE", a + "/alert-rules/" + ruleA, ""},
		{"POST", a + "/alert-rules/" + ruleA + "/test", ""},
		{"POST", a + "/notification-channels", `{"name":"x","kind":"teams","secret_env":"TEAMS_X"}`},
		{"POST", a + "/user-groups", `{"name":"x"}`},
		{"PUT", a + "/user-groups/" + groupA + "/members", `{"user_ids":[]}`},
		{"GET", a + "/alert-rules", ""},
		{"GET", a + "/notification-deliveries", ""},
	} {
		if code, _ := h.do(w.method, w.path, viewer, w.body); code != 403 {
			t.Errorf("viewer %s %s: %d, want 403", w.method, w.path, code)
		}
	}
	// A member reads but does not write.
	h.expect(200, "GET", a+"/alert-rules", member, "")
	h.expect(200, "GET", a+"/alerts", member, "")
	if code, _ := h.do("POST", a+"/alert-rules", member, ruleBody); code != 403 {
		t.Errorf("member wrote a rule: %d", code)
	}
	if code, _ := h.do("GET", a+"/notification-deliveries", member, ""); code != 403 {
		t.Errorf("member read deliveries: %d", code)
	}
	// Prefs are self service for any role.
	prefs := h.do
	if code, out := prefs("PUT", a+"/me/notification-prefs", viewer,
		`[{"channel_kind":"email","enabled":false,"min_severity":"critical"}]`); code != 200 {
		t.Fatalf("viewer prefs: %d %v", code, out)
	}

	// Cross-org: B's admin cannot reach A's objects by id, through either org.
	for _, p := range []string{"/alert-rules/" + ruleA, "/notification-channels/" + chA, "/user-groups/" + groupA} {
		if code, _ := h.do("GET", a+p, adminB, ""); code != 403 {
			t.Errorf("B reading A's %s through A: %d", p, code)
		}
		if code, _ := h.do("GET", b+p, adminB, ""); code != 404 {
			t.Errorf("B reading A's %s through B: %d", p, code)
		}
		if code, _ := h.do("DELETE", b+p, adminB, ""); code != 404 {
			t.Errorf("B deleting A's %s through B: %d", p, code)
		}
	}
	for _, body := range []string{
		`{"name":"x","event_types":["upstream.error"],"channel_ids":["` + chA + `"]}`,
		`{"name":"y","event_types":["upstream.error"],"recipients":{"group_ids":["` + groupA + `"]}}`,
		`{"name":"z","event_types":["upstream.error"],"recipients":{"user_ids":["` + userA.String() + `"]}}`,
	} {
		if code, out := h.do("POST", b+"/alert-rules", adminB, body); code != 400 {
			t.Errorf("B referencing A's objects: %d %v", code, out)
		}
	}
	groupB := h.expect(201, "POST", b+"/user-groups", adminB, `{"name":"g"}`)["id"].(string)
	if code, _ := h.do("PUT", b+"/user-groups/"+groupB+"/members", adminB, `{"user_ids":["`+userA.String()+`"]}`); code != 400 {
		t.Errorf("B added A's member to a group: %d", code)
	}
	if code, _ := h.do("POST", b+"/alert-rules/"+ruleA+"/test", adminB, ""); code != 404 {
		t.Errorf("B tested A's rule: %d", code)
	}

	// secret_env allowlist and URL rules.
	for _, body := range []string{
		`{"name":"x","kind":"webhook","config":{"url":"https://example.com/h"},"secret_env":"DATABASE_URL"}`,
		`{"name":"x","kind":"webhook","config":{"url":"https://example.com/h"},"secret_env":"JWT_SECRET"}`,
		`{"name":"x","kind":"webhook","config":{"url":"http://example.com/h"},"secret_env":"WEBHOOK_SECRET_X"}`,
		`{"name":"x","kind":"webhook","config":{"url":"https://169.254.169.254/"},"secret_env":"WEBHOOK_SECRET_X"}`,
		`{"name":"x","kind":"a2a","config":{"agent_card_url":"https://metadata.google.internal/"}}`,
		`{"name":"x","kind":"slack","config":{"mode":"bot","channel":"C1"},"secret_env":"OIDC_SECRET_X"}`,
		`{"name":"x","kind":"email","config":{"to":["not an email"]}}`,
		`{"name":"x","kind":"a2a","config":{"agent_card_url":"https://agent.example.com"},"secret_env":"SLACK_BOT_TOKEN"}`,
		`{"name":"x","kind":"a2a","config":{"agent_card_url":"https://agent.example.com"},"secret_env":"WEBHOOK_SECRET_SEC"}`,
		`{"name":"x","kind":"a2a","config":{"agent_card_url":"https://agent.example.com"},"secret_env":"A2A_ONLY_B"}`,
		`{"name":"x","kind":"webhook","config":{"url":"https://example.com/h?token=abc"},"secret_env":"WEBHOOK_SECRET_SEC"}`,
		`{"name":"x","kind":"webhook","config":{"url":"https://example.com/h","extra":1},"secret_env":"WEBHOOK_SECRET_X"}`,
	} {
		if code, out := h.do("POST", a+"/notification-channels", adminA, body); code != 400 {
			t.Errorf("channel %s: %d %v", body, code, out)
		}
	}
	// Condition errors come back as 400 with the parse error.
	code, out := h.do("POST", a+"/alert-rules", adminA, `{"name":"bad","event_types":["detection.blocked"],"condition":"attrs.score >"}`)
	if code != 400 || !strings.Contains(fmt.Sprint(out["error"]), "condition") || out["position"] == nil {
		t.Errorf("bad condition: %d %v", code, out)
	}

	// Every write is in the activity log.
	act := h.expect(200, "GET", a+"/activity?action=alerts", adminA, "")
	seen := map[string]bool{}
	for _, it := range act["items"].([]any) {
		seen[it.(map[string]any)["action"].(string)] = true
	}
	for _, want := range []string{"alerts.rule.created", "alerts.channel.created", "alerts.group.created", "alerts.prefs.updated"} {
		if !seen[want] {
			t.Errorf("activity log lacks %s: %v", want, seen)
		}
	}
	caps := h.expect(200, "GET", "/v1/alerts/capabilities", viewer, "")
	if caps["telegram"].(map[string]any)["enabled"] != true || caps["slack_bot"] != true || caps["smtp"] != false ||
		caps["allow_private_urls"] != true {
		t.Errorf("capabilities %v", caps)
	}
}

func TestTelegramLinking(t *testing.T) {
	h := newAlertsHarness(t)
	_, user, token := h.org(auth.RoleMember)
	start := h.expect(200, "POST", "/v1/me/channel-links/telegram/start", token, "")
	code := start["code"].(string)
	if start["deep_link"] != "https://t.me/guard_test_bot?start="+code {
		t.Fatalf("deep link %v", start)
	}
	var stored string
	if err := withUser(context.Background(), h.db, user, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT code_hash FROM telegram_link_codes WHERE user_id = $1`, user).Scan(&stored)
	}); err != nil || stored == code || stored != hashCode(code) {
		t.Fatalf("code not stored hashed: %v", err)
	}
	update := func(chat int, text string) string {
		return fmt.Sprintf(`{"update_id":1,"message":{"text":%q,"chat":{"id":%d,"type":"private"}}}`, text, chat)
	}
	hook := func(secret, body string) int {
		req := httptest.NewRequest("POST", "/v1/integrations/telegram/webhook", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if secret != "" {
			req.Header.Set("X-Telegram-Bot-Api-Secret-Token", secret)
		}
		resp, err := h.app.Test(req, -1)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if c := hook("", update(777, "/start "+code)); c != 401 {
		t.Fatalf("no secret: %d", c)
	}
	if c := hook("wrong", update(777, "/start "+code)); c != 401 {
		t.Fatalf("wrong secret: %d", c)
	}
	if c := hook(telegramHookKey, update(777, "/start "+code)); c != 200 {
		t.Fatalf("webhook: %d", c)
	}
	links := h.expect(200, "GET", "/v1/me/channel-links", token, "")
	items := links["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["address"] != "777" {
		t.Fatalf("links %v", links)
	}
	// Single use: a second chat with the same code does not take over.
	hook(telegramHookKey, update(888, "/start "+code))
	links = h.expect(200, "GET", "/v1/me/channel-links", token, "")
	if links["items"].([]any)[0].(map[string]any)["address"] != "777" {
		t.Fatal("code worked twice")
	}
	// Expired codes do not work.
	code2 := h.expect(200, "POST", "/v1/me/channel-links/telegram/start", token, "")["code"].(string)
	if err := withUser(context.Background(), h.db, user, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE telegram_link_codes SET expires_at = NOW() - interval '1 second'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	hook(telegramHookKey, update(999, "/start "+code2))
	links = h.expect(200, "GET", "/v1/me/channel-links", token, "")
	if links["items"].([]any)[0].(map[string]any)["address"] != "777" {
		t.Fatal("expired code worked")
	}
	h.expect(200, "POST", "/v1/me/channel-links/slack", token, "")
	h.expect(204, "DELETE", "/v1/me/channel-links/telegram", token, "")
	links = h.expect(200, "GET", "/v1/me/channel-links", token, "")
	if len(links["items"].([]any)) != 1 || links["items"].([]any)[0].(map[string]any)["kind"] != "slack" {
		t.Fatalf("links %v", links)
	}
}

func TestNotificationStream(t *testing.T) {
	h := newAlertsHarness(t)
	org, admin, token := h.org(auth.RoleAdmin)
	base := "/v1/organizations/" + org.String()
	rule := h.expect(201, "POST", base+"/alert-rules", token, jsonBody(map[string]any{
		"name": "to me", "event_types": []string{"upstream.error"}, "recipients": map[string]any{"user_ids": []uuid.UUID{admin}}}))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = h.app.Listener(ln) }()
	t.Cleanup(func() { _ = h.app.ShutdownWithTimeout(time.Second) })
	url := "http://" + ln.Addr().String() + "/v1/notifications/stream"

	// No token, or a token in the URL: refused.
	for _, u := range []string{url, url + "?token=" + token, url + "?access_token=" + token} {
		resp, err := http.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("%s: %d", u, resp.StatusCode)
		}
	}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content type %s", ct)
	}
	evs := make(chan string, 16)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if line := sc.Text(); strings.HasPrefix(line, "event: ") {
				evs <- strings.TrimPrefix(line, "event: ")
			}
		}
		close(evs)
	}()
	next := func() string {
		select {
		case e := <-evs:
			return e
		case <-time.After(5 * time.Second):
			t.Fatal("no event")
		}
		return ""
	}
	if e := next(); e != "unread" {
		t.Fatalf("first event %q", e)
	}
	h.expect(200, "POST", base+"/alert-rules/"+rule["id"].(string)+"/test", token, "")
	if e := next(); e != "notification" {
		t.Fatalf("event %q, want notification", e)
	}
	if e := next(); e != "unread" {
		t.Fatalf("event %q, want unread", e)
	}
	notes := h.expect(200, "GET", "/v1/notifications?unread=1", token, "")
	if notes["total"].(float64) != 1 {
		t.Fatalf("notifications %v", notes)
	}
	h.expect(200, "POST", "/v1/notifications/read", token, `{"all":true}`)
	if notes := h.expect(200, "GET", "/v1/notifications?unread=1", token, ""); notes["total"].(float64) != 0 {
		t.Fatalf("still unread %v", notes)
	}
}

func TestEventsRowLevelSecurity(t *testing.T) {
	h := newAlertsHarness(t)
	orgA, _, _ := h.org(auth.RoleAdmin)
	orgB, _, _ := h.org(auth.RoleAdmin)
	h.em.Emit(events.Event{OrgID: orgA, Type: events.UpstreamError})
	waitFor(t, 3*time.Second, "the event row", func() bool {
		var n int
		_ = tenant.WithOrg(context.Background(), h.db, orgA, func(tx pgx.Tx) error {
			return tx.QueryRow(context.Background(), `SELECT count(*) FROM events`).Scan(&n)
		})
		return n > 0
	})
	for _, table := range []string{"events", "alert_rules", "alerts", "notification_channels", "user_groups",
		"user_group_members", "notification_outbox", "notifications", "user_notification_prefs", "alert_rule_hits",
		"user_channel_links", "telegram_link_codes"} {
		var n int
		err := tenant.WithOrg(context.Background(), h.db, orgB, func(tx pgx.Tx) error {
			return tx.QueryRow(context.Background(), `SELECT count(*) FROM `+table+` WHERE true`).Scan(&n)
		})
		if err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		if table == "events" && n != 0 {
			t.Fatalf("org B sees %d events of org A", n)
		}
		// Outside any scope nothing is visible.
		var all int
		if err := h.db.QueryRow(context.Background(), `SELECT count(*) FROM `+table).Scan(&all); err == nil && all != 0 {
			t.Errorf("%s: %d rows visible without app.org_id", table, all)
		}
	}
}
