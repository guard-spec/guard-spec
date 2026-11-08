// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package channels

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func incidentGuard() Guard { return NewGuard(map[string]bool{"o1": true}) }

func TestPagerDuty(t *testing.T) {
	c, srv := newCapture(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		w.WriteHeader(202)
		_, _ = w.Write([]byte(`{"status":"success","message":"Event processed","dedup_key":"guardspec-a1"}`))
	})
	d := &PagerDuty{Guard: incidentGuard(), BaseURL: srv.URL}
	m := &Message{Kind: KindPagerDuty, Secret: "R0UTINGKEY", Payload: testPayload(), Config: map[string]any{"region": "eu"}}
	res, err := d.Send(context.Background(), m)
	if err != nil || res.RemoteID != "guardspec-a1" {
		t.Fatalf("trigger: %v %v", res, err)
	}
	m.Payload.State = "resolved"
	if _, err := d.Send(context.Background(), m); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	var trigger, resolve map[string]any
	_ = json.Unmarshal(c.bodies[0], &trigger)
	_ = json.Unmarshal(c.bodies[1], &resolve)
	if c.reqs[0].URL.Path != "/v2/enqueue" || trigger["event_action"] != "trigger" || trigger["dedup_key"] != "guardspec-a1" ||
		trigger["routing_key"] != "R0UTINGKEY" {
		t.Fatalf("trigger body: %s", c.bodies[0])
	}
	pl := trigger["payload"].(map[string]any)
	if pl["severity"] != "critical" || pl["source"] != "guard-spec" || !strings.Contains(pl["summary"].(string), "Jailbreak burst") {
		t.Fatalf("payload: %v", pl)
	}
	if cd := pl["custom_details"].(map[string]any); cd["count"] != float64(7) || cd["group.attrs.category"] != "jailbreak" {
		t.Fatalf("details: %v", cd)
	}
	if resolve["event_action"] != "resolve" || resolve["dedup_key"] != "guardspec-a1" || resolve["payload"] != nil {
		t.Fatalf("resolve body: %s", c.bodies[1])
	}
	// A test opens its own incident, keyed by the delivery.
	m.Payload.State, m.Payload.Test = "resolved", true
	_, _ = d.Send(context.Background(), m)
	var test map[string]any
	_ = json.Unmarshal(c.bodies[2], &test)
	if test["event_action"] != "trigger" || test["dedup_key"] != "guardspec-test-gs1_key" {
		t.Fatalf("test: %s", c.bodies[2])
	}
}

func TestPagerDutyErrors(t *testing.T) {
	status := 400
	_, srv := newCapture(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		if status == 429 {
			w.Header().Set("Retry-After", "30")
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"status":"invalid event","message":"Event object is invalid","errors":["Invalid routing key R0UTINGKEY"]}`))
	})
	d := &PagerDuty{Guard: incidentGuard(), BaseURL: srv.URL}
	m := &Message{Secret: "R0UTINGKEY", Payload: testPayload()}
	_, err := d.Send(context.Background(), m)
	var ce *Error
	if !errors.As(err, &ce) || !ce.Permanent || strings.Contains(ce.Msg, "R0UTINGKEY") {
		t.Fatalf("400: %#v", err)
	}
	status = 429
	_, err = d.Send(context.Background(), m)
	if !errors.As(err, &ce) || ce.Permanent || ce.RetryAfter.Seconds() != 30 {
		t.Fatalf("429: %#v", err)
	}
	if _, err := d.Send(context.Background(), &Message{Payload: testPayload()}); err == nil {
		t.Fatal("no routing key accepted")
	}
}

func TestOpsgenie(t *testing.T) {
	c, srv := newCapture(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		w.WriteHeader(202)
		_, _ = w.Write([]byte(`{"result":"Request will be processed","took":0.1,"requestId":"x"}`))
	})
	o := &Opsgenie{Guard: incidentGuard(), BaseURL: srv.URL}
	m := &Message{Kind: KindOpsgenie, Secret: "genie-key", Payload: testPayload()}
	if _, err := o.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	m.Payload.State = "resolved"
	if _, err := o.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if c.reqs[0].URL.Path != "/v2/alerts" || c.reqs[0].Header.Get("Authorization") != "GenieKey genie-key" {
		t.Fatalf("create: %s %v", c.reqs[0].URL, c.reqs[0].Header)
	}
	var create map[string]any
	_ = json.Unmarshal(c.bodies[0], &create)
	if create["alias"] != "guardspec-a1" || create["priority"] != "P1" || len([]rune(create["message"].(string))) > 130 ||
		create["details"].(map[string]any)["count"] != "7" {
		t.Fatalf("create body: %s", c.bodies[0])
	}
	if c.reqs[1].URL.Path != "/v2/alerts/guardspec-a1/close" || c.reqs[1].URL.Query().Get("identifierType") != "alias" {
		t.Fatalf("close: %s", c.reqs[1].URL)
	}
	if ogPriority("warning") != "P3" || ogPriority("info") != "P5" {
		t.Error("priorities")
	}
}

// Without a private-address grant the sender refuses a loopback endpoint.
func TestIncidentGuard(t *testing.T) {
	_, srv := newCapture(t, nil)
	d := &PagerDuty{Guard: NewGuard(nil), BaseURL: srv.URL}
	if _, err := d.Send(context.Background(), &Message{Secret: "k", Payload: testPayload()}); err == nil {
		t.Fatal("loopback reached without a grant")
	}
}
