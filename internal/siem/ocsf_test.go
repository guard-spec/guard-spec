// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package siem

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/guard-spec/guard-spec/internal/events"
)

// schema is testdata/ocsf-1.9.0-required.json: the required attributes and
// enum values of the classes and objects used, taken from the official OCSF
// 1.9.0 schema (base schema, no profiles).
type schema struct {
	Classes map[string]struct {
		UID         int              `json:"uid"`
		CategoryUID int              `json:"category_uid"`
		Required    []string         `json:"required"`
		Enums       map[string][]int `json:"enums"`
	} `json:"classes"`
	Objects map[string]struct {
		Required   []string `json:"required"`
		AtLeastOne []string `json:"at_least_one"`
	} `json:"objects"`
}

func loadSchema(t *testing.T) schema {
	t.Helper()
	b, err := os.ReadFile("testdata/ocsf-1.9.0-required.json")
	if err != nil {
		t.Fatal(err)
	}
	var s schema
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// sampleEvents has one event of every type the control plane and the
// gateway emit.
func sampleEvents() []events.Event {
	org := uuid.New()
	at := time.Date(2026, 11, 8, 9, 30, 0, 0, time.UTC)
	mk := func(typ, sev string, attrs map[string]any) events.Event {
		return events.Event{ID: uuid.New(), OrgID: org, Type: typ, Severity: sev, OccurredAt: at, Attrs: attrs}
	}
	return []events.Event{
		mk(events.DetectionBlocked, events.Warning, map[string]any{"request_id": uuid.NewString(), "categories": []any{"prompt_injection"},
			"score": 0.97, "layer": "l2", "decision": "block", "api_key_id": "gs_abcd1234", "model": "gpt-4o", "pii_kinds": []any{"email"}, "pii_count": 1}),
		mk(events.DetectionFlagged, events.Info, map[string]any{"request_id": uuid.NewString(), "score": 0.6, "layer": "l3", "decision": "allow"}),
		mk(events.DetectionFlagged, events.Warning, map[string]any{"score": 0.9, "layer": "indirect", "decision": "redact", "redacted": 2}),
		mk(events.UpstreamError, events.Warning, map[string]any{"upstream_id": "u1", "status": 502, "error_kind": "5xx"}),
		mk(events.SecurityLoginFailed, events.Warning, map[string]any{"user_id": nil, "email_hash": "0011", "ip": "203.0.113.7", "reason": "invalid_credentials"}),
		mk(events.SecurityMFALocked, events.Critical, map[string]any{"user_id": uuid.NewString()}),
		mk(events.SecurityRoleChanged, events.Warning, map[string]any{"actor_id": uuid.NewString(), "user_id": uuid.NewString(), "from": "member", "to": "admin"}),
		mk(events.SecurityOwnerAdded, events.Critical, map[string]any{"actor_id": uuid.NewString(), "user_id": uuid.NewString()}),
		mk(events.SecuritySSOChanged, events.Warning, map[string]any{"actor_id": uuid.NewString(), "provider_id": "p", "action": "updated"}),
		mk(events.ConfigPolicyChanged, events.Info, map[string]any{"actor_id": uuid.NewString(), "policy_id": "x", "action": "created"}),
		mk(events.ConfigUpstreamChange, events.Info, map[string]any{"actor_id": uuid.NewString(), "upstream_id": "u", "action": "deleted"}),
		mk("activity.request.content_viewed", events.Info, map[string]any{"actor_id": uuid.NewString(), "action": "request.content_viewed"}),
		mk(events.AlertTest, events.Critical, map[string]any{"actor_id": uuid.NewString(), "rule_id": "r"}),
	}
}

var classByUID = map[int]string{2004: "detection_finding", 3001: "account_change", 3002: "authentication", 6003: "api_activity"}

// Every record carries the attributes its OCSF class requires, with values
// the schema defines, and the required parts of the objects in it.
func TestRecordsMatchOCSF(t *testing.T) {
	s := loadSchema(t)
	for _, ev := range sampleEvents() {
		r := Map(ev)
		// Through JSON, as a SIEM receives it.
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		_ = json.Unmarshal(b, &got)
		name := classByUID[int(got["class_uid"].(float64))]
		cls, ok := s.Classes[name]
		if !ok {
			t.Errorf("%s: class %v not in the schema", ev.Type, got["class_uid"])
			continue
		}
		for _, attr := range cls.Required {
			if _, ok := got[attr]; !ok {
				t.Errorf("%s (%s): required %q missing", ev.Type, name, attr)
			}
		}
		if int(got["category_uid"].(float64)) != cls.CategoryUID {
			t.Errorf("%s: category_uid %v, want %d", ev.Type, got["category_uid"], cls.CategoryUID)
		}
		act := int(got["activity_id"].(float64))
		if int(got["type_uid"].(float64)) != cls.UID*100+act {
			t.Errorf("%s: type_uid %v", ev.Type, got["type_uid"])
		}
		for enum, values := range cls.Enums {
			if v, ok := got[enum]; ok && !slices.Contains(values, int(v.(float64))) {
				t.Errorf("%s: %s %v is not a value of the schema", ev.Type, enum, v)
			}
		}
		for obj, spec := range s.Objects {
			var o map[string]any
			switch obj {
			case "metadata":
				o, _ = got["metadata"].(map[string]any)
			case "product":
				m, _ := got["metadata"].(map[string]any)
				o, _ = m["product"].(map[string]any)
			default:
				o, _ = got[obj].(map[string]any)
			}
			if o == nil {
				continue
			}
			for _, attr := range spec.Required {
				if _, ok := o[attr]; !ok {
					t.Errorf("%s: %s.%s missing", ev.Type, obj, attr)
				}
			}
			if len(spec.AtLeastOne) > 0 && !slices.ContainsFunc(spec.AtLeastOne, func(a string) bool { _, ok := o[a]; return ok }) {
				t.Errorf("%s: %s has none of %v", ev.Type, obj, spec.AtLeastOne)
			}
		}
		if got["src_endpoint"] != nil {
			se := got["src_endpoint"].(map[string]any)
			if se["ip"] == nil && se["name"] == nil {
				t.Errorf("%s: src_endpoint without ip or name", ev.Type)
			}
		}
		if strings.Contains(string(b), "@") {
			t.Errorf("%s: an address in the record: %s", ev.Type, b)
		}
	}
}

func TestDetectionMapping(t *testing.T) {
	evs := sampleEvents()
	blocked, flagged, redacted := Map(evs[0]), Map(evs[1]), Map(evs[2])
	if blocked.ClassUID() != 2004 || blocked["disposition"] != "Blocked" || blocked["action"] != "Denied" || blocked["confidence_score"] != 97 {
		t.Errorf("blocked: %v", blocked)
	}
	if flagged["disposition"] != "Allowed" || redacted["disposition"] != "Corrected" {
		t.Errorf("flagged %v / redacted %v", flagged["disposition"], redacted["disposition"])
	}
	if Map(evs[4]).ClassUID() != 3002 || Map(evs[5])["activity_name"] != "Lock" || Map(evs[10])["activity_name"] != "Delete" {
		t.Error("other mappings")
	}
}
