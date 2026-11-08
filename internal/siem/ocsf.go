// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Package siem exports Guard Spec's events to security information and event
// management systems (RF-f2f95010): each event of the events table becomes an
// OCSF 1.9.0 record (the Open Cybersecurity Schema Framework) and goes to
// Splunk (HTTP Event Collector), Elasticsearch, Microsoft Sentinel (Logs
// Ingestion API), syslog over TLS (CEF or OCSF JSON), or any HTTP endpoint.
//
// Events hold metadata only (ids, categories, scores, decisions); so do the
// records. Never a prompt, an answer or a secret.
package siem

import (
	"fmt"
	"strings"

	"github.com/guard-spec/guard-spec/internal/events"
	"github.com/guard-spec/guard-spec/internal/version"
)

// OCSFVersion is the schema version of the records.
const OCSFVersion = "1.9.0"

// OCSF classes used.
const (
	classDetectionFinding = 2004 // Findings
	classAccountChange    = 3001 // Identity & Access Management
	classAuthentication   = 3002
	classAPIActivity      = 6003 // Application Activity
)

var classCategory = map[int]int{classDetectionFinding: 2, classAccountChange: 3, classAuthentication: 3, classAPIActivity: 6}

var classNames = map[int]string{classDetectionFinding: "Detection Finding", classAccountChange: "Account Change",
	classAuthentication: "Authentication", classAPIActivity: "API Activity"}

// severityID maps an event severity to OCSF severity_id.
func severityID(s string) (int, string) {
	switch s {
	case events.Critical:
		return 5, "Critical"
	case events.Warning:
		return 3, "Medium"
	default:
		return 1, "Informational"
	}
}

// Record is one OCSF event, ready to encode.
type Record map[string]any

// ClassUID of the record.
func (r Record) ClassUID() int { n, _ := r["class_uid"].(int); return n }

// Map turns an event into its OCSF record.
func Map(ev events.Event) Record {
	sev, sevName := severityID(ev.Severity)
	r := Record{
		"time":        ev.OccurredAt.UnixMilli(),
		"severity_id": sev,
		"severity":    sevName,
		"message":     ev.Type,
		"metadata": map[string]any{
			"version": OCSFVersion,
			"uid":     ev.ID.String(),
			"product": map[string]any{"name": "Guard Spec", "vendor_name": "The Guard Spec Authors", "version": version.String()},
			"tenant_uid":   ev.OrgID.String(),
			"log_name":     "guard-spec.events",
			"event_code":   ev.Type,
			"original_time": ev.OccurredAt.UTC().Format("2006-01-02T15:04:05.000Z07:00"),
		},
		"unmapped": unmappedAttrs(ev),
	}
	if ev.ProjectID != nil {
		r["metadata"].(map[string]any)["labels"] = []string{"project:" + ev.ProjectID.String()}
	}
	switch {
	case strings.HasPrefix(ev.Type, "detection."):
		detection(r, ev)
	case ev.Type == events.SecurityLoginFailed:
		r.class(classAuthentication, 1, "Logon")
		r["status_id"], r["status"] = 2, "Failure"
		r["status_detail"] = str(ev.Attrs, "reason")
		r["user"] = user(str(ev.Attrs, "user_id"), str(ev.Attrs, "email_hash"))
		if ip := str(ev.Attrs, "ip"); ip != "" {
			r["src_endpoint"] = map[string]any{"ip": ip}
		}
	case ev.Type == events.SecurityMFALocked:
		r.class(classAccountChange, 9, "Lock")
		r["user"] = user(str(ev.Attrs, "user_id"), "")
	case ev.Type == events.SecurityRoleChanged, ev.Type == events.SecurityOwnerAdded:
		r.class(classAccountChange, 7, "Attach Policy")
		r["user"] = user(str(ev.Attrs, "user_id"), "")
		if a := str(ev.Attrs, "actor_id"); a != "" {
			r["actor"] = map[string]any{"user": map[string]any{"uid": a}}
		}
	default:
		apiActivity(r, ev)
	}
	return r
}

// class sets the class, category, activity and type of the record.
func (r Record) class(uid, activity int, activityName string) {
	r["class_uid"], r["class_name"] = uid, classNames[uid]
	r["category_uid"] = classCategory[uid]
	r["activity_id"], r["activity_name"] = activity, activityName
	r["type_uid"] = uid*100 + activity
	r["type_name"] = classNames[uid] + ": " + activityName
}

func detection(r Record, ev events.Event) {
	r.class(classDetectionFinding, 1, "Create")
	types := []string{}
	if cats, ok := ev.Attrs["categories"].([]any); ok {
		for _, c := range cats {
			if s, ok := c.(string); ok {
				types = append(types, s)
			}
		}
	}
	info := map[string]any{
		"uid":   ev.ID.String(),
		"title": map[string]string{events.DetectionBlocked: "Prompt injection blocked", events.DetectionFlagged: "Prompt injection flagged"}[ev.Type],
		"types": types,
	}
	if info["title"] == "" {
		info["title"] = ev.Type
	}
	if layer := str(ev.Attrs, "layer"); layer != "" {
		info["analytic"] = map[string]any{"name": layer, "type_id": 1, "type": "Rule"}
	}
	if id := str(ev.Attrs, "request_id"); id != "" {
		info["related_events"] = []map[string]any{{"uid": id, "type": "guard-spec request"}}
	}
	r["finding_info"] = info
	switch {
	case ev.Type == events.DetectionBlocked:
		r["disposition_id"], r["disposition"] = 2, "Blocked"
	case str(ev.Attrs, "decision") == "redact":
		r["disposition_id"], r["disposition"] = 11, "Corrected"
	default:
		r["disposition_id"], r["disposition"] = 1, "Allowed"
	}
	r["action_id"], r["action"] = map[bool]int{true: 2, false: 1}[ev.Type == events.DetectionBlocked],
		map[bool]string{true: "Denied", false: "Allowed"}[ev.Type == events.DetectionBlocked]
	r["status_id"], r["status"] = 1, "New"
	if score, ok := ev.Attrs["score"].(float64); ok {
		r["confidence_score"] = int(score*100 + 0.5)
	}
}

func apiActivity(r Record, ev events.Event) {
	// The verb: the event's action attribute when it has one (config.*
	// events carry created, updated, deleted), else the end of its type.
	verb := str(ev.Attrs, "action")
	if verb == "" {
		verb = ev.Type[strings.LastIndexByte(ev.Type, '.')+1:]
	}
	activity, name := 99, "Other"
	switch {
	case strings.Contains(verb, "creat") || strings.Contains(verb, "added"):
		activity, name = 1, "Create"
	case strings.Contains(verb, "delet") || strings.Contains(verb, "removed") || strings.Contains(verb, "revoked"):
		activity, name = 4, "Delete"
	case strings.Contains(verb, "chang") || strings.Contains(verb, "updat"):
		activity, name = 3, "Update"
	case strings.Contains(verb, "viewed"):
		activity, name = 2, "Read"
	}
	r.class(classAPIActivity, activity, name)
	actor := map[string]any{"app_name": "Guard Spec"}
	if a := str(ev.Attrs, "actor_id"); a != "" {
		actor["user"] = map[string]any{"uid": a}
	}
	r["actor"] = actor
	r["api"] = map[string]any{"operation": ev.Type, "service": map[string]any{"name": "guard-spec"}}
	src := map[string]any{"name": "guard-spec"}
	if ip := str(ev.Attrs, "ip"); ip != "" {
		src = map[string]any{"ip": ip}
	}
	r["src_endpoint"] = src
	if ev.Type == events.UpstreamError {
		r["status_id"], r["status"] = 2, "Failure"
		r["status_code"] = fmt.Sprint(ev.Attrs["status"])
		r["status_detail"] = str(ev.Attrs, "error_kind")
	} else {
		r["status_id"], r["status"] = 1, "Success"
	}
}

func user(uid, emailHash string) map[string]any {
	u := map[string]any{}
	if uid != "" {
		u["uid"] = uid
	}
	if emailHash != "" {
		// The hash of the address, never the address (docs/alerts.md).
		u["uid_alt"] = emailHash
	}
	if uid == "" {
		u["name"] = "unknown" // a failed login of an address that has no account
	}
	return u
}

func str(m map[string]any, k string) string {
	if v, ok := m[k]; ok && v != nil {
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprint(v)
	}
	return ""
}

// unmappedAttrs keeps the event's own fields, so nothing is lost on the way.
func unmappedAttrs(ev events.Event) map[string]any {
	out := map[string]any{"event_type": ev.Type, "org_id": ev.OrgID.String()}
	for k, v := range ev.Attrs {
		out[k] = v
	}
	return out
}
