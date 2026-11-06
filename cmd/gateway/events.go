// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/events"
	"github.com/guard-spec/guard-spec/internal/inference"
	"github.com/guard-spec/guard-spec/internal/proxy"
)

// Alert events of the gateway (docs/alerts.md): detection.blocked,
// detection.flagged and upstream.error. They are built from the audit entry
// after the response, on the audit goroutine, and handed to a bounded
// emitter that never blocks; nothing is added to the request path. Events
// carry metadata only: never the prompt or the response.

// Layers that block a request, the layer attribute of detection events.
const (
	layerSanitizer = "sanitizer" // hidden characters or anomaly score
	layerIndirect  = "indirect"  // tool results, documents, tool descriptions
	layerPolicy    = "policy"
	layerScan      = "scan" // the /guardrail/scan endpoints
)

// decisionRedact is the decision of a detection.flagged event for a request
// whose untrusted content was redacted; its audit row says allow (or route)
// with the tag input:redacted=<n>.
const decisionRedact = "redact"

// error_kind values of upstream.error.
const (
	errorKindTimeout = "timeout"
	errorKind5xx     = "5xx"
	errorKindModel   = "model_not_allowed"
	errorKindConnect = "connect"
)

// defaultFlagThreshold is the injection score at which a request that was
// not blocked is reported as detection.flagged (ALERTS_FLAG_THRESHOLD).
const defaultFlagThreshold = 0.5

func flagThreshold(getenv func(string) string) float64 {
	if v, err := strconv.ParseFloat(getenv("ALERTS_FLAG_THRESHOLD"), 64); err == nil && v > 0 && v <= 1 {
		return v
	}
	return defaultFlagThreshold
}

// apiKeyPrefix is the shown prefix of the caller's key (gs_ plus 8
// characters), the api_key_id of events. Never the key itself.
func apiKeyPrefix(c *fiber.Ctx) string {
	raw := c.Get("x-api-key")
	if a := c.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		raw = strings.TrimPrefix(a, "Bearer ")
	}
	if len(raw) < 11 || !strings.HasPrefix(raw, "gs_") {
		return ""
	}
	return raw[:11]
}

// modelLayer names the detection layer with the highest score.
func modelLayer(s inference.Scores) string {
	d := s.Injection.Detail
	if d == nil {
		return "l1"
	}
	layer, best := "l1", d.L1
	if d.L2 > best {
		layer, best = "l2", d.L2
	}
	if d.L3 > best {
		layer = "l3"
	}
	return layer
}

// categories lists the detected categories, strongest first, at most five.
func categories(e *requestEntry) []string {
	out := []string{}
	if d := e.Scores.Injection.Detail; d != nil && len(d.Categories) > 0 {
		type kv struct {
			k string
			v float64
		}
		list := make([]kv, 0, len(d.Categories))
		for k, v := range d.Categories {
			if v > 0 {
				list = append(list, kv{k, v})
			}
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].v != list[j].v {
				return list[i].v > list[j].v
			}
			return list[i].k < list[j].k
		})
		for _, x := range list {
			if len(out) == 5 {
				break
			}
			out = append(out, x.k)
		}
	}
	if len(out) == 0 {
		if c := e.Indirect.Category; c != "" {
			out = append(out, c)
		} else if l := e.Scores.Injection.Label; l != "" && l != "BENIGN" {
			out = append(out, l)
		}
	}
	return out
}

// upstreamErrorKind classifies a proxy failure.
func upstreamErrorKind(err error) (string, int) {
	var pe *proxy.Error
	if !errors.As(err, &pe) {
		return errorKindConnect, 0
	}
	switch {
	case pe.Code == "upstream_timeout":
		return errorKindTimeout, pe.Status
	case pe.Status >= 500:
		return errorKind5xx, pe.Status
	case pe.Status == 0:
		return errorKindConnect, 0
	}
	return "", pe.Status // a 4xx is the client's request, not an upstream failure
}

// eventsFor returns the alert events of a finished request.
func eventsFor(e *requestEntry, flagAt float64) []events.Event {
	if e.OrgID == uuid.Nil {
		return nil
	}
	var project *uuid.UUID
	if e.ProjectID != uuid.Nil {
		p := e.ProjectID
		project = &p
	}
	score := float64(e.Scores.Injection.Confidence)
	if e.Indirect.Score > score {
		score = e.Indirect.Score
	}
	detection := func(typ, severity, layer string) events.Event {
		attrs := map[string]any{
			"request_id": e.ID.String(),
			"categories": categories(e),
			"score":      score,
			"layer":      layer,
			"decision":   e.Action,
			"api_key_id": e.KeyPrefix,
			"model":      truncate(e.Model, 100),
		}
		if e.RuleID != uuid.Nil {
			attrs["policy_id"] = e.RuleID.String()
		}
		return events.Event{OrgID: e.OrgID, ProjectID: project, Type: typ, Severity: severity, OccurredAt: e.Start,
			Attrs: attrs}
	}
	var out []events.Event
	switch {
	case e.Action == actionBlock && e.Detected != "":
		out = append(out, detection(events.DetectionBlocked, events.Warning, e.Detected))
	case e.Redacted > 0:
		// Untrusted content removed (INDIRECT_ACTION=redact); the request went on.
		ev := detection(events.DetectionFlagged, events.Warning, layerIndirect)
		ev.Attrs["decision"], ev.Attrs["redacted"] = decisionRedact, e.Redacted
		out = append(out, ev)
	case (e.Action == actionAllow || e.Action == actionRoute) && score >= flagAt:
		out = append(out, detection(events.DetectionFlagged, events.Info, modelLayer(e.Scores)))
	}
	if e.ErrorKind != "" {
		attrs := map[string]any{"status": e.UpstreamStatus, "error_kind": e.ErrorKind, "request_id": e.ID.String()}
		if e.UpstreamID != uuid.Nil {
			attrs["upstream_id"] = e.UpstreamID.String()
		}
		out = append(out, events.Event{OrgID: e.OrgID, ProjectID: project, Type: events.UpstreamError,
			Severity: events.Warning, OccurredAt: e.Start, Attrs: attrs})
	}
	return out
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// emitEvents hands the request's events to em; it never blocks.
func emitEvents(em *events.Emitter, e requestEntry, flagAt float64) {
	if em == nil {
		return
	}
	for _, ev := range eventsFor(&e, flagAt) {
		em.Emit(ev)
	}
}
