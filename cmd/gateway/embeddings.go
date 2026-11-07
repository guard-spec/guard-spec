// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/indirect"
	"github.com/guard-spec/guard-spec/internal/policy"
	"github.com/guard-spec/guard-spec/internal/proxy"
)

// POST /v1/embeddings is forwarded to {base_url}/embeddings of the upstream the
// request's route picks, with the key check, rate limit, policies, routing and
// the upstream's model allowlist, and one audit row (its content stored only
// when the org stores content; the vectors never). An embedding produces no
// text a model acts on, so the input is not classified by default: text that
// is embedded for retrieval is scanned when it is retrieved, as a document or
// tool result (POST /guardrail/scan, or in the request that carries it).
// EMBEDDINGS_SCAN=on classifies each input as an untrusted document anyway
// (a poisoned corpus caught at indexing time); it is never rewritten, since
// that would change the vector, and a request over the indirect threshold is
// refused (INDIRECT_ACTION=redact cannot apply: nothing replaces an input).

// errNotEmbeddings refuses /v1/embeddings for an upstream without the endpoint.
var errNotEmbeddings = errors.New("upstream does not serve embeddings")

// embeddingsRoute refuses the anthropic provider, which has no embeddings.
func embeddingsRoute(r route) error {
	if r.proxy == nil || r.provider != providerAnthropic {
		return nil
	}
	name := r.name
	if name == "" {
		name = "UPSTREAM_LLM_URL"
	}
	return errors.New(errNotEmbeddings.Error() + ": upstream " + strconv.Quote(name) +
		" (provider anthropic) has no /embeddings; route /v1/embeddings to an OpenAI-compatible upstream")
}

// embeddingTexts returns the text inputs of an embeddings request. Token
// arrays cannot be read as text, so they are refused when scanning is on.
func embeddingTexts(raw any) ([]string, error) {
	switch v := raw.(type) {
	case string:
		return []string{v}, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			text, ok := item.(string)
			if !ok {
				return nil, errUnsupportedContent
			}
			out = append(out, text)
		}
		return out, nil
	}
	return nil, errUnsupportedContent
}

func embeddingsHandler(gw gateway) fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()
		release := gw.audit.hold()
		entry := newEntry(c)
		gw := gw.forRequest(&entry)
		defer func() {
			entry.Status = c.Response().StatusCode()
			entry.LatencyMs = int(time.Since(start).Milliseconds())
			gw.audit.record(entry)
			release()
		}()

		body, err := decodeBody(c.Body())
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
		}
		entry.Model, _ = body["model"].(string)
		scanCfg, err := gw.scanConfigFor(entry.OrgID)
		if err != nil {
			slog.Error("org scan settings unavailable", "org", entry.OrgID, "err", err)
			return policyUnavailable(c)
		}

		if scanCfg.EmbeddingsScan {
			guard := textGuard{roles: &scanCfg.Roles, org: entry.OrgID, useCache: true}
			texts, err := embeddingTexts(body["input"])
			if err == nil {
				err = guard.as(indirect.SourceDocument, nil, func() error {
					for _, t := range texts {
						if err := guard.scoreUntrusted(t); err != nil {
							return err
						}
					}
					return nil
				})
			}
			entry.Report = guard.report
			if err != nil {
				if errors.Is(err, errBlocked) {
					entry.Detected, entry.Trigger = layerSanitizer, guard.blocked
				}
				return guardError(c, err)
			}
			verdict, err := gw.scoreRequest(&guard)
			if err != nil {
				return scanError(c, err)
			}
			entry.Scores, entry.Indirect, entry.SourceRole = verdict.Scores, verdict.Indirect, verdict.SourceRole
			if verdict.Indirect.Score >= scanCfg.IndirectThreshold {
				slog.Info("blocked indirect injection in embeddings input", "score", verdict.Indirect.Score,
					"category", verdict.Indirect.Category)
				entry.Detected, entry.Trigger = layerIndirect, verdict.IndirectTrigger
				return blockResponse(c, "Request blocked: prompt injection detected in tool or document content.")
			}
		}

		decision, routes, err := gw.evaluatePolicies(entry, policyVars(entry, body, len(c.Body())))
		if err != nil {
			slog.Error("policy evaluation failed", "org", entry.OrgID, "err", err)
			return policyUnavailable(c)
		}
		entry.RuleID = decision.RuleID
		if entry.RuleID == uuid.Nil && len(decision.Logged) > 0 {
			entry.RuleID = decision.Logged[0]
		}
		switch decision.Action {
		case policy.ActionAllow, policy.ActionRoute:
		case policy.ActionBlock:
			entry.Detected = layerPolicy
			return blockResponse(c, "Request blocked by policy.")
		default:
			slog.Error("rule has an action the gateway cannot enforce", "rule", decision.RuleID, "action", decision.Action)
			return policyUnavailable(c)
		}

		target, err := gw.resolveRoute(entry, decision, routes)
		entry.RouteTarget = target.name
		if errors.Is(err, errRouteUnavailable) {
			entry.Action, entry.ErrorKind = actionError, errorKindConnect
			return c.Status(fiber.StatusBadGateway).
				JSON(errorBody("route target unavailable", "server_error", "route_unavailable"))
		}
		if err != nil {
			slog.Error("upstreams unavailable", "org", entry.OrgID, "err", err)
			return policyUnavailable(c)
		}
		if err := embeddingsRoute(target); err != nil {
			entry.Action, entry.UpstreamID = actionError, target.id
			return c.Status(fiber.StatusBadRequest).JSON(errorBody(err.Error(), "invalid_request_error", "unsupported_upstream"))
		}
		entry.Action = actionAllow
		if decision.Action == policy.ActionRoute {
			entry.Action = actionRoute
		}
		model, err := target.applyModel(entry.Model)
		if errors.Is(err, errModelNotAllowed) {
			entry.ErrorKind, entry.UpstreamID, entry.Action = errorKindModel, target.id, actionBlock
			return c.Status(fiber.StatusBadRequest).JSON(errorBody(
				"model "+strconv.Quote(entry.Model)+" is not allowed for this upstream", "invalid_request_error", "model_not_allowed"))
		}
		data := c.Body()
		if model != entry.Model {
			body["model"], entry.Model = model, model
			if data, err = json.Marshal(body); err != nil {
				return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
			}
		}
		if target.proxy == nil {
			return c.JSON(embeddingsStub(body))
		}
		entry.UpstreamID = target.id
		resp, err := target.proxy.Do(requestContext(c, gw.base), "/embeddings", data, proxy.Call{})
		if err != nil {
			entry.Action = actionError
			entry.ErrorKind, entry.UpstreamStatus = upstreamErrorKind(err)
			return upstreamError(c, err)
		}
		defer resp.Close()
		out, err := resp.ReadAll()
		if err != nil {
			entry.Action = actionError
			entry.ErrorKind, entry.UpstreamStatus = upstreamErrorKind(err)
			return upstreamError(c, err)
		}
		c.Set(fiber.HeaderContentType, resp.ContentType)
		return c.Status(resp.Status).Send(out)
	}
}

// embeddingsStub answers without an upstream: a zero vector per input.
func embeddingsStub(body map[string]any) fiber.Map {
	n := 1
	if list, ok := body["input"].([]any); ok {
		n = len(list)
	}
	data := make([]fiber.Map, 0, n)
	for i := range n {
		data = append(data, fiber.Map{"object": "embedding", "index": i, "embedding": make([]float64, 8)})
	}
	return fiber.Map{"object": "list", "data": data, "model": body["model"],
		"usage": fiber.Map{"prompt_tokens": 0, "total_tokens": 0}}
}
