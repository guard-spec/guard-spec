// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"errors"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gofiber/fiber/v2"
	"github.com/guard-spec/guard-spec/internal/backend"
	"github.com/guard-spec/guard-spec/internal/indirect"
	"github.com/guard-spec/guard-spec/internal/jsonpath"
	"github.com/guard-spec/guard-spec/internal/outputguard"
	"github.com/guard-spec/guard-spec/internal/policy"
	"github.com/guard-spec/guard-spec/internal/proxy"
	"github.com/guard-spec/guard-spec/internal/tracing"
)

// Custom backends (RF-d6ba510e): /v1/backend/{upstream}/{path} sends a
// request to {base_url}{path} of the org's upstream {upstream}, which must be
// of provider custom (internal/backend, migration 031).
//
// In order: the API key and rate limit (middleware); the upstream (404 when
// the org has none of that name, 400 when it is not a custom backend, 502
// when it is disabled, misconfigured, or its key is not allowed for the org
// by UPSTREAM_KEY_ORGS); the method (405) and the path (400 when it could
// mean another path to the backend, 403 outside the path prefixes); the body
// (JSON, or text with raw_text; anything else 415).
//
// The declared request fields (scan.request, or every string with
// scan.all_strings) and every query parameter value are sanitized and
// classified as user text, with the same thresholds, input checks and
// policies as a chat request. A refused request never reaches the backend.
// An allowed one is forwarded byte for byte, unless the org's
// input_pii_action replaced personal data in a scanned field: then only those
// string values are rewritten (jsonpath.Doc.Replace), every other byte stays
// as sent; a changed query string is re-encoded. Route rules do not apply:
// the URL names the backend.
//
// The answer: 2xx and 4xx are relayed (401 and 407 are about the gateway's
// credentials and become a 502, as are 5xx and redirects, which are never
// followed). A JSON answer has its declared fields (scan.response, or every
// string with all_strings) put through the output guard: links, the org's
// output_pii_action and kinds, and tokenized values restored. A text answer
// is guarded whole with raw_text. An event stream, and any other answer, is
// relayed unchecked.

// routeBackend is the route label of /v1/backend/..., path-style like the
// other labels.
const routeBackend = "/v1/backend"

const backendPrefix = "/v1/backend/"

// isBackendPath reports a path under /v1/backend/.
func isBackendPath(path string) bool {
	return len(path) > len(backendPrefix) && strings.EqualFold(path[:len(backendPrefix)], backendPrefix)
}

// backendTarget splits the raw request path into the upstream's name and the
// backend path ("" when none).
func backendTarget(raw string) (name, rest string, ok bool) {
	if !isBackendPath(raw) {
		return "", "", false
	}
	name, rest, found := strings.Cut(raw[len(backendPrefix):], "/")
	if found {
		rest = "/" + rest
	}
	return name, rest, policy.ValidUpstreamName(name)
}

// backendDeniedHeaders are client headers never forwarded besides those the
// proxy refuses (credentials, hop-by-hop, Host, X-Forwarded-*, Proxy-*):
// addresses a backend might trust, and the gateway's own content headers.
var backendDeniedHeaders = map[string]bool{
	"x-real-ip": true, "true-client-ip": true, "x-client-ip": true, "cf-connecting-ip": true,
	"content-type": true, "content-length": true, "accept-encoding": true,
}

const (
	maxBackendHeaders     = 50
	maxBackendHeaderBytes = 4096
)

// backendHeaders copies the client headers that may go to the backend. The
// proxy drops reserved and credential names again (proxy.Call.Header).
func backendHeaders(c *fiber.Ctx) http.Header {
	out := http.Header{}
	connection := map[string]bool{}
	for _, v := range c.Request().Header.PeekAll(fiber.HeaderConnection) {
		for _, name := range strings.Split(string(v), ",") {
			connection[strings.ToLower(strings.TrimSpace(name))] = true
		}
	}
	n := 0
	for k, v := range c.Request().Header.All() {
		name := string(k)
		lower := strings.ToLower(name)
		if backendDeniedHeaders[lower] || connection[lower] || n >= maxBackendHeaders || len(v) > maxBackendHeaderBytes {
			continue
		}
		n++
		out.Add(name, string(v))
	}
	return out
}

// backendRelayedHeaders are the backend's response headers sent on.
var backendRelayedHeaders = []string{"Cache-Control", "Content-Language", "ETag", "Last-Modified", "Expires", "Retry-After"}

// mediaType returns the lower-case media type of a Content-Type.
func mediaType(contentType string) string {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(contentType))
	}
	return mt
}

func isJSONType(mt string) bool { return mt == "application/json" || strings.HasSuffix(mt, "+json") }

// isTextType is what raw_text guards in an answer.
func isTextType(mt string) bool {
	return strings.HasPrefix(mt, "text/") && mt != "text/event-stream"
}

func backendError(c *fiber.Ctx, status int, message, code string) error {
	errType := "invalid_request_error"
	if status >= 500 {
		errType = "server_error"
	}
	return c.Status(status).JSON(errorBody(message, errType, code))
}

// backendRequest is a request body read for scanning: the JSON document and
// its scanned strings, or the whole text with raw_text.
type backendRequest struct {
	doc   *jsonpath.Doc
	nodes []*jsonpath.Node
	raw   bool
	text  string
}

// backendRefusal is a request refused before it is scanned.
type backendRefusal struct {
	status        int
	message, code string
}

func (e *backendRefusal) Error() string { return e.message }

// readBackendBody parses the body as the backend's configuration says.
func readBackendBody(cfg *backend.Config, body []byte, contentType string) (backendRequest, *backendRefusal) {
	var r backendRequest
	if len(body) == 0 {
		return r, nil
	}
	mt := mediaType(contentType)
	if !isJSONType(mt) {
		if !cfg.Scan.RawText {
			return r, &backendRefusal{fiber.StatusUnsupportedMediaType,
				"this backend accepts JSON bodies (Content-Type: application/json)", "unsupported_media_type"}
		}
		if !utf8.Valid(body) {
			return r, &backendRefusal{fiber.StatusUnsupportedMediaType, "the body is not UTF-8 text", "unsupported_media_type"}
		}
		r.raw, r.text = true, string(body)
		return r, nil
	}
	doc, err := jsonpath.ParseDoc(body)
	if err != nil {
		return r, &backendRefusal{fiber.StatusBadRequest, err.Error(), "invalid_body"}
	}
	r.doc = doc
	if paths := cfg.RequestPaths(); len(paths) > 0 {
		r.nodes, err = doc.Collect(paths)
	} else if cfg.Scan.AllStrings {
		r.nodes = jsonpath.Strings(doc.Root)
	}
	if err != nil {
		return r, &backendRefusal{fiber.StatusBadRequest, err.Error(), "invalid_body"}
	}
	return r, nil
}

func backendHandler(gw gateway) fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()
		release := gw.audit.hold()
		entry := newEntry(c)
		gw := gw.forRequest(&entry)
		tctx := requestContext(c, gw.base)
		streaming := false // the stream writes the row when it ends
		defer func() {
			if !streaming {
				entry.Status = c.Response().StatusCode()
				entry.LatencyMs = int(time.Since(start).Milliseconds())
				gw.audit.record(entry)
				release()
			}
		}()

		// The raw path, not the normalized one: what is checked is what the
		// backend gets.
		name, rawPath, ok := backendTarget(string(c.Request().URI().PathOriginal()))
		if !ok {
			return backendError(c, fiber.StatusNotFound, "use /v1/backend/{upstream}/{path}", "backend_not_found")
		}
		entry.RouteTarget = name
		if gw.upstreams == nil || gw.pool == nil {
			return backendError(c, fiber.StatusNotFound, "no custom backend named "+strconv.Quote(name), "backend_not_found")
		}
		ctx, cancel := context.WithTimeout(gw.base, policyTimeout)
		up, _, err := gw.upstreams(ctx, entry.OrgID, entry.ProjectID, name)
		cancel()
		if errors.Is(err, errNoSuchUpstream) {
			return backendError(c, fiber.StatusNotFound, "no custom backend named "+strconv.Quote(name), "backend_not_found")
		}
		if err != nil {
			slog.Error("upstreams unavailable", "org", entry.OrgID, "err", err)
			return policyUnavailable(c)
		}
		entry.UpstreamID = up.ID
		if up.Provider != backend.Provider || up.Backend == nil {
			return backendError(c, fiber.StatusBadRequest, "upstream "+strconv.Quote(name)+
				" is not a custom backend; send model requests to /v1/chat/completions", "not_a_backend")
		}
		unavailable := func(reason error) error {
			slog.Warn("custom backend unavailable", "org", entry.OrgID, "upstream_id", up.ID, "reason", reason)
			entry.Action, entry.ErrorKind = actionError, errorKindConnect
			return backendError(c, fiber.StatusBadGateway, "route target unavailable", "route_unavailable")
		}
		if !up.Enabled {
			return unavailable(errors.New("upstream is disabled"))
		}
		cfg := *up.Backend
		if err := cfg.Validate(); err != nil {
			return unavailable(err)
		}

		method := strings.Clone(c.Method())
		if !cfg.AllowsMethod(method) {
			c.Set(fiber.HeaderAllow, strings.Join(cfg.Methods, ", "))
			return backendError(c, fiber.StatusMethodNotAllowed, "method "+method+" is not allowed for this backend",
				"method_not_allowed")
		}
		path, err := backend.CleanPath(rawPath)
		if err != nil {
			return backendError(c, fiber.StatusBadRequest, err.Error(), "invalid_path")
		}
		if !cfg.AllowsPath(path) {
			return backendError(c, fiber.StatusForbidden, "path "+strconv.Quote(path)+" is not allowed for this backend",
				"path_not_allowed")
		}
		query, err := url.ParseQuery(string(c.Request().URI().QueryString()))
		if err != nil {
			return backendError(c, fiber.StatusBadRequest, "the query string is not valid", "invalid_query")
		}
		// The key allowlist (UPSTREAM_KEY_ORGS) and the address rules, before
		// anything is scanned.
		px, err := gw.pool.get(entry.OrgID, up)
		if err != nil {
			return unavailable(err)
		}

		body := c.Body()
		contentType := strings.Clone(c.Get(fiber.HeaderContentType))
		req, refusal := readBackendBody(&cfg, body, contentType)
		if refusal != nil {
			return backendError(c, refusal.status, refusal.message, refusal.code)
		}

		scanCfg, err := gw.scanConfigFor(entry.OrgID)
		if err != nil {
			slog.Error("org scan settings unavailable", "org", entry.OrgID, "err", err)
			return policyUnavailable(c)
		}
		guard := textGuard{roles: &scanCfg.Roles, org: entry.OrgID, detectPII: scanCfg.InputPII,
			pseudo: outputguard.NewPseudonymizer(scanCfg.PIIAction, scanCfg.PIIKinds), limits: gw.limitsFor(scanCfg),
			input: scanCfg.Input, source: indirect.SourceUser}

		// Sanitize and collect; personal data is replaced in the value as
		// sent, not in its sanitized form, so that nothing else changes.
		replaced := map[*jsonpath.Node]string{}
		rawText := req.text
		queryChanged := false
		_, endSpan := tracing.Start(tctx, "sanitize")
		err = func() error {
			for _, n := range req.nodes {
				if _, err := guard.sanitizeCollect(n.Str); err != nil {
					return err
				}
				if out := guard.pseudonymize(n.Str); out != n.Str {
					replaced[n] = out
				}
			}
			if req.raw {
				if _, err := guard.sanitizeCollect(req.text); err != nil {
					return err
				}
				rawText = guard.pseudonymize(req.text)
			}
			for _, values := range query {
				for i, v := range values {
					if _, err := guard.sanitizeCollect(v); err != nil {
						return err
					}
					if out := guard.pseudonymize(v); out != v {
						values[i], queryChanged = out, true
					}
				}
			}
			return nil
		}()
		endSpan(err)
		entry.Report, entry.InputPII = guard.report, guard.pii
		if guard.pseudo != nil {
			entry.PIIAction, entry.PIIProtected = scanCfg.PIIAction, guard.pseudo.Counts
		}
		if err != nil {
			if errors.Is(err, errBlocked) {
				entry.Detected, entry.Trigger = layerSanitizer, guard.blocked
			}
			return guardError(c, err)
		}
		var refused *inputRefusal
		if err := gw.checkInputTokens(&guard); err != nil {
			if errors.As(err, &refused) {
				return refuseInput(c, &entry, refused)
			}
			return scanError(c, err)
		}

		_, endSpan = tracing.Start(tctx, "detect")
		verdict, err := gw.scoreRequest(&guard)
		endSpan(err)
		if err != nil {
			if errors.Is(err, errUnsupportedContent) {
				return guardError(c, err)
			}
			return scanError(c, err)
		}
		entry.Scores, entry.Indirect, entry.SourceRole = verdict.Scores, verdict.Indirect, verdict.SourceRole
		if verdict.Direct >= scanCfg.injectionThreshold() {
			slog.Info("blocked injection", "route", routeBackend, "score", verdict.Direct,
				"layer", modelLayer(verdict.Scores), "label", verdict.Scores.Injection.Label)
			entry.Detected, entry.Trigger = modelLayer(verdict.Scores), verdict.DirectTrigger
			return blockResponse(c, "Request blocked: prompt injection detected.")
		}
		if verdict.Indirect.Score >= scanCfg.IndirectThreshold {
			entry.Detected, entry.Trigger = layerIndirect, verdict.IndirectTrigger
			return blockResponse(c, "Request blocked: prompt injection detected in tool or document content.")
		}

		// The body as sent: the client's bytes, or with the replaced values.
		data := body
		if len(replaced) > 0 {
			if data, err = req.doc.Replace(replaced); err != nil {
				return backendError(c, fiber.StatusBadRequest, "invalid body", "invalid_body")
			}
		} else if req.raw && rawText != req.text {
			data = []byte(rawText)
		}
		rawQuery := string(c.Request().URI().QueryString())
		if queryChanged {
			rawQuery = query.Encode()
		}

		_, endSpan = tracing.Start(tctx, "policy")
		decision, _, err := gw.evaluatePolicies(entry, policyVars(entry, nil, len(data)))
		endSpan(err)
		if err != nil {
			slog.Error("policy evaluation failed", "org", entry.OrgID, "err", err)
			return policyUnavailable(c)
		}
		recordPolicyMatches(&entry, decision)
		switch decision.Action {
		case policy.ActionAllow, policy.ActionRoute: // the URL names the backend; route rules do not apply
		case policy.ActionBlock:
			slog.Info("blocked by policy", "rule", decision.RuleID, "route", routeBackend)
			entry.Detected, entry.Trigger = layerPolicy, verdict.DirectTrigger
			return blockResponse(c, "Request blocked by policy.")
		default:
			slog.Error("rule has an action the gateway cannot enforce", "rule", decision.RuleID, "action", decision.Action)
			return policyUnavailable(c)
		}
		entry.Action = actionAllow

		// The output guard: the org's personal data settings, no canary (a
		// backend has no system prompt to carry one).
		var scan *outputguard.Scanner
		if gw.output != nil {
			scan = gw.output.WithPII(scanCfg.OutputPIIAction, scanCfg.OutputPIIKinds).ForRequest("")
		}
		if tokens := guard.pseudo.Tokens(); tokens != nil {
			if scan == nil {
				scan = outputguard.RestoreOnly().ForRequest("")
			}
			scan.WithTokens(tokens)
		}

		call := proxy.Call{Method: method, Header: backendHeaders(c), URLPath: path, RawQuery: rawQuery,
			ContentType: contentType, PassClientErrors: true}
		reqCtx, cancelReq := context.WithCancel(tctx)
		conn := c.Context().Conn()
		stopWatch := watchClose(conn, cancelReq, !gw.waitOnHalfClose)
		handedOff := false
		defer func() {
			if !handedOff {
				stopWatch()
				cancelReq()
			}
		}()
		resp, err := px.Do(reqCtx, "/backend", data, call)
		if err != nil {
			entry.Action = actionError
			entry.ErrorKind, entry.UpstreamStatus = upstreamErrorKind(err)
			clientLeft(reqCtx, gw.base)
			return upstreamError(c, err)
		}
		if resp.Status >= 400 {
			entry.UpstreamStatus = resp.Status
		}
		for _, h := range backendRelayedHeaders {
			if v := resp.Header.Get(h); v != "" {
				c.Set(h, v)
			}
		}

		if resp.Stream() {
			// Relayed as it comes, unchecked: the stream's format is the
			// backend's own.
			streaming, handedOff = true, true
			stopWatch()
			c.Set(fiber.HeaderContentType, resp.ContentType)
			c.Set(fiber.HeaderCacheControl, "no-cache")
			c.Status(resp.Status).Context().SetBodyStreamWriter(func(w *bufio.Writer) {
				defer release()
				defer cancelReq()
				defer resp.Close()
				stop := watchClose(conn, cancelReq, !gw.waitOnHalfClose)
				if relay(w, resp, nil, func(string, string, string) []byte { return nil }) == relayUpstreamFailed {
					entry.Action, entry.ErrorKind = actionError, errorKindConnect
				}
				stop()
				entry.Status = resp.Status
				entry.LatencyMs = int(time.Since(start).Milliseconds())
				gw.audit.record(entry)
			})
			return nil
		}

		defer resp.Close()
		out, err := resp.ReadAll()
		if err != nil {
			entry.Action = actionError
			entry.ErrorKind, entry.UpstreamStatus = upstreamErrorKind(err)
			clientLeft(reqCtx, gw.base)
			return upstreamError(c, err)
		}
		entry.Response = string(out)
		if scan != nil {
			counts := outputguard.Counts{}
			_, endSpan := tracing.Start(tctx, "output_guard")
			guarded, err := guardBackendResponse(&cfg, scan, resp.ContentType, out, counts)
			endSpan(err)
			entry.Output = counts
			if err != nil {
				entry.Action = actionError
				slog.Warn("backend response could not be checked", "upstream_id", up.ID, "err", err)
				return backendError(c, fiber.StatusBadGateway, "upstream response could not be checked", "upstream_error")
			}
			if string(guarded) != string(out) {
				c.Response().Header.Del(fiber.HeaderETag) // it named the backend's bytes
				out = guarded
			}
		}
		entry.Response = string(out)
		if resp.ContentType != "" {
			c.Set(fiber.HeaderContentType, resp.ContentType)
		}
		return c.Status(resp.Status).Send(out)
	}
}

// guardBackendResponse runs the output guard on the declared fields of a JSON
// answer, or on a whole text answer with raw_text. Anything else, and an
// empty body, is returned as is. An answer that says it is JSON but is not
// is an error: its fields cannot be found.
func guardBackendResponse(cfg *backend.Config, scan *outputguard.Scanner, contentType string, body []byte,
	counts outputguard.Counts) ([]byte, error) {
	if len(body) == 0 {
		return body, nil
	}
	mt := mediaType(contentType)
	switch {
	case isJSONType(mt):
		paths := cfg.ResponsePaths()
		if len(paths) == 0 && !cfg.Scan.AllStrings {
			return body, nil
		}
		doc, err := jsonpath.ParseDoc(body)
		if err != nil {
			return nil, err
		}
		var nodes []*jsonpath.Node
		if len(paths) > 0 {
			// A case-shadowed key is the backend's own doing, not an
			// attack on the gateway: every match is guarded.
			if nodes, err = doc.Collect(paths); errors.Is(err, jsonpath.ErrShadowKey) {
				nodes, err = jsonpath.Strings(doc.Root), nil
			}
			if err != nil {
				return nil, err
			}
		} else {
			nodes = jsonpath.Strings(doc.Root)
		}
		replaced := map[*jsonpath.Node]string{}
		for _, n := range nodes {
			if out := scan.Text(n.Str, counts); out != n.Str {
				replaced[n] = out
			}
		}
		if len(replaced) == 0 {
			return body, nil
		}
		return doc.Replace(replaced)
	case cfg.Scan.RawText && isTextType(mt) && utf8.Valid(body):
		return []byte(scan.Text(string(body), counts)), nil
	}
	return body, nil
}
