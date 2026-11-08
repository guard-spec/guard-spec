// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package siem

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/guard-spec/guard-spec/internal/events"
	"github.com/guard-spec/guard-spec/internal/proxy"
	"github.com/guard-spec/guard-spec/internal/version"
)

// Sink kinds.
const (
	KindSplunk   = "splunk_hec"
	KindElastic  = "elastic"
	KindSentinel = "sentinel"
	KindSyslog   = "syslog"
	KindHTTP     = "http"
)

// Kinds lists the sink kinds.
var Kinds = []string{KindSplunk, KindElastic, KindSentinel, KindSyslog, KindHTTP}

// Timeout bounds one delivery.
const Timeout = 15 * time.Second

// Sink is one destination, as configured for an organization.
type Sink struct {
	Kind   string
	Config map[string]any
	// Secret is the value of the sink's secret_env: the HEC token, the
	// Elasticsearch API key, the Entra ID client secret, the bearer token.
	Secret string
	// AllowPrivate lets it reach loopback and private addresses (the org is
	// in ALERTS_PRIVATE_ORGS and the sink asks for it).
	AllowPrivate bool
}

func (s Sink) cfg(key string) string {
	v, _ := s.Config[key].(string)
	return strings.TrimSpace(v)
}

// Validate checks the configuration as Deliver will use it. The error is
// safe to show.
func (s Sink) Validate() error {
	need := func(keys ...string) error {
		for _, k := range keys {
			if s.cfg(k) == "" {
				return fmt.Errorf("%s needs config.%s", s.Kind, k)
			}
		}
		return nil
	}
	checkURL := func(key string) error {
		if err := need(key); err != nil {
			return err
		}
		return proxy.ValidateTargetURL(s.cfg(key), s.AllowPrivate)
	}
	switch s.Kind {
	case KindSplunk, KindElastic, KindHTTP:
		return checkURL("url")
	case KindSentinel:
		if err := need("tenant_id", "client_id", "dcr_id", "stream"); err != nil {
			return err
		}
		return checkURL("endpoint")
	case KindSyslog:
		if err := need("address"); err != nil {
			return err
		}
		if _, _, err := net.SplitHostPort(s.cfg("address")); err != nil {
			return errors.New("syslog needs config.address as host:port (TLS)")
		}
		if f := s.cfg("format"); f != "" && f != "cef" && f != "json" {
			return errors.New("syslog config.format is cef or json")
		}
		return nil
	}
	return fmt.Errorf("unknown sink kind %q (have %s)", s.Kind, strings.Join(Kinds, ", "))
}

// Deliver sends the records of evs to the sink, all or nothing: an error
// means none can be taken as delivered (a retry may send some twice;
// SIEMs deduplicate on metadata.uid).
func Deliver(ctx context.Context, s Sink, evs []events.Event) error {
	if len(evs) == 0 {
		return nil
	}
	if err := s.Validate(); err != nil {
		return err
	}
	recs := make([]Record, len(evs))
	for i, ev := range evs {
		recs[i] = Map(ev)
	}
	client := proxy.SafeClient(!s.AllowPrivate, Timeout)
	switch s.Kind {
	case KindSplunk:
		return splunk(ctx, client, s, recs)
	case KindElastic:
		return elastic(ctx, client, s, recs)
	case KindSentinel:
		return sentinel(ctx, client, s, recs)
	case KindHTTP:
		return httpJSON(ctx, client, s, recs)
	case KindSyslog:
		return syslogTLS(ctx, s, evs, recs)
	}
	return fmt.Errorf("unknown sink kind %q", s.Kind)
}

// post sends body and returns the response body of a 2xx answer.
func post(ctx context.Context, client *http.Client, target, contentType string, body []byte, header map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "guard-spec/"+version.String())
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", redactURL(target), unwrap(err))
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%s: HTTP %d %s", redactURL(target), resp.StatusCode, truncate(string(data), 300))
	}
	return data, nil
}

func unwrap(err error) error {
	var u *url.Error
	if errors.As(err, &u) {
		return u.Err
	}
	return err
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "the sink"
	}
	u.User, u.RawQuery = nil, ""
	return u.String()
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// splunk sends to the HTTP Event Collector: one JSON event object a line.
func splunk(ctx context.Context, client *http.Client, s Sink, recs []Record) error {
	sourcetype := s.cfg("sourcetype")
	if sourcetype == "" {
		sourcetype = "ocsf:guard-spec"
	}
	var b bytes.Buffer
	for _, r := range recs {
		ev := map[string]any{"time": float64(r["time"].(int64)) / 1000, "sourcetype": sourcetype, "source": "guard-spec", "event": r}
		if idx := s.cfg("index"); idx != "" {
			ev["index"] = idx
		}
		line, _ := json.Marshal(ev)
		b.Write(line)
		b.WriteByte('\n')
	}
	target := strings.TrimRight(s.cfg("url"), "/") + "/services/collector/event"
	_, err := post(ctx, client, target, "application/json", b.Bytes(), map[string]string{"Authorization": "Splunk " + s.Secret})
	return err
}

// elastic sends a bulk request of create actions; a document that fails is
// an error (the whole batch is sent again, ids keep it idempotent).
func elastic(ctx context.Context, client *http.Client, s Sink, recs []Record) error {
	index := s.cfg("index")
	if index == "" {
		index = "guard-spec-ocsf"
	}
	var b bytes.Buffer
	for _, r := range recs {
		id := r["metadata"].(map[string]any)["uid"]
		action, _ := json.Marshal(map[string]any{"create": map[string]any{"_index": index, "_id": id}})
		doc := map[string]any{"@timestamp": r["metadata"].(map[string]any)["original_time"]}
		for k, v := range r {
			doc[k] = v
		}
		line, _ := json.Marshal(doc)
		b.Write(action)
		b.WriteByte('\n')
		b.Write(line)
		b.WriteByte('\n')
	}
	header := map[string]string{}
	if s.Secret != "" {
		header["Authorization"] = "ApiKey " + s.Secret
	}
	target := strings.TrimRight(s.cfg("url"), "/") + "/_bulk"
	data, err := post(ctx, client, target, "application/x-ndjson", b.Bytes(), header)
	if err != nil {
		return err
	}
	var out struct {
		Errors bool `json:"errors"`
		Items  []map[string]struct {
			Status int `json:"status"`
			Error  any `json:"error"`
		} `json:"items"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return fmt.Errorf("elasticsearch: %w", err)
	}
	if out.Errors {
		for _, item := range out.Items {
			for _, res := range item {
				// 409: the document is there already (a retry): fine.
				if res.Error != nil && res.Status != http.StatusConflict {
					e, _ := json.Marshal(res.Error)
					return fmt.Errorf("elasticsearch: %s", truncate(string(e), 300))
				}
			}
		}
	}
	return nil
}

// httpJSON posts a JSON array of records, with a bearer token when set.
func httpJSON(ctx context.Context, client *http.Client, s Sink, recs []Record) error {
	body, _ := json.Marshal(recs)
	header := map[string]string{}
	if s.Secret != "" {
		header["Authorization"] = "Bearer " + s.Secret
	}
	_, err := post(ctx, client, s.cfg("url"), "application/json", body, header)
	return err
}

// ── Microsoft Sentinel (Azure Monitor Logs Ingestion API) ────────────────────

type entraToken struct {
	value string
	until time.Time
}

var (
	tokensMu sync.Mutex
	tokens   = map[string]entraToken{}
)

// sentinelToken gets an Entra ID token for the Logs Ingestion API with the
// client credentials of the sink, cached until a minute before it expires.
func sentinelToken(ctx context.Context, client *http.Client, s Sink) (string, error) {
	authority := s.cfg("authority")
	if authority == "" {
		authority = "https://login.microsoftonline.com"
	}
	key := authority + "|" + s.cfg("tenant_id") + "|" + s.cfg("client_id")
	tokensMu.Lock()
	if t, ok := tokens[key]; ok && time.Now().Before(t.until) {
		tokensMu.Unlock()
		return t.value, nil
	}
	tokensMu.Unlock()
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {s.cfg("client_id")},
		"client_secret": {s.Secret}, "scope": {"https://monitor.azure.com/.default"}}
	target := strings.TrimRight(authority, "/") + "/" + url.PathEscape(s.cfg("tenant_id")) + "/oauth2/v2.0/token"
	if err := proxy.ValidateTargetURL(target, s.AllowPrivate); err != nil {
		return "", err
	}
	data, err := post(ctx, client, target, "application/x-www-form-urlencoded", []byte(form.Encode()), nil)
	if err != nil {
		return "", fmt.Errorf("entra id token: %w", err)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.AccessToken == "" {
		return "", errors.New("entra id token: no access_token in the answer")
	}
	tokensMu.Lock()
	tokens[key] = entraToken{out.AccessToken, time.Now().Add(time.Duration(out.ExpiresIn-60) * time.Second)}
	tokensMu.Unlock()
	return out.AccessToken, nil
}

// sentinel sends rows to a data collection rule's stream. The custom table
// has TimeGenerated (datetime), ClassUid (int), SeverityId (int), EventType
// (string) and Event (dynamic: the OCSF record); docs/siem.md has the DCR.
func sentinel(ctx context.Context, client *http.Client, s Sink, recs []Record) error {
	token, err := sentinelToken(ctx, client, s)
	if err != nil {
		return err
	}
	rows := make([]map[string]any, len(recs))
	for i, r := range recs {
		md := r["metadata"].(map[string]any)
		rows[i] = map[string]any{"TimeGenerated": md["original_time"], "ClassUid": r["class_uid"],
			"SeverityId": r["severity_id"], "EventType": md["event_code"], "Event": r}
	}
	body, _ := json.Marshal(rows)
	target := strings.TrimRight(s.cfg("endpoint"), "/") + "/dataCollectionRules/" + url.PathEscape(s.cfg("dcr_id")) +
		"/streams/" + url.PathEscape(s.cfg("stream")) + "?api-version=2023-01-01"
	_, err = post(ctx, client, target, "application/json", body, map[string]string{"Authorization": "Bearer " + token})
	return err
}

// ── syslog over TLS ──────────────────────────────────────────────────────────

// syslogTLS sends RFC 5424 messages with octet-counting framing (RFC 6587)
// over TLS (RFC 5425), one connection a batch. The message is CEF (ArcSight
// Common Event Format) or the OCSF record as JSON.
func syslogTLS(ctx context.Context, s Sink, evs []events.Event, recs []Record) error {
	dialer := proxy.SafeDialer(!s.AllowPrivate, Timeout)
	host, _, _ := net.SplitHostPort(s.cfg("address"))
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	if pem := s.cfg("ca_pem"); pem != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(pem)) {
			return errors.New("syslog config.ca_pem holds no certificate")
		}
		cfg.RootCAs = pool
	}
	d := tls.Dialer{NetDialer: dialer, Config: cfg}
	conn, err := d.DialContext(ctx, "tcp", s.cfg("address"))
	if err != nil {
		return fmt.Errorf("syslog %s: %w", s.cfg("address"), err)
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(Timeout))
	}
	var b bytes.Buffer
	for i, r := range recs {
		msg := FormatSyslog(evs[i], r, s.cfg("format"))
		b.WriteString(strconv.Itoa(len(msg)))
		b.WriteByte(' ')
		b.WriteString(msg)
	}
	if _, err := conn.Write(b.Bytes()); err != nil {
		return fmt.Errorf("syslog %s: %w", s.cfg("address"), err)
	}
	return nil
}

// syslogSeverity maps the event severity to a syslog severity.
func syslogSeverity(s string) int {
	switch s {
	case events.Critical:
		return 2
	case events.Warning:
		return 4
	}
	return 6
}

// FormatSyslog renders one RFC 5424 message (facility local0).
func FormatSyslog(ev events.Event, r Record, format string) string {
	pri := 16*8 + syslogSeverity(ev.Severity)
	var msg string
	if format == "json" {
		b, _ := json.Marshal(r)
		msg = string(b)
	} else {
		msg = CEF(ev, r)
	}
	return fmt.Sprintf("<%d>1 %s guard-spec guard-spec - %s - %s", pri,
		ev.OccurredAt.UTC().Format("2006-01-02T15:04:05.000Z"), sdName(ev.Type), msg)
}

func sdName(t string) string {
	if len(t) > 32 {
		return t[:32]
	}
	return t
}

// CEF renders the event in ArcSight Common Event Format.
func CEF(ev events.Event, r Record) string {
	head := func(s string) string { return strings.NewReplacer(`\`, `\\`, `|`, `\|`).Replace(s) }
	ext := func(s string) string {
		return strings.NewReplacer(`\`, `\\`, `=`, `\=`, "\n", `\n`, "\r", `\r`).Replace(s)
	}
	sev := map[string]int{events.Critical: 10, events.Warning: 6}[ev.Severity]
	if sev == 0 {
		sev = 3
	}
	name := ev.Type
	if fi, ok := r["finding_info"].(map[string]any); ok {
		if t, _ := fi["title"].(string); t != "" {
			name = t
		}
	}
	parts := []string{"rt=" + strconv.FormatInt(ev.OccurredAt.UnixMilli(), 10), "externalId=" + ev.ID.String(),
		"cs1Label=org_id", "cs1=" + ev.OrgID.String(), "cat=" + ext(ev.Type)}
	keys := []struct{ attr, cef string }{{"request_id", "cs2"}, {"layer", "cs3"}, {"decision", "act"},
		{"api_key_id", "cs4"}, {"model", "cs5"}, {"ip", "src"}, {"actor_id", "suid"}, {"user_id", "duid"}}
	labels := map[string]string{"cs2": "request_id", "cs3": "layer", "cs4": "api_key_id", "cs5": "model"}
	for _, k := range keys {
		if v := str(ev.Attrs, k.attr); v != "" {
			if l, ok := labels[k.cef]; ok {
				parts = append(parts, k.cef+"Label="+l)
			}
			parts = append(parts, k.cef+"="+ext(v))
		}
	}
	if score, ok := ev.Attrs["score"].(float64); ok {
		parts = append(parts, "cfp1Label=score", "cfp1="+strconv.FormatFloat(score, 'f', 3, 64))
	}
	return fmt.Sprintf("CEF:0|Guard Spec|Guard Spec|%s|%s|%s|%d|%s", head(version.String()), head(ev.Type), head(name), sev,
		strings.Join(parts, " "))
}
