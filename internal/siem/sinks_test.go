// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package siem

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type capture struct {
	mu      sync.Mutex
	paths   []string
	headers []http.Header
	bodies  []string
}

func (c *capture) server(t *testing.T, answer func(path string) (int, string)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.paths = append(c.paths, r.URL.RequestURI())
		c.headers = append(c.headers, r.Header.Clone())
		c.bodies = append(c.bodies, string(b))
		c.mu.Unlock()
		code, body := answer(r.URL.Path)
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestSplunkHEC(t *testing.T) {
	var c capture
	srv := c.server(t, func(string) (int, string) { return 200, `{"text":"Success","code":0}` })
	s := Sink{Kind: KindSplunk, Config: map[string]any{"url": srv.URL, "index": "security"}, Secret: "hec-token", AllowPrivate: true}
	if err := Deliver(context.Background(), s, sampleEvents()[:3]); err != nil {
		t.Fatal(err)
	}
	if c.paths[0] != "/services/collector/event" || c.headers[0].Get("Authorization") != "Splunk hec-token" {
		t.Fatalf("%s %v", c.paths[0], c.headers[0])
	}
	lines := strings.Split(strings.TrimSpace(c.bodies[0]), "\n")
	var ev map[string]any
	if len(lines) != 3 || json.Unmarshal([]byte(lines[0]), &ev) != nil || ev["index"] != "security" || ev["sourcetype"] != "ocsf:guard-spec" {
		t.Fatalf("body: %s", c.bodies[0])
	}
	if rec := ev["event"].(map[string]any); rec["class_uid"] != float64(2004) {
		t.Fatalf("event: %v", rec)
	}
	// A refusal is an error, with the answer, without the token.
	bad := c.server(t, func(string) (int, string) { return 403, `{"text":"Invalid token","code":4}` })
	s.Config["url"] = bad.URL
	err := Deliver(context.Background(), s, sampleEvents()[:1])
	if err == nil || !strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "hec-token") {
		t.Fatalf("refusal: %v", err)
	}
}

func TestElasticBulk(t *testing.T) {
	var c capture
	answer := `{"errors":false,"items":[]}`
	srv := c.server(t, func(string) (int, string) { return 200, answer })
	s := Sink{Kind: KindElastic, Config: map[string]any{"url": srv.URL}, Secret: "aWQ6a2V5", AllowPrivate: true}
	evs := sampleEvents()[:2]
	if err := Deliver(context.Background(), s, evs); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(c.bodies[0]), "\n")
	if c.paths[0] != "/_bulk" || c.headers[0].Get("Authorization") != "ApiKey aWQ6a2V5" || len(lines) != 4 {
		t.Fatalf("%s %v %d", c.paths[0], c.headers[0], len(lines))
	}
	var action map[string]map[string]any
	_ = json.Unmarshal([]byte(lines[0]), &action)
	if action["create"]["_index"] != "guard-spec-ocsf" || action["create"]["_id"] != evs[0].ID.String() {
		t.Fatalf("action %v", action)
	}
	// Already indexed (a retry): fine. Another error: not.
	answer = `{"errors":true,"items":[{"create":{"status":409,"error":{"type":"version_conflict_engine_exception"}}}]}`
	if err := Deliver(context.Background(), s, evs[:1]); err != nil {
		t.Fatalf("409: %v", err)
	}
	answer = `{"errors":true,"items":[{"create":{"status":400,"error":{"type":"mapper_parsing_exception"}}}]}`
	if err := Deliver(context.Background(), s, evs[:1]); err == nil || !strings.Contains(err.Error(), "mapper_parsing_exception") {
		t.Fatalf("400: %v", err)
	}
}

func TestSentinel(t *testing.T) {
	var c capture
	srv := c.server(t, func(path string) (int, string) {
		if strings.HasSuffix(path, "/oauth2/v2.0/token") {
			return 200, `{"access_token":"entra-token","expires_in":3600}`
		}
		return 204, ""
	})
	s := Sink{Kind: KindSentinel, Secret: "client-secret", AllowPrivate: true, Config: map[string]any{
		"authority": srv.URL, "tenant_id": "t1", "client_id": "c1", "endpoint": srv.URL,
		"dcr_id": "dcr-abc", "stream": "Custom-GuardSpecOCSF_CL"}}
	for range 2 {
		if err := Deliver(context.Background(), s, sampleEvents()[:2]); err != nil {
			t.Fatal(err)
		}
	}
	// One token for both batches.
	if len(c.paths) != 3 || c.paths[0] != "/t1/oauth2/v2.0/token" || !strings.Contains(c.bodies[0], "client_secret=client-secret") {
		t.Fatalf("calls: %v", c.paths)
	}
	if c.paths[1] != "/dataCollectionRules/dcr-abc/streams/Custom-GuardSpecOCSF_CL?api-version=2023-01-01" ||
		c.headers[1].Get("Authorization") != "Bearer entra-token" {
		t.Fatalf("ingestion: %s %v", c.paths[1], c.headers[1])
	}
	var rows []map[string]any
	if json.Unmarshal([]byte(c.bodies[1]), &rows) != nil || len(rows) != 2 || rows[0]["ClassUid"] != float64(2004) || rows[0]["TimeGenerated"] == nil {
		t.Fatalf("rows: %s", c.bodies[1])
	}
}

func TestSyslogTLS(t *testing.T) {
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS() // only for its certificate
	cert := srv.TLS.Certificates[0]
	srv.Close()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	got := make(chan []string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		r := bufio.NewReader(conn)
		var msgs []string
		for {
			n, err := r.ReadString(' ')
			if err != nil {
				break
			}
			size, _ := strconv.Atoi(strings.TrimSpace(n))
			buf := make([]byte, size)
			if _, err := io.ReadFull(r, buf); err != nil {
				break
			}
			msgs = append(msgs, string(buf))
		}
		got <- msgs
	}()
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))
	s := Sink{Kind: KindSyslog, AllowPrivate: true, Config: map[string]any{"address": ln.Addr().String(), "ca_pem": caPEM}}
	// The test certificate is for example.com and 127.0.0.1.
	evs := sampleEvents()[:2]
	if err := Deliver(context.Background(), s, evs); err != nil {
		t.Fatal(err)
	}
	msgs := <-got
	if len(msgs) != 2 || !strings.HasPrefix(msgs[0], "<132>1 2026-11-08T09:30:00.000Z guard-spec guard-spec - detection.blocked - CEF:0|Guard Spec|Guard Spec|") {
		t.Fatalf("messages: %q", msgs)
	}
	if !strings.Contains(msgs[0], "|detection.blocked|Prompt injection blocked|6|") || !strings.Contains(msgs[0], "cfp1=0.970") {
		t.Fatalf("CEF: %s", msgs[0])
	}
	if FormatSyslog(evs[0], Map(evs[0]), "json")[0] != '<' || !strings.Contains(FormatSyslog(evs[0], Map(evs[0]), "json"), `"class_uid":2004`) {
		t.Fatal("json format")
	}
}

func TestValidateAndPrivate(t *testing.T) {
	for _, s := range []Sink{
		{Kind: "kafka"},
		{Kind: KindSplunk, Config: map[string]any{}},
		{Kind: KindSentinel, Config: map[string]any{"endpoint": "https://x.ingest.monitor.azure.com"}},
		{Kind: KindSyslog, Config: map[string]any{"address": "nohost"}},
		{Kind: KindSyslog, Config: map[string]any{"address": "siem:6514", "format": "leef"}},
		{Kind: KindHTTP, Config: map[string]any{"url": "http://siem.example/ingest"}}, // http without allow_private
	} {
		if err := s.Validate(); err == nil {
			t.Errorf("%s %v accepted", s.Kind, s.Config)
		}
	}
	// A private address is refused at dial time unless allowed.
	var c capture
	srv := c.server(t, func(string) (int, string) { return 200, "" })
	s := Sink{Kind: KindHTTP, Config: map[string]any{"url": strings.Replace(srv.URL, "http://", "https://", 1)}}
	if err := Deliver(context.Background(), s, sampleEvents()[:1]); err == nil {
		t.Fatal("a loopback address was reached without allow_private")
	}
}
