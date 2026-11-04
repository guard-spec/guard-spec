// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package channels

// Regression tests of the security review of PR #32.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// L1: the Agent Card names an RPC endpoint on another origin; the secret
// must not be sent there.
func TestA2AEndpointMustShareTheCardOrigin(t *testing.T) {
	var got atomic.Value
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":"x","result":{"task":{"id":"t"}}}`)
	}))
	defer other.Close()
	card := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"supportedInterfaces":[{"url":"`+other.URL+`/rpc","protocolBinding":"JSONRPC","protocolVersion":"1.0"}]}`)
	}))
	defer card.Close()
	a := &A2A{Guard: privateGuard()}
	m := &Message{Kind: KindA2A, Config: map[string]any{"agent_card_url": card.URL, "allow_private": true},
		Secret: "the-secret", Payload: testPayload(), IdempotencyKey: "k"}
	_, err := a.Send(context.Background(), m)
	var ce *Error
	if !errors.As(err, &ce) || !ce.Permanent {
		t.Fatalf("err %v, want a permanent refusal", err)
	}
	if v, _ := got.Load().(string); v != "" {
		t.Fatalf("secret sent to %s, another origin than the card %s", other.URL, card.URL)
	}
}

// L1: a card cannot have the key sent in a reserved or hop-by-hop header.
func TestA2ARefusesReservedAuthHeaders(t *testing.T) {
	for _, header := range []string{"Host", "Content-Length", "Transfer-Encoding", "Connection", "Proxy-Authorization",
		"Cookie", "X-Forwarded-For", "Bad Header"} {
		var hits atomic.Int32
		var srvURL string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, ".json") {
				_, _ = io.WriteString(w, `{"supportedInterfaces":[{"url":"`+srvURL+`/rpc","protocolBinding":"JSONRPC","protocolVersion":"1.0"}],
				"securitySchemes":{"k":{"apiKeySecurityScheme":{"location":"header","name":"`+header+`"}}}}`)
				return
			}
			hits.Add(1)
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":"x","result":{"task":{"id":"t"}}}`)
		}))
		srvURL = srv.URL
		a := &A2A{Guard: privateGuard()}
		_, err := a.Send(context.Background(), &Message{Config: map[string]any{"agent_card_url": srv.URL, "allow_private": true},
			Secret: "agent-secret", Payload: testPayload()})
		srv.Close()
		if err == nil || hits.Load() != 0 {
			t.Fatalf("%s: err %v, rpc hits %d", header, err, hits.Load())
		}
	}
}

// L2: a refused dial reads "address not allowed", without the address.
func TestDialRefusalHidesTheAddress(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")
	w := &Webhook{Guard: NewGuard(nil)}
	_, err := w.Send(context.Background(), &Message{Config: map[string]any{"url": "https://localhost:" +
		host[strings.LastIndex(host, ":")+1:] + "/h"}, Secret: "s3cret-value", Payload: testPayload()})
	var ce *Error
	if !errors.As(err, &ce) || ce.Msg != "address not allowed" || !ce.Permanent {
		t.Fatalf("err %#v", err)
	}
	if strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), "::1") {
		t.Fatalf("error names the address: %v", err)
	}
}

// M3: private addresses are per org: another org's channel asking for them
// gets the strict guard.
func TestPrivateAddressesArePerOrg(t *testing.T) {
	_, srv := newCapture(t, nil)
	w := &Webhook{Guard: privateGuard()}
	p := testPayload()
	p.OrgID = "another-org"
	_, err := w.Send(context.Background(), &Message{Config: map[string]any{"url": srv.URL, "allow_private": true},
		Secret: "s3cret-value", Payload: p})
	if err == nil {
		t.Fatal("an org not listed in ALERTS_PRIVATE_ORGS reached a loopback URL")
	}
}

// L5: the event id is signed: a receiver can trust it for deduplication.
func TestSignatureCoversTheEventID(t *testing.T) {
	body := []byte(`{"a":1}`)
	ts := time.Now().Unix()
	sig := Sign([]byte("secret"), ts, "gs1_one", body)
	tsh := strconv.FormatInt(ts, 10)
	if err := Verify([]byte("secret"), tsh, "gs1_one", sig, body, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := Verify([]byte("secret"), tsh, "gs1_two", sig, body, time.Now()); err == nil {
		t.Fatal("a changed event id verified")
	}
}
