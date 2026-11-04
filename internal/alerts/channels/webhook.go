// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package channels

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Webhook headers (docs/alerts.md).
const (
	HeaderEventID   = "X-GuardSpec-Event-Id"
	HeaderTimestamp = "X-GuardSpec-Timestamp"
	HeaderSignature = "X-GuardSpec-Signature"
)

// MaxSkew is how far a receiver lets the timestamp drift.
const MaxSkew = 5 * time.Minute

// Sign returns the v1 signature header value: v1=<hex HMAC-SHA256(secret,
// timestamp + "." + event_id + "." + body)>. The event id (the delivery's
// idempotency key) is signed so a receiver can trust it for deduplication.
func Sign(secret []byte, ts int64, eventID string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(strconv.FormatInt(ts, 10)))
	mac.Write([]byte("."))
	mac.Write([]byte(eventID))
	mac.Write([]byte("."))
	mac.Write(body)
	return "v1=" + hex.EncodeToString(mac.Sum(nil))
}

// Verify checks a delivery as a receiver should: the timestamp within
// MaxSkew of now and a v1 signature that matches, compared in constant time.
func Verify(secret []byte, tsHeader, eventID, sigHeader string, body []byte, now time.Time) error {
	ts, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return errors.New("bad timestamp")
	}
	if math.Abs(float64(now.Unix()-ts)) > MaxSkew.Seconds() {
		return errors.New("timestamp too old or in the future")
	}
	want := Sign(secret, ts, eventID, body)
	for _, part := range strings.Split(sigHeader, ",") {
		if hmac.Equal([]byte(strings.TrimSpace(part)), []byte(want)) {
			return nil
		}
	}
	return errors.New("signature mismatch")
}

// Webhook POSTs the payload v1, signed with Secret, to Config "url".
type Webhook struct {
	Guard Guard
	Now   func() time.Time
}

// Send delivers m.
func (w *Webhook) Send(ctx context.Context, m *Message) (Result, error) {
	target := configString(m.Config, "url")
	if target == "" {
		return Result{}, permanent(0, "webhook: no url")
	}
	if m.Secret == "" {
		return Result{}, permanent(0, "webhook: signing secret is not set")
	}
	client, check := w.Guard.pick(configBool(m.Config, "allow_private"), m.Payload.OrgID)
	if err := check(target); err != nil {
		return Result{}, permanent(0, "%s", Redact("webhook: "+err.Error(), m.Secret))
	}
	body, err := json.Marshal(m.Payload)
	if err != nil {
		return Result{}, err
	}
	now := time.Now
	if w.Now != nil {
		now = w.Now
	}
	ts := now().Unix()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return Result{}, permanent(0, "webhook: invalid url")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "guard-spec-alerts/1")
	req.Header.Set(HeaderEventID, m.Payload.EventID)
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(HeaderSignature, Sign([]byte(m.Secret), ts, m.Payload.EventID, body))
	r, err := do(client, req, m.Secret)
	if err != nil {
		return Result{}, err
	}
	return Result{Status: r.status}, nil
}
