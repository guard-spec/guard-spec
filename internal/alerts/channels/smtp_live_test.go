// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package channels

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"os"
	"testing"
	"time"
)

// TestEmailLiveSMTP sends one English and one Vietnamese alert through a real
// SMTP server. It runs only when SMTP_LIVE_URL, SMTP_LIVE_FROM and
// SMTP_LIVE_TO are set; SMTP_LIVE_CA names a PEM file to trust (a test
// server's self-signed certificate).
func TestEmailLiveSMTP(t *testing.T) {
	u, from, to := os.Getenv("SMTP_LIVE_URL"), os.Getenv("SMTP_LIVE_FROM"), os.Getenv("SMTP_LIVE_TO")
	if u == "" || from == "" || to == "" {
		t.Skip("SMTP_LIVE_URL, SMTP_LIVE_FROM and SMTP_LIVE_TO are not set")
	}
	e := &Email{SMTP: SMTPConfig{URL: u, From: from}}
	if ca := os.Getenv("SMTP_LIVE_CA"); ca != "" {
		pem, err := os.ReadFile(ca)
		if err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			t.Fatal("SMTP_LIVE_CA holds no certificate")
		}
		pu, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}
		e.TLS = &tls.Config{RootCAs: pool, ServerName: pu.Hostname(), MinVersion: tls.VersionTLS12}
	}
	for _, lang := range []string{"en", "vi"} {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		res, err := e.Send(ctx, &Message{Kind: "email", Target: to, Payload: testPayload(), IdempotencyKey: "gs1_live_" + lang, Lang: lang})
		cancel()
		if err != nil || res.Status != 250 {
			t.Fatalf("%s: %+v %v", lang, res, err)
		}
	}
}
