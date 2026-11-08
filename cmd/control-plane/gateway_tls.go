// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/guard-spec/guard-spec/internal/tlsreload"
)

// gatewayTLSClient is the client the control plane reads the gateway's
// /readyz with (GATEWAY_URL), over mutual TLS when GATEWAY_TLS_CERT_FILE,
// GATEWAY_TLS_KEY_FILE and GATEWAY_TLS_CA_FILE are set: the gateway's admin
// listener (ADMIN_LISTEN_ADDR) accepts only certificates of its CA. The files
// are read again when they change. nil: the default client.
func gatewayTLSClient(get func(string) string) (*http.Client, error) {
	f := tlsreload.Files{Cert: strings.TrimSpace(get("GATEWAY_TLS_CERT_FILE")),
		Key: strings.TrimSpace(get("GATEWAY_TLS_KEY_FILE")), CA: strings.TrimSpace(get("GATEWAY_TLS_CA_FILE"))}
	if f.Cert == "" && f.Key == "" && f.CA == "" {
		return nil, nil
	}
	if f.Cert == "" || f.Key == "" || f.CA == "" {
		return nil, errors.New("GATEWAY_TLS_CERT_FILE, GATEWAY_TLS_KEY_FILE and GATEWAY_TLS_CA_FILE go together")
	}
	if u := strings.TrimSpace(get("GATEWAY_URL")); !strings.HasPrefix(u, "https://") {
		return nil, errors.New("GATEWAY_TLS_* needs GATEWAY_URL=https://<gateway>:<ADMIN_LISTEN_ADDR port>")
	}
	r, err := tlsreload.New(f)
	if err != nil {
		return nil, err
	}
	return r.Client(5 * time.Second), nil
}
