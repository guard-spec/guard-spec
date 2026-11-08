// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Package tlsreload keeps a certificate, its key and a CA bundle read from
// files, and reads them again when they change, so short-lived certificates
// (cert-manager, step-ca, a Vault agent) rotate without a restart. It builds
// the server side of mutual TLS (the gateway's admin listener) and the
// client side (the control plane calling it).
package tlsreload

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// Recheck is how often the files' modification times are looked at.
const Recheck = 10 * time.Second

// Files names a certificate, its key and the CA bundle that signs the other
// side's certificates.
type Files struct {
	Cert, Key, CA string
}

// Reloader serves the current certificate and CA pool.
type Reloader struct {
	files Files
	now   func() time.Time

	mu      sync.Mutex
	cert    *tls.Certificate
	pool    *x509.CertPool
	mods    [3]time.Time
	checked time.Time
}

// New loads files once (an error stops the caller from starting with a
// broken configuration) and returns the reloader.
func New(f Files) (*Reloader, error) {
	if f.Cert == "" || f.Key == "" || f.CA == "" {
		return nil, errors.New("tlsreload: a certificate, its key and a CA bundle are all needed")
	}
	r := &Reloader{files: f, now: time.Now}
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

func modTime(path string) (time.Time, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}, err
	}
	return fi.ModTime(), nil
}

// load reads the files when one of them changed since the last load.
func (r *Reloader) load() error {
	var mods [3]time.Time
	for i, p := range []string{r.files.Cert, r.files.Key, r.files.CA} {
		m, err := modTime(p)
		if err != nil {
			return fmt.Errorf("tlsreload: %w", err)
		}
		mods[i] = m
	}
	if r.cert != nil && mods == r.mods {
		return nil
	}
	cert, err := tls.LoadX509KeyPair(r.files.Cert, r.files.Key)
	if err != nil {
		return fmt.Errorf("tlsreload: %s: %w", r.files.Cert, err)
	}
	pem, err := os.ReadFile(r.files.CA)
	if err != nil {
		return fmt.Errorf("tlsreload: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return fmt.Errorf("tlsreload: %s holds no PEM certificate", r.files.CA)
	}
	r.cert, r.pool, r.mods = &cert, pool, mods
	return nil
}

// current returns the certificate and pool, reloading at most every Recheck.
// A failed reload keeps the previous ones (a rotation in progress).
func (r *Reloader) current() (*tls.Certificate, *x509.CertPool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if now := r.now(); now.Sub(r.checked) >= Recheck {
		r.checked = now
		_ = r.load()
	}
	return r.cert, r.pool
}

// ServerConfig requires a client certificate signed by the CA bundle.
func (r *Reloader) ServerConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			cert, pool := r.current()
			return &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{*cert},
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    pool,
			}, nil
		},
	}
}

// Client returns an HTTP client that presents the certificate and trusts
// only the CA bundle, both read again when they change.
func (r *Reloader) Client(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			cert, pool := r.current()
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			cfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: host,
				Certificates: []tls.Certificate{*cert}}
			d := tls.Dialer{NetDialer: dialer, Config: cfg}
			return d.DialContext(ctx, network, addr)
		},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        4,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: timeout,
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}
