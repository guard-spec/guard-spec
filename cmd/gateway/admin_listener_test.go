// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guard-spec/guard-spec/internal/tlsreload"
)

// testPKI writes a CA and two leaves it signs (server for 127.0.0.1, client).
func testPKI(t *testing.T) (dir string, ca *x509.Certificate) {
	t.Helper()
	dir = t.TempDir()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ = x509.ParseCertificate(caDER)
	_ = os.WriteFile(filepath.Join(dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600)
	for i, name := range []string{"server", "client"} {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 2)), Subject: pkix.Name{CommonName: name},
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		kb, _ := x509.MarshalECPrivateKey(key)
		_ = os.WriteFile(filepath.Join(dir, name+".crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
		_ = os.WriteFile(filepath.Join(dir, name+".key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	}
	return dir, ca
}

func TestAdminListener(t *testing.T) {
	dir, _ := testPKI(t)
	f := func(n string) string { return filepath.Join(dir, n) }
	if _, err := loadAdminListenerConfig(func(k string) string {
		return map[string]string{"ADMIN_LISTEN_ADDR": ":8443"}[k]
	}); err == nil {
		t.Fatal("ADMIN_LISTEN_ADDR without the TLS files accepted")
	}
	if _, err := loadAdminListenerConfig(func(k string) string {
		return map[string]string{"ADMIN_TLS_CERT_FILE": "x"}[k]
	}); err == nil {
		t.Fatal("ADMIN_TLS_* without ADMIN_LISTEN_ADDR accepted")
	}
	cfg, err := loadAdminListenerConfig(func(k string) string {
		return map[string]string{"ADMIN_LISTEN_ADDR": "127.0.0.1:0", "ADMIN_TLS_CERT_FILE": f("server.crt"),
			"ADMIN_TLS_KEY_FILE": f("server.key"), "ADMIN_TLS_CLIENT_CA_FILE": f("ca.pem")}[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	gw := testGateway(t, nil)
	gw.adminSeparate = true
	app, addr, err := listenAdmin(cfg, gw)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Shutdown() }()

	client, err := tlsreload.New(tlsreload.Files{Cert: f("client.crt"), Key: f("client.key"), CA: f("ca.pem")})
	if err != nil {
		t.Fatal(err)
	}
	c := client.Client(5 * time.Second)
	for path, want := range map[string]int{"/readyz": 200, "/health": 200, "/admin/models": 404} {
		resp, err := c.Get("https://" + addr + path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		_ = resp.Body.Close()
		// /admin/models answers 404 "no model layers" in a gateway without them:
		// the route is there and the caller got through.
		if resp.StatusCode != want {
			t.Errorf("%s: %d, want %d", path, resp.StatusCode, want)
		}
	}
	// Without a client certificate the handshake fails.
	plain := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // the test checks the server refuses it
	if _, err := plain.Get("https://" + addr + "/readyz"); err == nil {
		t.Fatal("served without a client certificate")
	}
	// The public listener no longer has /admin.
	pub := newApp(gw, testLookup)
	resp, err := pub.Test(httptest.NewRequest("GET", "/admin/models", nil), -1)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 404 && resp.StatusCode != 401 {
		t.Fatalf("public /admin/models: %d", resp.StatusCode)
	}
}
