// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package tlsreload

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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(t *testing.T, name string) ca {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return ca{c, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// leaf writes a certificate for name signed by c into dir and returns the
// cert and key paths.
func (c ca) leaf(t *testing.T, dir, file, name string, serial int64) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
		DNSNames: []string{name}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	cp, kp := filepath.Join(dir, file+".crt"), filepath.Join(dir, file+".key")
	_ = os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return cp, kp
}

func TestMutualTLS(t *testing.T) {
	dir := t.TempDir()
	auth := newCA(t, "guard-spec internal CA")
	caFile := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(caFile, auth.pem, 0o600)
	sc, sk := auth.leaf(t, dir, "server", "127.0.0.1", 2)
	cc, ck := auth.leaf(t, dir, "client", "control-plane", 3)

	server, err := New(Files{Cert: sc, Key: sk, CA: caFile})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", server.ServerConfig())
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello " + r.TLS.PeerCertificates[0].Subject.CommonName))
	}), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()
	url := "https://" + ln.Addr().String() + "/readyz"

	client, err := New(Files{Cert: cc, Key: ck, CA: caFile})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Client(5 * time.Second).Get(url)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, _ := resp.Body.Read(buf)
	_ = resp.Body.Close()
	if string(buf[:n]) != "hello control-plane" {
		t.Fatalf("got %q", buf[:n])
	}

	// No client certificate: refused.
	plain := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool(), InsecureSkipVerify: true}}} //nolint:gosec // the test checks the server refuses it
	if _, err := plain.Get(url); err == nil {
		t.Fatal("a client without a certificate was served")
	}
	// A certificate of another CA: refused.
	other := newCA(t, "someone else")
	oc, ok := other.leaf(t, dir, "other", "intruder", 4)
	otherCA := filepath.Join(dir, "other-ca.pem")
	_ = os.WriteFile(otherCA, append(append([]byte{}, auth.pem...), other.pem...), 0o600)
	intruder, err := New(Files{Cert: oc, Key: ok, CA: otherCA})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := intruder.Client(5 * time.Second).Get(url); err == nil {
		t.Fatal("a certificate of another CA was accepted")
	}

	// The client certificate rotates: picked up after Recheck.
	now := time.Now()
	client.now = func() time.Time { return now }
	nc, nk := auth.leaf(t, dir, "client", "control-plane-2", 5)
	_ = os.Chtimes(nc, now.Add(time.Second), now.Add(time.Second))
	_ = os.Chtimes(nk, now.Add(time.Second), now.Add(time.Second))
	_, _ = nc, nk
	now = now.Add(Recheck)
	c2 := client.Client(5 * time.Second)
	resp, err = c2.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	n, _ = resp.Body.Read(buf)
	_ = resp.Body.Close()
	if !strings.HasSuffix(string(buf[:n]), "control-plane-2") {
		t.Fatalf("after rotation: %q", buf[:n])
	}

	if _, err := New(Files{Cert: sc}); err == nil {
		t.Error("missing files accepted")
	}
}
