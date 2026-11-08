// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestInRange(t *testing.T) {
	v := func(s string) semver {
		x, ok := parseSemver(s)
		if !ok {
			t.Fatalf("parse %q", s)
		}
		return x
	}
	for _, c := range []struct {
		ver, rng string
		want     bool
	}{
		{"0.3.0", "< 0.3.1", true},
		{"0.3.1", "< 0.3.1", false},
		{"0.3.1", "<= 0.3.1", true},
		{"0.2.5", ">= 0.2.0, < 0.3.1", true},
		{"0.1.9", ">= 0.2.0, < 0.3.1", false},
		{"0.3.0", "= 0.3.0", true},
		{"0.3.0", "0.3.0", true},
		{"1.0.0", "> 0.9.9", true},
		{"0.3.1", "", false},
		{"0.3.1", "garbage", true},
		{"0.3.1", "~> 0.3", true},
	} {
		if got := inRange(v(c.ver), c.rng); got != c.want {
			t.Errorf("%s in %q = %v, want %v", c.ver, c.rng, got, c.want)
		}
	}
	if _, ok := parseSemver("dev"); ok {
		t.Error("dev parsed as a version")
	}
	if x, ok := parseSemver("v0.4.0-rc.1"); !ok || x != (semver{0, 4, 0}) {
		t.Errorf("v0.4.0-rc.1: %v %v", x, ok)
	}
}

func TestCheckAdvisories(t *testing.T) {
	body := `[{"ghsa_id":"GHSA-aaaa-bbbb-cccc","cve_id":"CVE-2026-1","summary":"output guard bypass","severity":"high",
	  "html_url":"https://github.com/guard-spec/guard-spec/security/advisories/GHSA-aaaa-bbbb-cccc",
	  "vulnerabilities":[{"vulnerable_version_range":"< 0.3.1","patched_versions":"0.3.1"}]}]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/broken" {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	opts := Options{Timeout: 2 * time.Second}
	env := func(u string) func(string) string {
		return func(k string) string {
			if k == "DOCTOR_ADVISORIES_URL" {
				return u
			}
			return ""
		}
	}
	ctx := context.Background()

	r := checkAdvisoriesFor(ctx, "0.3.0", env(srv.URL), opts)
	if r.Status != Fail || !strings.Contains(r.Detail, "CVE-2026-1") || !strings.Contains(r.Hint, "upgrade to 0.3.1") {
		t.Errorf("affected: %+v", r)
	}
	if r := checkAdvisoriesFor(ctx, "0.3.1", env(srv.URL), opts); r.Status != OK {
		t.Errorf("patched: %+v", r)
	}
	if r := checkAdvisoriesFor(ctx, "dev", env(srv.URL), opts); r.Status != Skip {
		t.Errorf("dev: %+v", r)
	}
	if r := checkAdvisoriesFor(ctx, "0.3.0", env(srv.URL+"/broken"), opts); r.Status != Warn {
		t.Errorf("HTTP 502: %+v", r)
	}
	srv.Close()
	if r := checkAdvisoriesFor(ctx, "0.3.0", env(srv.URL), opts); r.Status != Warn {
		t.Errorf("unreachable: %+v", r)
	}
}
