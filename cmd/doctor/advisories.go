// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/guard-spec/guard-spec/internal/version"
)

// defaultAdvisoriesURL lists the published security advisories of the
// project (GitHub's repository advisories API; no token needed). The request
// carries no identifier of the installation. DOCTOR_ADVISORIES_URL points it
// at a mirror; -skip advisories turns it off (air-gapped installs).
const defaultAdvisoriesURL = "https://api.github.com/repos/guard-spec/guard-spec/security-advisories?state=published&per_page=100"

type advisory struct {
	GHSA     string `json:"ghsa_id"`
	CVE      string `json:"cve_id"`
	Summary  string `json:"summary"`
	Severity string `json:"severity"`
	URL      string `json:"html_url"`
	Vulns    []struct {
		Range   string `json:"vulnerable_version_range"`
		Patched string `json:"patched_versions"`
	} `json:"vulnerabilities"`
}

// checkAdvisories reports the published advisories that affect the running
// version. It only warns when the list cannot be read, so an install without
// internet access is not failed for it.
func (d *doctor) checkAdvisories(ctx context.Context) Result {
	return checkAdvisoriesFor(ctx, version.String(), d.get, d.opts)
}

func checkAdvisoriesFor(ctx context.Context, current string, get func(string) string, opts Options) Result {
	cur, ok := parseSemver(current)
	if !ok {
		return Result{Status: Skip, Detail: fmt.Sprintf("version %q is not a release; nothing to compare", current)}
	}
	src := strings.TrimSpace(get("DOCTOR_ADVISORIES_URL"))
	if src == "" {
		src = defaultAdvisoriesURL
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return Result{Status: Fail, Detail: "DOCTOR_ADVISORIES_URL: " + err.Error()}
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := (&http.Client{Timeout: opts.Timeout}).Do(req)
	if err != nil {
		return Result{Status: Warn, Detail: "cannot read the security advisories: " + unwrapURLError(err),
			Hint: "without internet access, follow https://github.com/guard-spec/guard-spec/security/advisories and run doctor with -skip advisories"}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return Result{Status: Warn, Detail: fmt.Sprintf("security advisories: HTTP %d", resp.StatusCode),
			Hint: "see https://github.com/guard-spec/guard-spec/security/advisories"}
	}
	var list []advisory
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&list); err != nil {
		return Result{Status: Warn, Detail: "security advisories: " + err.Error()}
	}
	var hits, hints []string
	for _, a := range list {
		for _, v := range a.Vulns {
			if !inRange(cur, v.Range) {
				continue
			}
			id := a.GHSA
			if a.CVE != "" {
				id = a.CVE + " (" + a.GHSA + ")"
			}
			hits = append(hits, fmt.Sprintf("%s %s: %s", id, strings.ToLower(a.Severity), a.Summary))
			fix := "upgrade"
			if v.Patched != "" {
				fix = "upgrade to " + v.Patched
			}
			hints = append(hints, fmt.Sprintf("%s: %s (%s)", id, fix, a.URL))
			break
		}
	}
	if len(hits) == 0 {
		return Result{Status: OK, Detail: fmt.Sprintf("no published advisory affects %s (%s)", current, plural(len(list), "advisory"))}
	}
	return Result{Status: Fail, Detail: fmt.Sprintf("%s affects %s: %s", plural(len(hits), "advisory"), current, strings.Join(hits, "; ")),
		Hint: strings.Join(hints, "\n")}
}

type semver [3]int

// parseSemver reads "1.2.3", "v1.2.3" and "1.2.3-rc.1" (the pre-release part
// is ignored, which errs toward reporting an advisory).
func parseSemver(s string) (semver, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexAny(s, "-+ "); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return semver{}, false
	}
	var v semver
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return semver{}, false
		}
		v[i] = n
	}
	return v, true
}

func (a semver) cmp(b semver) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// inRange reports whether v matches a GitHub vulnerable_version_range such as
// "< 0.3.1", ">= 0.2.0, < 0.3.1" or "= 0.3.0". An unreadable range matches,
// so that a malformed advisory is shown rather than hidden.
func inRange(v semver, r string) bool {
	r = strings.TrimSpace(r)
	if r == "" {
		return false
	}
	for _, c := range strings.Split(r, ",") {
		c = strings.TrimSpace(c)
		i := strings.IndexFunc(c, func(r rune) bool { return r >= '0' && r <= '9' || r == 'v' })
		if i < 0 {
			return true
		}
		op := strings.TrimSpace(c[:i])
		c = c[i:]
		w, ok := parseSemver(c)
		if !ok {
			return true
		}
		d := v.cmp(w)
		var match bool
		switch op {
		case "<":
			match = d < 0
		case "<=":
			match = d <= 0
		case ">":
			match = d > 0
		case ">=":
			match = d >= 0
		case "=", "==", "":
			match = d == 0
		default:
			return true
		}
		if !match {
			return false
		}
	}
	return true
}
