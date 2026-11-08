//go:build integration

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/guard-spec/guard-spec/internal/auth"
)

// newChain makes an org with n activity rows written the way the control
// plane writes them (application role, the trigger chains them).
func newChain(t *testing.T, h *cpHarness, n int) uuid.UUID {
	t.Helper()
	org, _, _ := h.org(auth.RoleOwner)
	for i := 0; i < n; i++ {
		writeActivity(context.Background(), h.db, activityEntry{Org: &org, Action: "policy.updated", Target: "rule " + string(rune('a'+i)),
			Details: map[string]any{"name": "Chặn thẻ", "n": i}})
	}
	return org
}

func audit(t *testing.T, env map[string]string, args ...string) (int, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := runAudit(context.Background(), args, func(k string) string { return env[k] }, &out, &errOut)
	return code, out.String() + errOut.String()
}

func TestAuditChain(t *testing.T) {
	ctx := context.Background()
	h := newCPHarness(t)
	owner, url := ownerDB(t)
	seed := make([]byte, 32)
	_, _ = rand.Read(seed)
	env := map[string]string{"DATABASE_URL": url, "AUDIT_SIGNING_KEY": base64.StdEncoding.EncodeToString(seed)}

	// The application role only appends.
	org := newChain(t, h, 3)
	if _, err := h.db.Exec(ctx, `UPDATE activity_log SET action = 'x' WHERE org_id = $1`, org); err == nil {
		t.Fatal("the application role updated activity_log")
	}
	if _, err := h.db.Exec(ctx, `DELETE FROM activity_log WHERE org_id = $1`, org); err == nil {
		t.Fatal("the application role deleted from activity_log")
	}
	if code, out := audit(t, env, "verify", "-org", org.String()); code != 0 || !strings.Contains(out, "3 rows (seq 1-3)") {
		t.Fatalf("clean chain: %d %s", code, out)
	}

	tamper := []struct {
		name, sql, want string
	}{
		{"changed row", `UPDATE activity_log SET details = '{"name":"khác"}' WHERE org_id = $1 AND seq = 2`, "BROKEN at seq 2: the row does not match"},
		// Changed, then its hash recomputed: the next row no longer links.
		{"changed and rehashed row", `UPDATE activity_log SET target = 'x' WHERE org_id = $1 AND seq = 2;
			UPDATE activity_log SET hash = sha256(prev_hash || convert_to(activity_log_canonical(activity_log), 'UTF8')) WHERE org_id = $1 AND seq = 2`, "BROKEN at seq 3: prev_hash"},
		{"removed row", `DELETE FROM activity_log WHERE org_id = $1 AND seq = 2`, "BROKEN at seq 2: rows 2 to 2 are missing"},
	}
	for _, c := range tamper {
		t.Run(c.name, func(t *testing.T) {
			org := newChain(t, h, 4)
			for _, stmt := range strings.Split(c.sql, ";") {
				if _, err := owner.Exec(ctx, stmt, org); err != nil {
					t.Fatal(err)
				}
			}
			if code, out := audit(t, env, "verify", "-org", org.String()); code != 1 || !strings.Contains(out, c.want) {
				t.Fatalf("got %d %s; want %q", code, out, c.want)
			}
		})
	}

	t.Run("anchors catch a cut chain and a rewritten one", func(t *testing.T) {
		org := newChain(t, h, 3)
		if code, out := audit(t, env, "anchor"); code != 0 || !strings.Contains(out, "anchors written") {
			t.Fatalf("anchor: %d %s", code, out)
		}
		if code, out := audit(t, env, "verify", "-org", org.String()); code != 0 || !strings.Contains(out, "1 anchors") {
			t.Fatalf("verify with anchor: %d %s", code, out)
		}
		// Cut the last row: the chain itself still links.
		if _, err := owner.Exec(ctx, `DELETE FROM activity_log WHERE org_id = $1 AND seq = 3`, org); err != nil {
			t.Fatal(err)
		}
		if code, out := audit(t, env, "verify", "-org", org.String()); code != 1 || !strings.Contains(out, "the row is gone") {
			t.Fatalf("cut chain: %d %s", code, out)
		}
		// Another key does not verify the anchors.
		other := make([]byte, 32)
		_, _ = rand.Read(other)
		org2 := newChain(t, h, 2)
		_, _ = audit(t, env, "anchor")
		bad := map[string]string{"DATABASE_URL": url, "AUDIT_SIGNING_KEY": base64.StdEncoding.EncodeToString(other)}
		if code, out := audit(t, bad, "verify", "-org", org2.String()); code != 1 || !strings.Contains(out, "signature does not verify") {
			t.Fatalf("other key: %d %s", code, out)
		}
		// Without any key the anchors are reported unchecked.
		if code, out := audit(t, map[string]string{"DATABASE_URL": url}, "verify", "-org", org2.String()); code != 0 || !strings.Contains(out, "not checked") {
			t.Fatalf("no key: %d %s", code, out)
		}
		if code, out := audit(t, env, "export", "-org", org2.String()); code != 0 || strings.Count(out, `"kind":"activity"`) != 2 || !strings.Contains(out, `"kind":"anchor"`) {
			t.Fatalf("export: %d %s", code, out)
		}
	})

	t.Run("concurrent writers make one chain", func(t *testing.T) {
		org := newChain(t, h, 0)
		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				writeActivity(ctx, h.db, activityEntry{Org: &org, Action: "member.added", Target: uuid.NewString()})
			}()
		}
		wg.Wait()
		if code, out := audit(t, env, "verify", "-org", org.String()); code != 0 || !strings.Contains(out, "20 rows (seq 1-20)") {
			t.Fatalf("concurrent: %d %s", code, out)
		}
	})

	t.Run("retention keeps the rest of the chain verifiable", func(t *testing.T) {
		org := newChain(t, h, 5)
		var cutoff time.Time
		if err := owner.QueryRow(ctx, `SELECT at + interval '1 microsecond' FROM activity_log WHERE org_id = $1 AND seq = 2`, org).Scan(&cutoff); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `DELETE FROM activity_log WHERE org_id = $1 AND at < $2`, org, cutoff); err != nil {
			t.Fatal(err)
		}
		if code, out := audit(t, env, "verify", "-org", org.String()); code != 0 || !strings.Contains(out, "rows before 3 removed by retention") {
			t.Fatalf("after retention: %d %s", code, out)
		}
	})

	if code, out := audit(t, env, "public-key"); code != 0 || !strings.Contains(out, "key id") {
		t.Fatalf("public-key: %d %s", code, out)
	}
	if code, _ := audit(t, map[string]string{"DATABASE_URL": envOr("TEST_DATABASE_URL", "")}, "verify"); code != 2 {
		t.Fatalf("the application role may verify: %d", code)
	}
}
