package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/giaplee/guard-spec/internal/policy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// storedPolicy is one row of the policies table, as the pre-flight reads it.
type storedPolicy struct {
	ID      uuid.UUID
	OrgID   uuid.UUID
	Name    string
	Enabled bool
	Rules   json.RawMessage
}

// runPolicyCheck validates every stored policy of every org with the rules a new
// policy must meet, and lists each failure. It returns the process exit code:
// 0 when all pass, 1 when any fails, 2 when the policies could not be read.
//
// policies is under RLS, so this must connect as a role that sees every org,
// such as the table owner (ps in the compose stack); guardspec_app sees none.
func runPolicyCheck(ctx context.Context, databaseURL string, out io.Writer) int {
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		fmt.Fprintf(out, "connect: %v\n", err)
		return 2
	}
	defer db.Close()
	policies, err := readAllPolicies(ctx, db)
	if err != nil {
		fmt.Fprintf(out, "read policies: %v\n"+
			"Run this check as a role that bypasses row-level security, such as the table owner.\n", err)
		return 2
	}
	eng, err := policy.New()
	if err != nil {
		fmt.Fprintf(out, "policy engine: %v\n", err)
		return 2
	}
	if checkPolicies(eng, policies, out) > 0 {
		return 1
	}
	return 0
}

func readAllPolicies(ctx context.Context, db *pgxpool.Pool) ([]storedPolicy, error) {
	rows, err := db.Query(ctx,
		`SELECT id, org_id, name, enabled, rules FROM policies ORDER BY org_id, created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var policies []storedPolicy
	for rows.Next() {
		var p storedPolicy
		if err := rows.Scan(&p.ID, &p.OrgID, &p.Name, &p.Enabled, &p.Rules); err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	return policies, rows.Err()
}

// checkPolicies writes one line per problem and a summary, and returns how many
// policies failed. Disabled policies are checked too: enabling one must not
// start refusing requests.
func checkPolicies(eng *policy.Engine, policies []storedPolicy, out io.Writer) int {
	failed := 0
	for _, p := range policies {
		var errs []error
		var rules []policy.Rule
		if err := json.Unmarshal(p.Rules, &rules); err != nil {
			errs = append(errs, fmt.Errorf("rules are not a valid list: %w", err))
		} else {
			errs = eng.CheckRules(rules)
		}
		if len(errs) == 0 {
			continue
		}
		failed++
		state := "enabled"
		if !p.Enabled {
			state = "disabled"
		}
		for _, err := range errs {
			fmt.Fprintf(out, "FAIL org=%s policy=%s name=%q (%s): %v\n", p.OrgID, p.ID, p.Name, state, err)
		}
	}
	fmt.Fprintf(out, "%d of %d policies failed the check\n", failed, len(policies))
	return failed
}
