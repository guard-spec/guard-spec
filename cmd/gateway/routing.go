package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"slices"
	"strconv"
	"sync"
	"time"

	appconfig "github.com/giaplee/guard-spec/internal/config"
	"github.com/giaplee/guard-spec/internal/metrics"
	"github.com/giaplee/guard-spec/internal/policy"
	"github.com/giaplee/guard-spec/internal/proxy"
	"github.com/giaplee/guard-spec/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Routing: which upstream an allowed request goes to (migration 011). In order:
//  1. the target of the route rule that decided the request;
//  2. the default upstream of the API key's project;
//  3. the default upstream of the organization;
//  4. UPSTREAM_LLM_URL;
//  5. the stub answer.
//
// A target that is missing or disabled, whose key variable is unset or not
// allowed for the org (UPSTREAM_KEY_ORGS), or whose address is refused, fails
// the request closed (502): the rule or default asked for that upstream, and
// sending the request elsewhere would ignore it.
//
// The upstreams a request may need are read in the same transaction as its
// policies (dbPolicyRouteLoader), so routing adds no transaction of its own.

// Values of the route source, also a metric label.
const (
	sourceRule    = "rule"
	sourceProject = "project"
	sourceOrg     = "org"
	sourceEnv     = "env"
	sourceStub    = "stub"
)

// upstreamRow is an org's named upstream, as stored. It holds no secret.
type upstreamRow struct {
	ID        uuid.UUID
	Name      string
	BaseURL   string
	Model     string
	KeyEnv    string // name of the variable holding the key; "" for none
	TimeoutMs int
	Enabled   bool
	UpdatedAt time.Time
	// Model provider fields (migration 014).
	Provider     string
	Models       []string // allowed models; empty: any
	Headers      map[string]string
	APIVersion   string
	MaxTokensCap *int
	Retries      int
}

// errNoSuchUpstream means a route rule names an upstream the org does not have.
var errNoSuchUpstream = errors.New("no such upstream")

// upstreamLoader returns the upstream a request goes to: the one named target
// when target is set (errNoSuchUpstream if there is none), else the project's
// or the org's default with its source. It returns nil when neither is set.
type upstreamLoader func(ctx context.Context, orgID, projectID uuid.UUID, target string) (*upstreamRow, string, error)

// routeSnapshot holds the upstreams one request may need, read with its
// policies: those its route rules name, and the default that applies.
type routeSnapshot struct {
	named     map[string]*upstreamRow
	def       *upstreamRow
	defSource string
}

func (s *routeSnapshot) lookup(target string) (*upstreamRow, string, error) {
	if target != "" {
		u, ok := s.named[target]
		if !ok {
			return nil, "", errNoSuchUpstream
		}
		return u, sourceRule, nil
	}
	return s.def, s.defSource, nil
}

// policyRouteLoader returns a request's policies and its route snapshot.
type policyRouteLoader func(ctx context.Context, orgID, projectID uuid.UUID) ([]policy.Policy, *routeSnapshot, error)

const upstreamColumns = `u.id, u.name, u.base_url, u.model, COALESCE(u.api_key_env, ''), u.timeout_ms, u.enabled, u.updated_at,
	u.provider, u.models, u.headers, u.api_version, u.max_tokens_cap, u.retries`

func scanUpstream(row pgx.Row, extra ...any) (*upstreamRow, error) {
	u := &upstreamRow{}
	dest := append(extra, &u.ID, &u.Name, &u.BaseURL, &u.Model, &u.KeyEnv, &u.TimeoutMs, &u.Enabled, &u.UpdatedAt,
		&u.Provider, &u.Models, &u.Headers, &u.APIVersion, &u.MaxTokensCap, &u.Retries)
	if err := row.Scan(dest...); err != nil {
		return nil, err
	}
	return u, nil
}

// queryNamed reads the org's upstreams with the given names.
func queryNamed(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, names []string) (map[string]*upstreamRow, error) {
	out := map[string]*upstreamRow{}
	if len(names) == 0 {
		return out, nil
	}
	rows, err := tx.Query(ctx, `SELECT `+upstreamColumns+` FROM upstreams u WHERE u.org_id = $1 AND u.name = ANY($2)`,
		orgID, names)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		u, err := scanUpstream(rows)
		if err != nil {
			return nil, err
		}
		out[u.Name] = u
	}
	return out, rows.Err()
}

// queryDefault reads the project's default upstream, else the org's.
func queryDefault(ctx context.Context, tx pgx.Tx, orgID, projectID uuid.UUID) (*upstreamRow, string, error) {
	source := ""
	up, err := scanUpstream(tx.QueryRow(ctx,
		`SELECT src, `+upstreamColumns+` FROM (
		   SELECT 1 AS rank, 'project' AS src, p.default_upstream_id AS uid FROM projects p
		    WHERE p.id = $2 AND p.org_id = $1 AND p.default_upstream_id IS NOT NULL
		   UNION ALL
		   SELECT 2, 'org', o.default_upstream_id FROM organizations o
		    WHERE o.id = $1 AND o.default_upstream_id IS NOT NULL
		 ) d JOIN upstreams u ON u.id = d.uid AND u.org_id = $1
		 ORDER BY d.rank LIMIT 1`, orgID, nullUUID(projectID)), &source)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	return up, source, nil
}

// dbUpstreamLoader reads upstreams inside the org's RLS scope, in a
// transaction of its own.
func dbUpstreamLoader(db *pgxpool.Pool) upstreamLoader {
	return func(ctx context.Context, orgID, projectID uuid.UUID, target string) (*upstreamRow, string, error) {
		var up *upstreamRow
		source := ""
		err := tenant.WithOrg(ctx, db, orgID, func(tx pgx.Tx) error {
			if target != "" {
				named, err := queryNamed(ctx, tx, orgID, []string{target})
				if err != nil {
					return err
				}
				var ok bool
				if up, ok = named[target]; !ok {
					return errNoSuchUpstream
				}
				source = sourceRule
				return nil
			}
			var err error
			up, source, err = queryDefault(ctx, tx, orgID, projectID)
			return err
		})
		if err != nil {
			return nil, "", err
		}
		return up, source, nil
	}
}

// dbPolicyRouteLoader reads a request's policies (as dbPolicyLoader) and the
// upstreams it may need, in one transaction in the org's RLS scope.
func dbPolicyRouteLoader(db *pgxpool.Pool) policyRouteLoader {
	return func(ctx context.Context, orgID, projectID uuid.UUID) ([]policy.Policy, *routeSnapshot, error) {
		var policies []policy.Policy
		snap := &routeSnapshot{}
		err := tenant.WithOrg(ctx, db, orgID, func(tx pgx.Tx) error {
			var err error
			if policies, err = queryPolicies(ctx, tx, orgID, projectID); err != nil {
				return err
			}
			var targets []string
			seen := map[string]bool{}
			for _, p := range policies {
				for _, r := range p.Rules {
					if r.Action == policy.ActionRoute && r.RouteTarget != "" && !seen[r.RouteTarget] {
						seen[r.RouteTarget] = true
						targets = append(targets, r.RouteTarget)
					}
				}
			}
			if snap.named, err = queryNamed(ctx, tx, orgID, targets); err != nil {
				return err
			}
			snap.def, snap.defSource, err = queryDefault(ctx, tx, orgID, projectID)
			return err
		})
		if err != nil {
			return nil, nil, err
		}
		return policies, snap, nil
	}
}

// queryPolicies reads enabled policies in evaluation order: project policies
// before org-wide ones, then oldest first; updated_at is not used so that
// editing a policy does not reorder it.
func queryPolicies(ctx context.Context, tx pgx.Tx, orgID, projectID uuid.UUID) ([]policy.Policy, error) {
	rows, err := tx.Query(ctx,
		`SELECT id, version, rules FROM policies
		 WHERE org_id = $1 AND enabled AND (project_id IS NULL OR project_id = $2)
		 ORDER BY project_id IS NULL, created_at, id`,
		orgID, nullUUID(projectID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var policies []policy.Policy
	for rows.Next() {
		p := policy.Policy{OrgID: orgID, ProjectID: projectID}
		var rules []byte
		if err := rows.Scan(&p.ID, &p.Version, &rules); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(rules, &p.Rules); err != nil {
			return nil, fmt.Errorf("policy %s: %w", p.ID, err)
		}
		policies = append(policies, p)
	}
	return policies, rows.Err()
}

// poolConfig is how named upstreams are reached.
type poolConfig struct {
	propagate bool
	// allowPrivate is UPSTREAM_ALLOW_PRIVATE: without it, an org's upstream
	// may not resolve to a loopback, private, unique local or CGNAT address.
	allowPrivate bool
	keyOrgs      appconfig.KeyOrgs // UPSTREAM_KEY_ORGS
	getenv       func(string) string
}

// upstreamPool keeps one proxy per named upstream, so that connections are
// reused. An entry is rebuilt when the row changes (updated_at). The key is
// read from the environment when the proxy is built and is never logged.
type upstreamPool struct {
	cfg poolConfig

	mu      sync.Mutex
	proxies map[uuid.UUID]pooledProxy
}

type pooledProxy struct {
	updated time.Time
	proxy   *proxy.Proxy
}

// maxPooledProxies bounds the pool; rows that were deleted leave entries behind.
const maxPooledProxies = 1024

func newUpstreamPool(cfg poolConfig) *upstreamPool {
	if cfg.getenv == nil {
		cfg.getenv = os.Getenv
	}
	return &upstreamPool{cfg: cfg, proxies: map[uuid.UUID]pooledProxy{}}
}

// errKeyMissing means an upstream names a key variable that is not set.
var errKeyMissing = errors.New("api_key_env is not set in the gateway's environment")

// get returns the proxy of org's upstream u. The key allowlist is checked on
// every call: a row saved before the operator narrowed UPSTREAM_KEY_ORGS, or
// written to the database directly, must not get the key.
func (p *upstreamPool) get(org uuid.UUID, u *upstreamRow) (*proxy.Proxy, error) {
	if u.KeyEnv != "" {
		if !appconfig.UpstreamKeyVarRe.MatchString(u.KeyEnv) {
			return nil, fmt.Errorf("api_key_env %q is not an UPSTREAM_KEY_ variable", u.KeyEnv)
		}
		if !p.cfg.keyOrgs.Allows(u.KeyEnv, org) {
			return nil, fmt.Errorf("api_key_env %s is not allowed for this organization by UPSTREAM_KEY_ORGS", u.KeyEnv)
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if cached, ok := p.proxies[u.ID]; ok && cached.updated.Equal(u.UpdatedAt) {
		return cached.proxy, nil
	}
	key := ""
	if u.KeyEnv != "" {
		if key = p.cfg.getenv(u.KeyEnv); key == "" {
			return nil, fmt.Errorf("%s: %w", u.KeyEnv, errKeyMissing)
		}
	}
	if err := proxy.ValidateBaseURL(u.BaseURL); err != nil {
		return nil, err
	}
	keyHeader := ""
	if u.Provider == "azure_openai" {
		keyHeader = "api-key" // Azure OpenAI keys are not bearer tokens
	}
	px, err := proxy.New(proxy.Config{
		BaseURL:     u.BaseURL,
		Key:         key,
		KeyHeader:   keyHeader,
		APIVersion:  u.APIVersion,
		Headers:     u.Headers,
		Retries:     u.Retries,
		Timeout:     time.Duration(u.TimeoutMs) * time.Millisecond,
		Propagate:   p.cfg.propagate,
		DenyPrivate: !p.cfg.allowPrivate,
	})
	if err != nil {
		return nil, err
	}
	if len(p.proxies) >= maxPooledProxies {
		clear(p.proxies)
	}
	p.proxies[u.ID] = pooledProxy{updated: u.UpdatedAt, proxy: px}
	return px, nil
}

// route is where an allowed request goes. A nil proxy means the stub answer.
type route struct {
	proxy  *proxy.Proxy
	name   string // the named upstream; "" for env and stub
	model  string // the upstream's default model
	source string
	// models are the upstream's allowed models; empty allows any.
	models       []string
	maxTokensCap *int
}

// errModelNotAllowed refuses a request for a model the upstream does not allow.
var errModelNotAllowed = errors.New("model not allowed")

// applyModel sets the model a request is sent with. Without an allowlist the
// upstream's default model, when set, replaces the requested one (as before
// migration 014). With one, the requested model must be listed; a request
// without a model gets the default.
func (r route) applyModel(requested string) (string, error) {
	if len(r.models) == 0 {
		if r.model != "" {
			return r.model, nil
		}
		return requested, nil
	}
	if requested == "" {
		if r.model == "" {
			return "", errModelNotAllowed
		}
		return r.model, nil
	}
	if !slices.Contains(r.models, requested) {
		return "", errModelNotAllowed
	}
	return requested, nil
}

// errBadTokenLimit refuses a max_tokens that is not a finite, non-negative number.
var errBadTokenLimit = errors.New("max_tokens and max_completion_tokens must be non-negative numbers")

// capTokens lowers max_tokens and max_completion_tokens above the upstream's
// cap. Every number form counts (5000.0, 1e6): the value is read as a float
// and floored before the comparison. It reports whether it changed the body,
// and refuses non-finite or negative values when a cap is set.
func (r route) capTokens(body map[string]any) (bool, error) {
	if r.maxTokensCap == nil {
		return false, nil
	}
	changed := false
	for _, k := range []string{"max_tokens", "max_completion_tokens"} {
		v, ok := body[k]
		if !ok || v == nil {
			continue
		}
		var f float64
		switch x := v.(type) {
		case json.Number:
			var err error
			if f, err = x.Float64(); err != nil {
				return false, errBadTokenLimit // out of range: ±Inf
			}
		case float64:
			f = x
		default:
			return false, errBadTokenLimit
		}
		if math.IsNaN(f) || math.IsInf(f, 0) || f < 0 {
			return false, errBadTokenLimit
		}
		if math.Floor(f) > float64(*r.maxTokensCap) {
			body[k] = json.Number(strconv.Itoa(*r.maxTokensCap))
			changed = true
		}
	}
	return changed, nil
}

// errRouteUnavailable fails a request closed with 502.
var errRouteUnavailable = errors.New("route target unavailable")

// resolveRoute picks the upstream for an allowed request, from snap when the
// policies came with one, else through gw.upstreams. An error wrapping
// errRouteUnavailable comes with the target's name in route.name; any other
// error means the upstreams could not be read.
func (gw gateway) resolveRoute(entry requestEntry, decision policy.Decision, snap *routeSnapshot) (route, error) {
	target := ""
	if decision.Action == policy.ActionRoute {
		target = decision.RouteTarget
	}
	fail := func(r route, reason error) (route, error) {
		metrics.RouteSelections.WithLabelValues(r.source, "failed").Inc()
		slog.Warn("route target unavailable", "org", entry.OrgID, "rule", decision.RuleID,
			"upstream", r.name, "source", r.source, "reason", reason)
		return r, fmt.Errorf("%w: %s: %v", errRouteUnavailable, r.name, reason)
	}
	if decision.Action == policy.ActionRoute && target == "" {
		// Refused when saved; a stored rule without a target must not fall
		// through to the defaults.
		return fail(route{source: sourceRule}, errors.New("route rule has no route_target"))
	}
	var (
		up     *upstreamRow
		source string
		err    error
	)
	switch {
	case snap != nil:
		up, source, err = snap.lookup(target)
	case gw.upstreams != nil && entry.OrgID != uuid.Nil:
		ctx, cancel := context.WithTimeout(gw.base, policyTimeout)
		up, source, err = gw.upstreams(ctx, entry.OrgID, entry.ProjectID, target)
		cancel()
	case target != "":
		err = errNoSuchUpstream
	}
	if errors.Is(err, errNoSuchUpstream) {
		return fail(route{name: target, source: sourceRule}, err)
	}
	if err != nil {
		return route{}, err
	}
	if up != nil {
		r := route{name: up.Name, model: up.Model, source: source, models: up.Models, maxTokensCap: up.MaxTokensCap}
		if !up.Enabled {
			return fail(r, errors.New("upstream is disabled"))
		}
		if gw.pool == nil {
			return fail(r, errors.New("no upstream pool"))
		}
		if r.proxy, err = gw.pool.get(entry.OrgID, up); err != nil {
			return fail(r, err)
		}
		metrics.RouteSelections.WithLabelValues(source, "ok").Inc()
		return r, nil
	}
	if gw.upstream != nil {
		metrics.RouteSelections.WithLabelValues(sourceEnv, "ok").Inc()
		return route{proxy: gw.upstream, source: sourceEnv}, nil
	}
	metrics.RouteSelections.WithLabelValues(sourceStub, "ok").Inc()
	return route{source: sourceStub}, nil
}
