package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"sync"
	"time"

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
// A target that is missing or disabled, or whose key variable is unset, fails
// the request closed (502): the rule or default asked for that upstream, and
// sending the request elsewhere would ignore it.

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
}

// errNoSuchUpstream means a route rule names an upstream the org does not have.
var errNoSuchUpstream = errors.New("no such upstream")

// upstreamLoader returns the upstream a request goes to: the one named target
// when target is set (errNoSuchUpstream if there is none), else the project's
// or the org's default with its source. It returns nil when neither is set.
type upstreamLoader func(ctx context.Context, orgID, projectID uuid.UUID, target string) (*upstreamRow, string, error)

const upstreamColumns = `u.id, u.name, u.base_url, u.model, COALESCE(u.api_key_env, ''), u.timeout_ms, u.enabled, u.updated_at`

func scanUpstream(row pgx.Row, extra ...any) (*upstreamRow, error) {
	u := &upstreamRow{}
	dest := append(extra, &u.ID, &u.Name, &u.BaseURL, &u.Model, &u.KeyEnv, &u.TimeoutMs, &u.Enabled, &u.UpdatedAt)
	if err := row.Scan(dest...); err != nil {
		return nil, err
	}
	return u, nil
}

// dbUpstreamLoader reads upstreams inside the org's RLS scope.
func dbUpstreamLoader(db *pgxpool.Pool) upstreamLoader {
	return func(ctx context.Context, orgID, projectID uuid.UUID, target string) (*upstreamRow, string, error) {
		var up *upstreamRow
		source := ""
		err := tenant.WithOrg(ctx, db, orgID, func(tx pgx.Tx) error {
			var err error
			if target != "" {
				up, err = scanUpstream(tx.QueryRow(ctx,
					`SELECT `+upstreamColumns+` FROM upstreams u WHERE u.org_id = $1 AND u.name = $2`, orgID, target))
				if errors.Is(err, pgx.ErrNoRows) {
					return errNoSuchUpstream
				}
				source = sourceRule
				return err
			}
			// The project's default comes first; the org's is the fallback.
			up, err = scanUpstream(tx.QueryRow(ctx,
				`SELECT src, `+upstreamColumns+` FROM (
				   SELECT 1 AS rank, 'project' AS src, p.default_upstream_id AS uid FROM projects p
				    WHERE p.id = $2 AND p.org_id = $1 AND p.default_upstream_id IS NOT NULL
				   UNION ALL
				   SELECT 2, 'org', o.default_upstream_id FROM organizations o
				    WHERE o.id = $1 AND o.default_upstream_id IS NOT NULL
				 ) d JOIN upstreams u ON u.id = d.uid AND u.org_id = $1
				 ORDER BY d.rank LIMIT 1`, orgID, nullUUID(projectID)), &source)
			if errors.Is(err, pgx.ErrNoRows) {
				up, err = nil, nil
			}
			return err
		})
		if err != nil {
			return nil, "", err
		}
		return up, source, nil
	}
}

// upstreamPool keeps one proxy per named upstream, so that connections are
// reused. An entry is rebuilt when the row changes (updated_at). The key is
// read from the environment when the proxy is built and is never logged.
type upstreamPool struct {
	propagate bool
	getenv    func(string) string

	mu      sync.Mutex
	proxies map[uuid.UUID]pooledProxy
}

type pooledProxy struct {
	updated time.Time
	proxy   *proxy.Proxy
}

// maxPooledProxies bounds the pool; rows that were deleted leave entries behind.
const maxPooledProxies = 1024

func newUpstreamPool(propagate bool, getenv func(string) string) *upstreamPool {
	if getenv == nil {
		getenv = os.Getenv
	}
	return &upstreamPool{propagate: propagate, getenv: getenv, proxies: map[uuid.UUID]pooledProxy{}}
}

// keyEnvRe is the only form of variable an upstream may read its key from, so
// that an org admin cannot make the gateway send DATABASE_URL or JWT_SECRET.
var keyEnvRe = regexp.MustCompile(`^UPSTREAM_KEY_[A-Z0-9_]{1,64}$`)

// errKeyMissing means an upstream names a key variable that is not set.
var errKeyMissing = errors.New("api_key_env is not set in the gateway's environment")

func (p *upstreamPool) get(u *upstreamRow) (*proxy.Proxy, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if cached, ok := p.proxies[u.ID]; ok && cached.updated.Equal(u.UpdatedAt) {
		return cached.proxy, nil
	}
	key := ""
	if u.KeyEnv != "" {
		if !keyEnvRe.MatchString(u.KeyEnv) {
			return nil, fmt.Errorf("api_key_env %q is not an UPSTREAM_KEY_ variable", u.KeyEnv)
		}
		if key = p.getenv(u.KeyEnv); key == "" {
			return nil, fmt.Errorf("%s: %w", u.KeyEnv, errKeyMissing)
		}
	}
	if err := proxy.ValidateBaseURL(u.BaseURL); err != nil {
		return nil, err
	}
	px, err := proxy.New(proxy.Config{
		BaseURL:   u.BaseURL,
		Key:       key,
		Timeout:   time.Duration(u.TimeoutMs) * time.Millisecond,
		Propagate: p.propagate,
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
	model  string // replaces the request's model when set
	source string
}

// errRouteUnavailable fails a request closed with 502.
var errRouteUnavailable = errors.New("route target unavailable")

// resolveRoute picks the upstream for an allowed request. An error wrapping
// errRouteUnavailable comes with the target's name in route.name; any other
// error means the upstreams could not be read.
func (gw gateway) resolveRoute(entry requestEntry, decision policy.Decision) (route, error) {
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
	if gw.upstreams != nil && entry.OrgID != uuid.Nil {
		ctx, cancel := context.WithTimeout(gw.base, policyTimeout)
		up, source, err := gw.upstreams(ctx, entry.OrgID, entry.ProjectID, target)
		cancel()
		if errors.Is(err, errNoSuchUpstream) {
			return fail(route{name: target, source: sourceRule}, err)
		}
		if err != nil {
			return route{}, err
		}
		if up != nil {
			r := route{name: up.Name, model: up.Model, source: source}
			if !up.Enabled {
				return fail(r, errors.New("upstream is disabled"))
			}
			if gw.pool == nil {
				return fail(r, errors.New("no upstream pool"))
			}
			if r.proxy, err = gw.pool.get(up); err != nil {
				return fail(r, err)
			}
			metrics.RouteSelections.WithLabelValues(source, "ok").Inc()
			return r, nil
		}
	}
	if target != "" {
		return fail(route{name: target, source: sourceRule}, errNoSuchUpstream)
	}
	if gw.upstream != nil {
		metrics.RouteSelections.WithLabelValues(sourceEnv, "ok").Inc()
		return route{proxy: gw.upstream, source: sourceEnv}, nil
	}
	metrics.RouteSelections.WithLabelValues(sourceStub, "ok").Inc()
	return route{source: sourceStub}, nil
}
