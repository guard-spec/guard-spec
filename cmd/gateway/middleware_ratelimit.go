package main

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/metrics"
	"github.com/guard-spec/guard-spec/internal/ratelimit"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// limitsTTL is how long a key's limits are cached, so a change made in the
	// control plane applies within this time.
	limitsTTL = 30 * time.Second
	// maxCachedKeys bounds the cache; it is cleared when full.
	maxCachedKeys = 100_000
	limitsTimeout = 2 * time.Second
)

// keyLimitsFn reads a key's own limits. A nil value means "use the default".
type keyLimitsFn func(ctx context.Context, orgID uuid.UUID, keyHash string) (rpm, tpm *int64, err error)

// rateLimiter enforces the per-key limits. Its state is in this process only,
// so each replica counts on its own.
type rateLimiter struct {
	limiter  *ratelimit.Limiter
	defaults ratelimit.Limits // RATE_LIMIT_RPM, RATE_LIMIT_TPM
	lookup   keyLimitsFn      // nil: the defaults apply to every key
	now      func() time.Time

	mu    sync.Mutex
	cache map[string]cachedLimits
}

type cachedLimits struct {
	limits  ratelimit.Limits
	expires time.Time
}

func newRateLimiter(defaults ratelimit.Limits, lookup keyLimitsFn) *rateLimiter {
	return &rateLimiter{
		limiter:  ratelimit.New(),
		defaults: defaults,
		lookup:   lookup,
		now:      time.Now,
		cache:    map[string]cachedLimits{},
	}
}

// limits resolves a key's limits: its own where set, the defaults otherwise.
// A lookup failure falls back to the defaults rather than refusing traffic.
func (r *rateLimiter) limits(ctx context.Context, orgID uuid.UUID, hash string) ratelimit.Limits {
	if r.lookup == nil {
		return r.defaults
	}
	now := r.now()
	r.mu.Lock()
	c, ok := r.cache[hash]
	r.mu.Unlock()
	if ok && now.Before(c.expires) {
		return c.limits
	}
	ctx, cancel := context.WithTimeout(ctx, limitsTimeout)
	defer cancel()
	rpm, tpm, err := r.lookup(ctx, orgID, hash)
	if err != nil {
		slog.Warn("rate limit lookup failed; using defaults", "err", err)
		return r.defaults
	}
	lim := r.defaults
	if rpm != nil {
		lim.RPM = *rpm
	}
	if tpm != nil {
		lim.TPM = *tpm
	}
	r.mu.Lock()
	if len(r.cache) >= maxCachedKeys {
		clear(r.cache)
	}
	r.cache[hash] = cachedLimits{limits: lim, expires: now.Add(limitsTTL)}
	r.mu.Unlock()
	return lim
}

// middleware runs after tenant.Middleware. Tokens are estimated from the body
// size, 4 bytes per token, as for request.tokens in policies.
func (r *rateLimiter) middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		hash := tenant.KeyHash(c)
		orgID, _ := tenant.OrgID(c)
		lim := r.limits(c.Context(), orgID, hash)
		d := r.limiter.Allow(hash, lim, int64(len(c.Body())/4))
		if d.Allowed {
			return c.Next()
		}
		metrics.RateLimited.WithLabelValues(d.Limit).Inc()
		secs := max(int(math.Ceil(d.RetryAfter.Seconds())), 1)
		c.Set(fiber.HeaderRetryAfter, strconv.Itoa(secs))
		limit := lim.RPM
		if d.Limit == ratelimit.LimitTokens {
			limit = lim.TPM
		}
		msg := fmt.Sprintf("Rate limit reached: %d %s per minute for this API key. Try again in %ds.",
			limit, d.Limit, secs)
		return c.Status(fiber.StatusTooManyRequests).JSON(errorBody(msg, d.Limit, "rate_limit_exceeded"))
	}
}

// dbKeyLimits reads api_keys.rpm_limit and tpm_limit inside the org's RLS scope.
func dbKeyLimits(db *pgxpool.Pool) keyLimitsFn {
	return func(ctx context.Context, orgID uuid.UUID, hash string) (rpm, tpm *int64, err error) {
		err = tenant.WithOrg(ctx, db, orgID, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx,
				`SELECT rpm_limit::bigint, tpm_limit FROM api_keys WHERE key_hash = $1 AND org_id = $2`,
				hash, orgID).Scan(&rpm, &tpm)
		})
		return rpm, tpm, err
	}
}
