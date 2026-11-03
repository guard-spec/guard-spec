package ml

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/singleflight"
)

type orgKey struct{}

// WithOrg tells L3 whose exemplars to use for scans under ctx.
func WithOrg(ctx context.Context, org uuid.UUID) context.Context {
	if org == uuid.Nil {
		return ctx
	}
	return context.WithValue(ctx, orgKey{}, org)
}

// OrgFrom returns the organization set by WithOrg.
func OrgFrom(ctx context.Context) (uuid.UUID, bool) {
	org, ok := ctx.Value(orgKey{}).(uuid.UUID)
	return org, ok
}

// TenantStore reads organizations' exemplars. The version must change
// whenever an org's exemplars change (the control plane bumps it).
type TenantStore interface {
	ExemplarVersion(ctx context.Context, org uuid.UUID) (int64, error)
	Exemplars(ctx context.Context, org uuid.UUID) ([]Exemplar, error)
}

// DefaultVersionTTL is how long a cached org index is used before its
// version is checked again.
const DefaultVersionTTL = 5 * time.Second

// TenantCache keeps each organization's embedded exemplars. The version is
// checked at most once per TTL; a new version re-embeds only texts not seen
// in the org's previous version. Safe for concurrent use.
type TenantCache struct {
	store TenantStore
	e     Embedder
	ttl   time.Duration
	now   func() time.Time

	mu   sync.Mutex
	orgs map[uuid.UUID]*orgIndex
	sf   singleflight.Group
}

type orgIndex struct {
	version int64
	checked time.Time
	idx     *Index               // nil: the org has no exemplars
	vecs    map[string][]float32 // text -> vector, reused across versions
}

// NewTenantCache returns a cache over store. ttl <= 0 means DefaultVersionTTL.
func NewTenantCache(store TenantStore, e Embedder, ttl time.Duration) *TenantCache {
	if ttl <= 0 {
		ttl = DefaultVersionTTL
	}
	return &TenantCache{store: store, e: e, ttl: ttl, now: time.Now, orgs: map[uuid.UUID]*orgIndex{}}
}

// Index returns the org's exemplar index, or nil when it has none. When the
// version check fails and an older index is cached, the older index is used
// (and the failure logged) rather than dropping the org's block exemplars.
func (c *TenantCache) Index(ctx context.Context, org uuid.UUID) (*Index, error) {
	c.mu.Lock()
	cur := c.orgs[org]
	if cur != nil && c.now().Sub(cur.checked) < c.ttl {
		c.mu.Unlock()
		return cur.idx, nil
	}
	c.mu.Unlock()

	v, err, _ := c.sf.Do(org.String(), func() (any, error) {
		return c.refresh(ctx, org, cur)
	})
	if err != nil {
		if cur != nil {
			slog.Warn("org exemplars: refresh failed, using cached version", "org", org, "version", cur.version, "err", err)
			return cur.idx, nil
		}
		return nil, err
	}
	return v.(*orgIndex).idx, nil
}

func (c *TenantCache) refresh(ctx context.Context, org uuid.UUID, cur *orgIndex) (*orgIndex, error) {
	version, err := c.store.ExemplarVersion(ctx, org)
	if err != nil {
		return nil, err
	}
	if cur != nil && cur.version == version {
		next := *cur
		next.checked = c.now()
		c.put(org, &next)
		return &next, nil
	}
	ex, err := c.store.Exemplars(ctx, org)
	if err != nil {
		return nil, err
	}
	next := &orgIndex{version: version, checked: c.now(), vecs: map[string][]float32{}}
	if len(ex) > 0 {
		var todo []string
		for _, x := range ex {
			if cur != nil && cur.vecs[x.Text] != nil {
				next.vecs[x.Text] = cur.vecs[x.Text]
			} else if next.vecs[x.Text] == nil {
				next.vecs[x.Text] = []float32{} // placeholder, filled below
				todo = append(todo, x.Text)
			}
		}
		for start := 0; start < len(todo); start += embedBatch {
			batch := todo[start:min(start+embedBatch, len(todo))]
			v, err := c.e.Embed(ctx, batch)
			if err != nil {
				return nil, err
			}
			for i, t := range batch {
				next.vecs[t] = v[i]
			}
		}
		vecs := make([][]float32, len(ex))
		for i, x := range ex {
			vecs[i] = next.vecs[x.Text]
		}
		if next.idx, err = indexFrom(ex, vecs); err != nil {
			return nil, err
		}
	}
	c.put(org, next)
	slog.Info("org exemplars loaded", "org", org, "version", version, "exemplars", len(ex))
	return next, nil
}

func (c *TenantCache) put(org uuid.UUID, e *orgIndex) {
	c.mu.Lock()
	c.orgs[org] = e
	c.mu.Unlock()
}
