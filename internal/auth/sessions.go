package auth

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Session is a row of the sessions table (migration 013) with what the
// middleware needs of its user.
type Session struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	Method    string // password, google or oidc:<provider id>
	MFA       bool   // a second factor was checked at login
	CreatedAt time.Time
	ExpiresAt time.Time
}

// ErrNoSession means the session does not exist, was revoked or expired, or
// its user is disabled.
var ErrNoSession = errors.New("no such session")

// SessionLookup resolves a session id to an active session.
type SessionLookup interface {
	Lookup(ctx context.Context, sid uuid.UUID) (Session, error)
}

// sessionCacheTTL bounds how long another control plane replica may accept a
// session after it was revoked. Revocations made by this process take effect
// at once.
const sessionCacheTTL = 15 * time.Second

// Sessions stores sessions in Postgres with a short in-process cache.
type Sessions struct {
	db *pgxpool.Pool

	mu    sync.Mutex
	cache map[uuid.UUID]cachedSession
	now   func() time.Time
}

type cachedSession struct {
	s       Session
	fetched time.Time
}

// maxCachedSessions bounds the cache; it is cleared when full.
const maxCachedSessions = 10_000

// NewSessions returns a session store backed by db.
func NewSessions(db *pgxpool.Pool) *Sessions {
	return &Sessions{db: db, cache: map[uuid.UUID]cachedSession{}, now: time.Now}
}

// NewSession is what Create stores.
type NewSession struct {
	UserID    uuid.UUID
	Method    string
	MFA       bool
	UserAgent string
	IP        string
}

// Create starts a session of TokenLifetime and records the login time.
func (s *Sessions) Create(ctx context.Context, n NewSession) (Session, error) {
	sess := Session{UserID: n.UserID, Method: n.Method, MFA: n.MFA}
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx,
			`INSERT INTO sessions (user_id, method, mfa, user_agent, ip, expires_at)
			 VALUES ($1, $2, $3, $4, $5, NOW() + $6::interval)
			 RETURNING id, created_at, expires_at`,
			n.UserID, n.Method, n.MFA, truncate(n.UserAgent, 512), truncate(n.IP, 64), TokenLifetime).
			Scan(&sess.ID, &sess.CreatedAt, &sess.ExpiresAt); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE users SET last_login_at = NOW() WHERE id = $1`, n.UserID)
		return err
	})
	return sess, err
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Lookup returns an active session. A cache miss also records last_seen_at.
func (s *Sessions) Lookup(ctx context.Context, sid uuid.UUID) (Session, error) {
	now := s.now()
	s.mu.Lock()
	if c, ok := s.cache[sid]; ok && now.Sub(c.fetched) < sessionCacheTTL && now.Before(c.s.ExpiresAt) {
		s.mu.Unlock()
		return c.s, nil
	}
	s.mu.Unlock()

	var sess Session
	err := s.db.QueryRow(ctx,
		`UPDATE sessions se SET last_seen_at = NOW()
		 FROM users u
		 WHERE se.id = $1 AND u.id = se.user_id
		   AND se.revoked_at IS NULL AND se.expires_at > NOW() AND u.disabled_at IS NULL
		 RETURNING se.id, se.user_id, se.method, se.mfa, se.created_at, se.expires_at`, sid).
		Scan(&sess.ID, &sess.UserID, &sess.Method, &sess.MFA, &sess.CreatedAt, &sess.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		s.forget(func(id uuid.UUID, _ Session) bool { return id == sid })
		return Session{}, ErrNoSession
	}
	if err != nil {
		return Session{}, err
	}
	s.mu.Lock()
	if len(s.cache) >= maxCachedSessions {
		clear(s.cache)
	}
	s.cache[sid] = cachedSession{s: sess, fetched: now}
	s.mu.Unlock()
	return sess, nil
}

func (s *Sessions) forget(match func(uuid.UUID, Session) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, c := range s.cache {
		if match(id, c.s) {
			delete(s.cache, id)
		}
	}
}

// Revoke ends one session of userID. It reports false when the user has no
// such active session.
func (s *Sessions) Revoke(ctx context.Context, userID, sid uuid.UUID) (bool, error) {
	tag, err := s.db.Exec(ctx,
		`UPDATE sessions SET revoked_at = NOW() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`, sid, userID)
	s.forget(func(id uuid.UUID, _ Session) bool { return id == sid })
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// RevokeAll ends every session of userID except keep (uuid.Nil: none kept).
func (s *Sessions) RevokeAll(ctx context.Context, userID, keep uuid.UUID) (int64, error) {
	tag, err := s.db.Exec(ctx,
		`UPDATE sessions SET revoked_at = NOW() WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL`, userID, keep)
	s.forget(func(id uuid.UUID, c Session) bool { return c.UserID == userID && id != keep })
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// Forget drops a user's sessions from the cache, so that a change to the user
// (disabled, say) is seen on the next request.
func (s *Sessions) Forget(userID uuid.UUID) {
	s.forget(func(_ uuid.UUID, c Session) bool { return c.UserID == userID })
}
