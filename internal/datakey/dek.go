// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package datakey

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Prefix starts every value this package sealed:
// "gsenc:v1:<dek uuid>:<base64 of nonce || ciphertext>". Text without it is
// stored in the clear (rows written before encryption was configured).
const Prefix = "gsenc:v1:"

// ErrKeyDestroyed means the DEK of a sealed value no longer exists: its
// organization was deleted or the key was pruned.
var ErrKeyDestroyed = errors.New("datakey: the data key of this value no longer exists")

// DEK is one organization's data key.
type DEK struct {
	ID    uuid.UUID
	OrgID uuid.UUID
	aead  cipher.AEAD
}

func newDEK(id, org uuid.UUID, raw []byte) (*DEK, error) {
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &DEK{ID: id, OrgID: org, aead: aead}, nil
}

// Seal encrypts plain. aad binds the value to where it is stored (see
// ContentAAD); Open must be given the same.
func (d *DEK) Seal(plain string, aad []byte) (string, error) {
	nonce := make([]byte, d.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := d.aead.Seal(nonce, nonce, []byte(plain), aad)
	return Prefix + d.ID.String() + ":" + base64.RawStdEncoding.EncodeToString(ct), nil
}

// Open decrypts a value Seal returned.
func (d *DEK) Open(sealed string, aad []byte) (string, error) {
	id, payload, err := Parse(sealed)
	if err != nil {
		return "", err
	}
	if id != d.ID {
		return "", fmt.Errorf("datakey: value sealed with key %s, not %s", id, d.ID)
	}
	n := d.aead.NonceSize()
	if len(payload) < n {
		return "", errors.New("datakey: sealed value too short")
	}
	plain, err := d.aead.Open(nil, payload[:n], payload[n:], aad)
	if err != nil {
		return "", errors.New("datakey: the value does not decrypt (wrong key or it was changed)")
	}
	return string(plain), nil
}

// IsSealed reports whether s was produced by Seal.
func IsSealed(s string) bool { return strings.HasPrefix(s, Prefix) }

// Parse splits a sealed value into its DEK id and payload.
func Parse(sealed string) (uuid.UUID, []byte, error) {
	if !IsSealed(sealed) {
		return uuid.Nil, nil, errors.New("datakey: not a sealed value")
	}
	rest := sealed[len(Prefix):]
	i := strings.IndexByte(rest, ':')
	if i < 0 {
		return uuid.Nil, nil, errors.New("datakey: malformed sealed value")
	}
	id, err := uuid.Parse(rest[:i])
	if err != nil {
		return uuid.Nil, nil, fmt.Errorf("datakey: malformed key id: %w", err)
	}
	payload, err := base64.RawStdEncoding.DecodeString(rest[i+1:])
	if err != nil {
		return uuid.Nil, nil, fmt.Errorf("datakey: malformed payload: %w", err)
	}
	return id, payload, nil
}

// ContentAAD is the additional data of a stored request or response body:
// the organization, the column and the body's SHA-256, so a value moved to
// another organization, column or row does not decrypt.
func ContentAAD(org uuid.UUID, column, sha256hex string) []byte {
	return []byte("guard-spec/requests/" + column + "/" + org.String() + "/" + sha256hex)
}

// dekAAD binds a wrapped DEK to its organization and id.
func dekAAD(org, id uuid.UUID) []byte {
	return []byte("guard-spec/org_data_keys/" + org.String() + "/" + id.String())
}

// Querier is a pgx transaction or pool.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Store loads and creates DEKs (table org_data_keys) and caches them
// unwrapped in memory for TTL, so a request seldom calls the KEK. Calls run
// in a transaction scoped to the organization (row-level security).
type Store struct {
	Ring *Keyring
	TTL  time.Duration // default 10 minutes
	now  func() time.Time

	mu     sync.Mutex
	byID   map[uuid.UUID]cachedDEK
	active map[uuid.UUID]cachedDEK
}

type cachedDEK struct {
	dek *DEK
	at  time.Time
}

// NewStore returns a store over ring.
func NewStore(ring *Keyring) *Store {
	return &Store{Ring: ring, byID: map[uuid.UUID]cachedDEK{}, active: map[uuid.UUID]cachedDEK{}}
}

func (s *Store) ttl() time.Duration {
	if s.TTL <= 0 {
		return 10 * time.Minute
	}
	return s.TTL
}

func (s *Store) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *Store) cached(m map[uuid.UUID]cachedDEK, key uuid.UUID) *DEK {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := m[key]; ok && s.clock().Sub(c.at) < s.ttl() {
		return c.dek
	}
	return nil
}

func (s *Store) remember(d *DEK, active bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := cachedDEK{dek: d, at: s.clock()}
	s.byID[d.ID] = c
	if active {
		s.active[d.OrgID] = c
	}
}

// Active returns the organization's active DEK, creating it on first use.
func (s *Store) Active(ctx context.Context, q Querier, org uuid.UUID) (*DEK, error) {
	if d := s.cached(s.active, org); d != nil {
		return d, nil
	}
	d, err := s.load(ctx, q, `SELECT id, kek_id, wrapped FROM org_data_keys WHERE org_id = $1 AND active`, org)
	if err == nil {
		s.remember(d, true)
		return d, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	d, err = s.create(ctx, q, org)
	if err != nil {
		return nil, err
	}
	s.remember(d, true)
	return d, nil
}

// Get returns the DEK a sealed value names.
func (s *Store) Get(ctx context.Context, q Querier, org, id uuid.UUID) (*DEK, error) {
	if d := s.cached(s.byID, id); d != nil && d.OrgID == org {
		return d, nil
	}
	d, err := s.load(ctx, q, `SELECT id, kek_id, wrapped FROM org_data_keys WHERE org_id = $1 AND id = $2`, org, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrKeyDestroyed
	}
	if err != nil {
		return nil, err
	}
	s.remember(d, false)
	return d, nil
}

// Open decrypts a stored value of org; text that is not sealed is returned
// as it is.
func (s *Store) Open(ctx context.Context, q Querier, org uuid.UUID, value string, aad []byte) (string, error) {
	if !IsSealed(value) {
		return value, nil
	}
	id, _, err := Parse(value)
	if err != nil {
		return "", err
	}
	d, err := s.Get(ctx, q, org, id)
	if err != nil {
		return "", err
	}
	return d.Open(value, aad)
}

func (s *Store) load(ctx context.Context, q Querier, sql string, args ...any) (*DEK, error) {
	var id uuid.UUID
	var kekID string
	var wrapped []byte
	org := args[0].(uuid.UUID)
	if err := q.QueryRow(ctx, sql, args...).Scan(&id, &kekID, &wrapped); err != nil {
		return nil, err
	}
	kek, ok := s.Ring.Get(kekID)
	if !ok {
		return nil, fmt.Errorf("datakey: the data key %s is wrapped by %s, which is not configured (configured: %s)",
			id, kekID, strings.Join(s.Ring.IDs(), ", "))
	}
	raw, err := kek.Unwrap(ctx, wrapped, dekAAD(org, id))
	if err != nil {
		return nil, fmt.Errorf("datakey: unwrap %s with %s: %w", id, kekID, err)
	}
	return newDEK(id, org, raw)
}

// create makes a new active DEK. Two processes may race: the partial unique
// index keeps one, and the loser reads the winner's.
func (s *Store) create(ctx context.Context, q Querier, org uuid.UUID) (*DEK, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	id := uuid.New()
	kek := s.Ring.Active()
	wrapped, err := kek.Wrap(ctx, raw, dekAAD(org, id))
	if err != nil {
		return nil, fmt.Errorf("datakey: wrap a new data key with %s: %w", kek.ID(), err)
	}
	tag, err := q.Exec(ctx, `INSERT INTO org_data_keys (id, org_id, kek_id, wrapped, active)
		VALUES ($1, $2, $3, $4, true) ON CONFLICT (org_id) WHERE active DO NOTHING`, id, org, kek.ID(), wrapped)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return s.load(ctx, q, `SELECT id, kek_id, wrapped FROM org_data_keys WHERE org_id = $1 AND active`, org)
	}
	return newDEK(id, org, raw)
}

// Rotate makes a new active DEK for org; the old one stays to open the
// values it sealed. It returns the new key's id.
func (s *Store) Rotate(ctx context.Context, q Querier, org uuid.UUID) (uuid.UUID, error) {
	if _, err := q.Exec(ctx, `UPDATE org_data_keys SET active = false, retired_at = NOW() WHERE org_id = $1 AND active`, org); err != nil {
		return uuid.Nil, err
	}
	d, err := s.create(ctx, q, org)
	if err != nil {
		return uuid.Nil, err
	}
	s.mu.Lock()
	delete(s.active, org)
	s.mu.Unlock()
	return d.ID, nil
}

// Rewrap wraps the DEK id of org again with the active KEK. It returns false
// when the DEK already used it.
func (s *Store) Rewrap(ctx context.Context, q Querier, org, id uuid.UUID) (bool, error) {
	var kekID string
	var wrapped []byte
	if err := q.QueryRow(ctx, `SELECT kek_id, wrapped FROM org_data_keys WHERE org_id = $1 AND id = $2`, org, id).Scan(&kekID, &wrapped); err != nil {
		return false, err
	}
	active := s.Ring.Active()
	if kekID == active.ID() && !strings.HasPrefix(active.ID(), "vault:") {
		return false, nil
	}
	old, ok := s.Ring.Get(kekID)
	if !ok {
		return false, fmt.Errorf("datakey: %s is wrapped by %s, which is not configured", id, kekID)
	}
	raw, err := old.Unwrap(ctx, wrapped, dekAAD(org, id))
	if err != nil {
		return false, err
	}
	nw, err := active.Wrap(ctx, raw, dekAAD(org, id))
	if err != nil {
		return false, err
	}
	if _, err := q.Exec(ctx, `UPDATE org_data_keys SET kek_id = $3, wrapped = $4, rewrapped_at = NOW() WHERE org_id = $1 AND id = $2`,
		org, id, active.ID(), nw); err != nil {
		return false, err
	}
	return true, nil
}
