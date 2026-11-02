package tenant

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WithOrg runs fn in a transaction scoped to orgID. The setting is
// transaction-local, so it is safe with PgBouncer transaction mode.
func WithOrg(ctx context.Context, db *pgxpool.Pool, orgID uuid.UUID, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.org_id', $1, true)`, orgID.String()); err != nil {
			return err
		}
		return fn(tx)
	})
}
