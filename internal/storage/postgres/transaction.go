package postgres

import (
	"context"
	"database/sql"
)

// dbTransaction is shared by read snapshots and the ordered writer. It does not
// translate SQL: every backend query is PostgreSQL SQL with explicit parameters.
type dbTransaction interface {
	Exec(string, ...any) (sql.Result, error)
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	Query(string, ...any) (*sql.Rows, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// countingTx tracks actual affected rows rather than SQLite's total_changes().
// Callers reset mutations when rolling back a savepoint; a no-op cannot repair
// a prior failed writer health state. RETURNING inserts account explicitly.
type countingTx struct {
	*sql.Tx
	mutations int64
	ctx       context.Context
}

func (tx *countingTx) Exec(query string, args ...any) (sql.Result, error) {
	return tx.ExecContext(tx.ctx, query, args...)
}
func (tx *countingTx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	result, err := tx.Tx.ExecContext(ctx, query, args...)
	if err == nil {
		n, e := result.RowsAffected()
		if e == nil {
			tx.mutations += n
		}
	}
	return result, err
}

func (tx *countingTx) Query(query string, args ...any) (*sql.Rows, error) {
	return tx.Tx.QueryContext(tx.ctx, query, args...)
}
func (tx *countingTx) QueryRow(query string, args ...any) *sql.Row {
	return tx.Tx.QueryRowContext(tx.ctx, query, args...)
}
