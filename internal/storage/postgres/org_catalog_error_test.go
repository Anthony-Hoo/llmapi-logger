package postgres

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"llmapi-logger/internal/orgreport"
)

func TestOrgAdminErrorMapsConstraintCodes(t *testing.T) {
	for _, tc := range []struct {
		code string
		want error
	}{
		{"23505", orgreport.ErrConflict}, // unique_violation
		{"23503", orgreport.ErrConflict}, // foreign_key_violation
		{"23001", orgreport.ErrConflict}, // restrict_violation (ON DELETE RESTRICT)
		{"23514", orgreport.ErrInvalid},  // check_violation
		{"23502", orgreport.ErrInvalid},  // not_null_violation
	} {
		err := orgAdminError(fmt.Errorf("wrapped: %w", &pgconn.PgError{Code: tc.code, ConstraintName: "c"}))
		if !errors.Is(err, tc.want) {
			t.Errorf("code %s: got %v, want %v", tc.code, err, tc.want)
		}
	}
	other := &pgconn.PgError{Code: "40001"}
	if err := orgAdminError(other); err != other {
		t.Errorf("unmapped code changed: %v", err)
	}
}
