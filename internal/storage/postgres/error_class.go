package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
	"llmapi-logger/internal/auditmodel"
)

// ErrorClass returns a fixed allowlisted category. Never log the error text:
// driver/validation errors may contain SQL values, paths or captured content.
func ErrorClass(err error) string {
	if err == nil {
		return "none"
	}
	var coded *pgconn.PgError
	if errors.As(err, &coded) {
		switch coded.Code {
		case "53100":
			return "postgres_full"
		case "55P03", "40P01", "40001":
			return "postgres_busy"
		case "25006":
			return "postgres_read_only"
		case "XX001", "XX002":
			return "postgres_corrupt"
		}
		if len(coded.Code) >= 2 && coded.Code[:2] == "23" {
			return "postgres_constraint"
		}
		return "postgres_error"
	}

	var identity storedObjectIntegrityError
	var local localWriteError
	switch {
	case errors.Is(err, ErrRecoveryOverflow):
		return "recovery_overflow"
	case errors.Is(err, ErrQueueFull):
		return "queue_full"
	case errors.Is(err, ErrClosed):
		return "closed"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.As(err, &identity):
		return "object_integrity"
	case errors.Is(err, auditmodel.ErrReconstruction):
		return "reconstruction"
	case errors.As(err, &local):
		return "invalid_write"
	case errors.Is(err, sql.ErrNoRows):
		return "missing_row"
	default:
		return "unknown"
	}
}
