package storage

import (
	"context"
	"database/sql"
	"errors"
	"llmapi-logger/internal/auditmodel"
)

// ErrorClass emits only stable allowlisted categories. Driver messages may
// contain credentials, SQL arguments, ciphertext or captured request content.
func ErrorClass(err error) string {
	if err == nil {
		return "none"
	}
	var classified interface{ StorageErrorClass() string }
	if errors.As(err, &classified) {
		switch c := classified.StorageErrorClass(); c {
		case "object_integrity", "invalid_write":
			return c
		}
	}
	var state interface{ SQLState() string }
	if errors.As(err, &state) {
		c := state.SQLState()
		switch c {
		case "53100":
			return "postgres_full"
		case "25006":
			return "postgres_read_only"
		case "55P03", "40P01", "40001":
			return "postgres_busy"
		}
		if len(c) >= 2 {
			switch c[:2] {
			case "23":
				return "postgres_constraint"
			case "08":
				return "postgres_connection"
			case "58":
				return "postgres_io_error"
			}
		}
		return "postgres_error"
	}
	// Kept for offline migration diagnostics and legacy fixtures without linking
	// the SQLite driver into the runtime binary.
	var code interface{ Code() int }
	if errors.As(err, &code) {
		switch code.Code() & 255 {
		case 13:
			return "sqlite_full"
		case 5, 6:
			return "sqlite_busy"
		case 8:
			return "sqlite_read_only"
		case 10:
			return "sqlite_io_error"
		case 11, 26:
			return "sqlite_corrupt"
		case 19:
			return "sqlite_constraint"
		}
		return "sqlite_error"
	}
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
	case errors.Is(err, auditmodel.ErrReconstruction):
		return "reconstruction"
	case errors.Is(err, sql.ErrNoRows):
		return "missing_row"
	default:
		return "unknown"
	}
}
