package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"llmapi-logger/internal/auditmodel"
	sqlitecodes "modernc.org/sqlite/lib"
)

// ErrorClass returns a fixed allowlisted category. Never log the error text:
// driver/validation errors may contain SQL values, paths or captured content.
func ErrorClass(err error) string {
	if err == nil {
		return "none"
	}
	var coded interface{ Code() int }
	if errors.As(err, &coded) {
		switch coded.Code() & 0xff {
		case sqlitecodes.SQLITE_FULL:
			return "sqlite_full"
		case sqlitecodes.SQLITE_BUSY, sqlitecodes.SQLITE_LOCKED:
			return "sqlite_busy"
		case sqlitecodes.SQLITE_READONLY:
			return "sqlite_read_only"
		case sqlitecodes.SQLITE_IOERR:
			return "sqlite_io_error"
		case sqlitecodes.SQLITE_CORRUPT, sqlitecodes.SQLITE_NOTADB:
			return "sqlite_corrupt"
		case sqlitecodes.SQLITE_CONSTRAINT:
			return "sqlite_constraint"
		default:
			return "sqlite_error"
		}
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
