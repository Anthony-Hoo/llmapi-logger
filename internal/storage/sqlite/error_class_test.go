package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	sqlitecodes "modernc.org/sqlite/lib"
)

func TestStorageErrorClassesNeverExposeErrorText(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		err  error
		want string
	}{
		{nil, "none"}, {codedWriteFailure(sqlitecodes.SQLITE_FULL), "sqlite_full"},
		{codedWriteFailure(sqlitecodes.SQLITE_IOERR | (3 << 8)), "sqlite_io_error"},
		{codedWriteFailure(sqlitecodes.SQLITE_BUSY), "sqlite_busy"},
		{codedWriteFailure(sqlitecodes.SQLITE_READONLY), "sqlite_read_only"},
		{codedWriteFailure(sqlitecodes.SQLITE_CONSTRAINT), "sqlite_constraint"},
		{codedWriteFailure(sqlitecodes.SQLITE_CORRUPT), "sqlite_corrupt"},
		{storedObjectIntegrityError("private object details"), "object_integrity"},
		{ErrQueueFull, "queue_full"}, {ErrRecoveryOverflow, "recovery_overflow"},
		{context.Canceled, "cancelled"}, {context.DeadlineExceeded, "timeout"},
		{sql.ErrNoRows, "missing_row"}, {errors.New("private database path and SQL values"), "unknown"},
	} {
		err := test.err
		if err != nil {
			err = fmt.Errorf("private wrapper: %w", err)
		}
		if got := ErrorClass(err); got != test.want {
			t.Fatalf("class=%s want=%s", got, test.want)
		}
	}
	var output bytes.Buffer
	store := &Store{logger: slog.New(slog.NewJSONHandler(&output, nil))}
	store.recoveryFailed(errors.New("private database path and SQL values"))
	if strings.Contains(output.String(), "private") || !strings.Contains(output.String(), `"storage_error":"unknown"`) {
		t.Fatalf("unsafe or unclassified recovery log: %s", output.String())
	}
}
