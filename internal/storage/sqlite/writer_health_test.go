package sqlite

import (
	"errors"
	"fmt"
	"testing"

	sqlitecodes "modernc.org/sqlite/lib"
)

type codedWriteFailure int

func (err codedWriteFailure) Error() string { return "injected database failure" }
func (err codedWriteFailure) Code() int     { return int(err) }

func TestOnlyKnownLocalWriteErrorsAreIsolated(t *testing.T) {
	t.Parallel()
	for _, code := range []int{sqlitecodes.SQLITE_FULL, sqlitecodes.SQLITE_READONLY,
		sqlitecodes.SQLITE_IOERR, sqlitecodes.SQLITE_IOERR | (3 << 8), sqlitecodes.SQLITE_BUSY,
		sqlitecodes.SQLITE_CORRUPT, sqlitecodes.SQLITE_ERROR} {
		if canIsolateWriteError(fmt.Errorf("wrapped: %w", codedWriteFailure(code))) {
			t.Fatalf("database error %d was classified as local", code)
		}
	}
	if canIsolateWriteError(errors.New("unknown write failure")) {
		t.Fatal("unknown write failure was classified as local")
	}
	for _, err := range []error{codedWriteFailure(sqlitecodes.SQLITE_CONSTRAINT),
		codedWriteFailure(sqlitecodes.SQLITE_CONSTRAINT | (8 << 8)), localWriteError("invalid prepared sequence"), storedObjectIntegrityError("object identity mismatch")} {
		if !canIsolateWriteError(fmt.Errorf("wrapped: %w", err)) {
			t.Fatal("known operation-local error failed the database")
		}
	}
}

func TestReadOnlyWriterFailsBatchAndRecoversAfterRealWrite(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	if _, err := store.writerDB.Exec("PRAGMA query_only = ON"); err != nil {
		t.Fatal(err)
	}
	writer := &Store{writerDB: store.writerDB}
	writer.healthy.Store(true)
	run := func(ids ...string) []error {
		writer.queue, writer.done = make(chan writeRequest, len(ids)), make(chan struct{})
		acks := make([]chan error, len(ids))
		for i, id := range ids {
			record := testAudit(id)
			record.defaults()
			if id == "constraint-failure" {
				record.Mode = "invalid"
			}
			acks[i] = make(chan error, 1)
			writer.queue <- writeRequest{kind: writeBeginAudit, data: record, ack: acks[i]}
		}
		close(writer.queue)
		writer.runWriter()
		results := make([]error, len(acks))
		for i, ack := range acks {
			results[i] = <-ack
		}
		return results
	}
	for _, err := range run("readonly-one", "readonly-two") {
		var coded interface{ Code() int }
		if !errors.As(err, &coded) || coded.Code()&0xff != sqlitecodes.SQLITE_READONLY {
			t.Fatalf("batch did not return the read-only database failure: %v", err)
		}
	}
	if writer.Healthy() {
		t.Fatal("read-only database still reports healthy")
	}
	assertTableCount(t, store.readerDB, "audit_records", 0)
	if _, err := store.writerDB.Exec("PRAGMA query_only = OFF"); err != nil {
		t.Fatal(err)
	}
	if err := run("constraint-failure")[0]; err == nil || !canIsolateWriteError(err) {
		t.Fatal("expected an isolated constraint error")
	}
	if writer.Healthy() {
		t.Fatal("an empty commit after a local failure restored health")
	}
	if err := run("after-storage-recovery")[0]; err != nil {
		t.Fatal(err)
	}
	if !writer.Healthy() {
		t.Fatal("successful committed write did not restore health")
	}
	assertTableCount(t, store.readerDB, "audit_records", 1)
}
