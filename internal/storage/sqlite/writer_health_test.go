package sqlite

import (
	"context"
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
			op := writeRequest{kind: writeBeginAudit, data: record, ack: acks[i]}
			if id == "noop-release" {
				op.kind, op.data = writeReleaseProcessingParse, "absent-audit"
			}
			if id == "noop-claim" {
				op.kind, op.data = writeClaimPendingParse, &parseClaim{AuditID: "absent-audit"}
			}
			writer.queue <- op
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
	if err := run("noop-release")[0]; err != nil {
		t.Fatal(err)
	}
	if writer.Healthy() {
		t.Fatal("a read-only idempotent release restored write health")
	}
	if _, err := store.writerDB.Exec("PRAGMA query_only = OFF"); err != nil {
		t.Fatal(err)
	}
	if err := run("constraint-failure")[0]; err == nil || !canIsolateWriteError(err) {
		t.Fatal("expected an isolated constraint error")
	}
	if writer.Healthy() {
		t.Fatal("an empty commit after a local failure restored health")
	}
	for _, err := range run("noop-release", "noop-claim") {
		if err != nil {
			t.Fatal(err)
		}
	}
	if writer.Healthy() {
		t.Fatal("successful no-op operations restored write health")
	}
	if err := run("after-storage-recovery")[0]; err != nil {
		t.Fatal(err)
	}
	if !writer.Healthy() {
		t.Fatal("successful committed write did not restore health")
	}
	assertTableCount(t, store.readerDB, "audit_records", 1)
}

func TestRolledBackMutationsCannotRestoreWriteHealth(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	ended := int64(20)
	insertRetentionAudit(t, store, "rollback-health", 10, &ended, ParseProcessing, false)
	store.healthy.Store(false)
	// The parsed-result UPSERT changes a row before the wrong parser name
	// makes parent finalization fail. total_changes counts that rolled-back
	// mutation, but it cannot be used as evidence of a committed write.
	err := store.SaveParsedResult(context.Background(), ParsedResult{AuditID: "rollback-health", ParserName: "wrong-parser", ParserVersion: "1", Status: ParseOK, ParsedAtNS: 21})
	if err == nil || !canIsolateWriteError(err) {
		t.Fatalf("expected a local parse failure: %v", err)
	}
	assertTableCount(t, store.readerDB, "parsed_results", 0)
	if store.Healthy() {
		t.Fatal("rolled-back writes restored health")
	}
	if err := store.ReleaseProcessingParse(context.Background(), "absent-audit"); err != nil {
		t.Fatal(err)
	}
	if store.Healthy() {
		t.Fatal("a later no-op restored health")
	}
}
