package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// statementCounter is a dbTransaction that counts every statement the writer
// sends, reads included.
type statementCounter struct {
	tx         *sql.Tx
	statements int
}

func (counter *statementCounter) Exec(query string, args ...any) (sql.Result, error) {
	return counter.ExecContext(context.Background(), query, args...)
}

func (counter *statementCounter) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	counter.statements++
	return counter.tx.ExecContext(ctx, query, args...)
}

func (counter *statementCounter) Query(query string, args ...any) (*sql.Rows, error) {
	return counter.QueryContext(context.Background(), query, args...)
}

func (counter *statementCounter) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	counter.statements++
	return counter.tx.QueryContext(ctx, query, args...)
}

func (counter *statementCounter) QueryRow(query string, args ...any) *sql.Row {
	return counter.QueryRowContext(context.Background(), query, args...)
}

func (counter *statementCounter) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	counter.statements++
	return counter.tx.QueryRowContext(ctx, query, args...)
}

// writeRequestOf prepares an operation as its public method does before
// queueing it.
func writeRequestOf(t *testing.T, op hOp) writeRequest {
	t.Helper()
	switch op.kind {
	case writeBeginAudit:
		record := op.data.(AuditRecord)
		record.Defaults()
		owned := cloneAuditRecord(record)
		if record.Inbound != nil {
			inbound := cloneInboundStage(*record.Inbound)
			inbound.Stage.Defaults()
			owned.Inbound = &inbound
		}
		return writeRequest{kind: op.kind, data: owned}
	case writeStartStage:
		stage := op.data.(HTTPStage)
		stage.Defaults()
		return writeRequest{kind: op.kind, data: stage}
	case writeStartBody:
		body := op.data.(BodyStream)
		body.Defaults()
		return writeRequest{kind: op.kind, data: body}
	case writeAddChunk:
		chunk := op.data.(BodyChunk)
		chunk.Defaults()
		return writeRequest{kind: op.kind, data: chunk}
	case writeFinishStage:
		finish := op.data.(StageFinish)
		finish.Defaults()
		return writeRequest{kind: op.kind, data: finish}
	case writeFinishAudit:
		finish := op.data.(AuditFinish)
		finish.Defaults()
		return writeRequest{kind: op.kind, data: &finish}
	case writeCheckpoint:
		return writeRequest{kind: op.kind, data: &checkpointWrite{AuditCheckpoint: op.data.(AuditCheckpoint)}}
	case writeCommitAudit:
		commit := op.data.(AuditCommit)
		commit.Finish.Defaults()
		for index := range commit.Stages {
			if body := commit.Stages[index].Body; body != nil {
				owned := *body
				commitBodyDefaults(&owned, commit.Stages[index].Timeline)
				commit.Stages[index].Body = &owned
			}
		}
		return writeRequest{kind: op.kind, data: cloneAuditCommit(commit)}
	default:
		return writeRequest{kind: op.kind, data: op.data}
	}
}

// countStatements applies each operation in its own savepoint, as
// commitBatch does, on a separate connection to the same schema, and counts
// the statements including SAVEPOINT and RELEASE. BEGIN and COMMIT are not
// counted: how many operations share a batch depends on timing.
func countStatements(t *testing.T, store *Store, dsn string, ops []hOp) (int, map[writeKind]int) {
	t.Helper()
	database, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	total := 0
	perKind := make(map[writeKind]int)
	for index, op := range ops {
		tx, err := database.Begin()
		if err != nil {
			t.Fatal(err)
		}
		counter := &statementCounter{tx: tx}
		if _, err := counter.Exec("SAVEPOINT writer_operation"); err != nil {
			t.Fatal(err)
		}
		if err := store.applyWrite(counter, writeRequestOf(t, op)); err != nil {
			t.Fatalf("operation %d (kind %d): %v", index, op.kind, err)
		}
		if _, err := counter.Exec("RELEASE writer_operation"); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		total += counter.statements
		perKind[op.kind] += counter.statements
	}
	return total, perKind
}

var harnessKindNames = map[writeKind]string{
	writeBeginAudit: "BeginAudit", writeStartStage: "StartStage", writeAddHeaders: "AddHeaders", writeStartBody: "StartBody",
	writeAddChunk: "AddChunk", writeFinishStage: "FinishStage", writeFinishAudit: "FinishAudit",
	writeCheckpoint: "Checkpoint", writeCommitAudit: "CommitAudit",
}

func describeCounts(ops []hOp, perKind map[writeKind]int) string {
	operations := make(map[writeKind]int)
	for _, op := range ops {
		operations[op.kind]++
	}
	parts := make([]string, 0, len(perKind))
	for kind, statements := range perKind {
		parts = append(parts, fmt.Sprintf("%s x%d: %d", harnessKindNames[kind], operations[kind], statements))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

// TestStagedWriteStatementCounts counts the statements and savepoints of a
// typical streaming request (A.2: four stages, bodies under 1 MiB, no
// trailers, both pairs merged) under both sequences.
func TestStagedWriteStatementCounts(t *testing.T) {
	t.Parallel()
	store, dsn := openTestStore(t)
	if err := store.EnableIntegrity(context.Background(), harnessIntegrityKey); err != nil {
		t.Fatal(err)
	}
	sealer := harnessSealer{t: t, cipher: harnessCipher(t)}
	clock := &harnessClock{now: 1_000_000}
	typical := scenarioByName(t, "stream both pairs merged")
	legacyHarness := newHarness(t, clock, "count-legacy")
	typical.build(legacyHarness)
	unifiedHarness := newHarness(t, clock, "count-unified")
	typical.build(unifiedHarness)
	legacyOps, unifiedOps := legacyHarness.legacyOps(sealer), unifiedHarness.unifiedOps(sealer)
	legacyTotal, legacyKinds := countStatements(t, store, dsn, legacyOps)
	unifiedTotal, unifiedKinds := countStatements(t, store, dsn, unifiedOps)
	t.Logf("legacy: %d operations, %d savepoints, %d statements (%s)", len(legacyOps), len(legacyOps), legacyTotal, describeCounts(legacyOps, legacyKinds))
	t.Logf("unified: %d operations, %d savepoints, %d statements (%s)", len(unifiedOps), len(unifiedOps), unifiedTotal, describeCounts(unifiedOps, unifiedKinds))
	if len(legacyOps) != 22 || len(unifiedOps) != 4 || unifiedTotal >= legacyTotal {
		t.Fatalf("legacy %d/%d, unified %d/%d", len(legacyOps), legacyTotal, len(unifiedOps), unifiedTotal)
	}
	var chunks int
	if err := store.readerDB.QueryRow(`SELECT count(*) FROM body_chunks WHERE audit_id = 'count-unified'`).Scan(&chunks); err != nil || chunks != 2 {
		t.Fatalf("unified chunks = %d, %v", chunks, err)
	}
}
