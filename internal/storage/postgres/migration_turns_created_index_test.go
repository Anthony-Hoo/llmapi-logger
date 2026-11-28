package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// These tests need a real PostgreSQL (TEST_DATABASE_URL) and skip otherwise.

// rollbackToSchemaFiveSQL is the rollback documented in
// doc/deployment/postgresql-migration.md for returning to a binary that only
// understands schema version 5. The tests run it verbatim.
const rollbackToSchemaFiveSQL = `
BEGIN;
DROP INDEX IF EXISTS turns_created_idx;
DELETE FROM schema_migrations WHERE version = 6;
COMMIT;
`

// turnsCreatedIndexes lists the indexes on turns whose key is exactly
// (created_at_ns, turn_id), by name.
func turnsCreatedIndexes(t *testing.T, db rowQueryer) []string {
	t.Helper()
	// The indexes of this schema's turns are selected before their
	// definitions are rendered: pg_indexes may render the definition of an
	// index in another schema, which fails with "could not open relation"
	// when a concurrent test drops that schema meanwhile.
	rows, err := db.QueryContext(context.Background(), `
WITH own AS MATERIALIZED (
    SELECT x.indexrelid, c.relname
    FROM pg_index AS x JOIN pg_class AS c ON c.oid = x.indexrelid
    WHERE x.indrelid = to_regclass('turns')
)
SELECT relname FROM own
WHERE pg_get_indexdef(indexrelid) LIKE '%(created_at_ns, turn_id)'
ORDER BY relname`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return names
}

func requireTurnsCreatedIndex(t *testing.T, db rowQueryer, present bool) {
	t.Helper()
	names := turnsCreatedIndexes(t, db)
	if present && !slices.Equal(names, []string{"turns_created_idx"}) {
		t.Fatalf("indexes on turns (created_at_ns, turn_id) = %v, want [turns_created_idx]", names)
	}
	if !present && len(names) != 0 {
		t.Fatalf("indexes on turns (created_at_ns, turn_id) = %v, want none", names)
	}
}

func TestFreshStoreEndsAtVersionSixWithTurnsCreatedIndex(t *testing.T) {
	store, _ := openTestStore(t)
	requireVersions(t, appliedSchemaVersions(t, store.readerDB), 1, 2, 3, 4, 5, 6, 7, 8)
	requireTurnsCreatedIndex(t, store.readerDB, true)
}

func TestMigrationSixUpgradesVersionFiveDatabase(t *testing.T) {
	ctx := context.Background()
	store, dsn := openTestStore(t)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()

	// The documented rollbacks, 007 and then 006, leave exactly the version 5
	// state, which a binary that understands version 5 accepts.
	for _, rollback := range []string{rollbackToSchemaSevenSQL, rollbackToSchemaSixSQL, rollbackToSchemaFiveSQL} {
		if _, err := admin.ExecContext(ctx, rollback); err != nil {
			t.Fatalf("documented rollback SQL: %v", err)
		}
	}
	versions := appliedSchemaVersions(t, admin)
	requireVersions(t, versions, 1, 2, 3, 4, 5)
	requireTurnsCreatedIndex(t, admin, false)
	if err := requireSupportedSchema(versions[len(versions)-1], 5); err != nil {
		t.Fatalf("a version 5 binary rejects the rolled-back database: %v", err)
	}

	upgraded, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open version 5 database: %v", err)
	}
	if err := upgraded.Close(); err != nil {
		t.Fatal(err)
	}
	requireVersions(t, appliedSchemaVersions(t, admin), 1, 2, 3, 4, 5, 6, 7, 8)
	requireTurnsCreatedIndex(t, admin, true)

	// A version 5 database on which an operator built the index beforehand,
	// as the deployment document describes for large tables. The document
	// builds it CONCURRENTLY; that leaves the same catalog entry, but here it
	// waits on every transaction in the shared test database and fails when a
	// parallel test drops its schema meanwhile, so the test builds it plainly.
	for _, rollback := range []string{rollbackToSchemaSevenSQL, rollbackToSchemaSixSQL, rollbackToSchemaFiveSQL} {
		if _, err := admin.ExecContext(ctx, rollback); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admin.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS turns_created_idx ON turns(created_at_ns, turn_id)`); err != nil {
		t.Fatal(err)
	}
	upgraded, err = Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open version 5 database with the index built by hand: %v", err)
	}
	if err := upgraded.Close(); err != nil {
		t.Fatal(err)
	}
	requireVersions(t, appliedSchemaVersions(t, admin), 1, 2, 3, 4, 5, 6, 7, 8)
	requireTurnsCreatedIndex(t, admin, true)
}

func TestMigrationSixIsIdempotent(t *testing.T) {
	ctx := context.Background()
	store, dsn := openTestStore(t)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	body, err := migrationFiles.ReadFile("migrations/006_turns_created_idx.sql")
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := admin.ExecContext(ctx, string(body)); err != nil {
			t.Fatalf("re-running migration 6 (attempt %d): %v", attempt, err)
		}
	}
	for attempt := 0; attempt < 2; attempt++ {
		reopened, err := Open(ctx, dsn)
		if err != nil {
			t.Fatalf("reopen %d: %v", attempt, err)
		}
		if err := reopened.Close(); err != nil {
			t.Fatal(err)
		}
	}
	requireVersions(t, appliedSchemaVersions(t, admin), 1, 2, 3, 4, 5, 6, 7, 8)
	requireTurnsCreatedIndex(t, admin, true)
}

// The protocol-wide candidate search orders by (created_at_ns DESC, turn_id
// DESC). turn_id is the primary key, so the order is total and the 32 rows
// are fixed by the data alone; walking turns_created_idx backwards yields the
// same order. This checks it on timestamps shared by several turns of
// different conversations and protocols, with turn ids unrelated to insertion
// order: the rows of the writer's per-protocol statement, with the index
// forced and as planned, equal the rows of the parameterised statement with
// no index, for every cut-off, including one equal to a shared timestamp.
func TestKeylessCandidatesAreTheSameWithTurnsCreatedIndex(t *testing.T) {
	ctx := context.Background()
	store, _ := openTestStore(t)
	protocols := []string{"openai", "anthropic", "gemini"}
	var ids, conversations []string
	var created []int64
	conversationProtocol := map[string]string{}
	for index := 0; index < 600; index++ {
		digest := sha256.Sum256([]byte(fmt.Sprint("tie", index)))
		ids = append(ids, "tie-"+hex.EncodeToString(digest[:6]))
		conversation := fmt.Sprintf("conv_tie_%03d", index%40)
		conversations = append(conversations, conversation)
		conversationProtocol[conversation] = protocols[(index%40)%len(protocols)]
		// Groups of nine turns share a timestamp.
		created = append(created, int64(1_000_000_000)+int64(index/9)*1000)
	}
	var conversationIDs, conversationProtocols []string
	for conversation, protocol := range conversationProtocol {
		conversationIDs = append(conversationIDs, conversation)
		conversationProtocols = append(conversationProtocols, protocol)
	}
	protocolOf := make([]string, len(ids))
	for index, conversation := range conversations {
		protocolOf[index] = conversationProtocol[conversation]
	}
	seed := []struct {
		query     string
		arguments []any
	}{
		{`INSERT INTO content_objects (object_hash, semantic_hash, kind, compression, plaintext_length, encoded_length, data_enc, created_at_ns)
VALUES (decode(repeat('11', 32), 'hex'), decode(repeat('22', 32), 'hex'), 'request_envelope', 'none', 1, 1, '\x5a'::bytea, 1)`, nil},
		{`INSERT INTO audit_records (audit_id, started_at_ns, ended_at_ns, route_id, protocol, parser_name, method, path,
    request_uri_enc, mode, forward_status, capture_status, parse_status)
SELECT id, s, s + 1, 'route', p, 'parser', 'POST', '/v1/test', '\x01'::bytea, 'available', 'completed', 'complete', 'ok'
FROM unnest($1::text[], $2::bigint[], $3::text[]) AS u(id, s, p)`, []any{ids, created, protocolOf}},
		{`INSERT INTO conversations (conversation_id, protocol, key_hash, created_at_ns, updated_at_ns)
SELECT id, p, NULL, 1, 1 FROM unnest($1::text[], $2::text[]) AS u(id, p)`, []any{conversationIDs, conversationProtocols}},
		{`INSERT INTO turns (turn_id, audit_id, conversation_id, parent_turn_id, parent_base, link_reason, link_confidence,
    request_layout, response_layout, request_envelope_hash, response_envelope_hash,
    request_item_count, response_item_count, request_sequence_hash, response_sequence_hash,
    request_reconstruction_hash, response_reconstruction_hash, reconstruction_status, response_id, created_at_ns)
SELECT id, id, c, NULL, 'root', 'root', 95, 'marker_envelope', 'marker_envelope',
    decode(repeat('11', 32), 'hex'), decode(repeat('11', 32), 'hex'), 1, 1,
    sha256(id::bytea), sha256(id::bytea), sha256(id::bytea), sha256(id::bytea), 'verified', NULL, s
FROM unnest($1::text[], $2::text[], $3::bigint[]) AS u(id, c, s)`, []any{ids, conversations, created}},
		{`ANALYZE turns`, nil},
		{`ANALYZE conversations`, nil},
	}
	for _, statement := range seed {
		if _, err := store.writerConn.ExecContext(ctx, statement.query, statement.arguments...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	// today runs the parameterised statement with the index dropped, as before
	// migration 006; forced runs the writer's per-protocol statement with
	// everything but the index walk priced out; chosen runs it as planned.
	candidates := func(mode, protocol string, before int64) []string {
		t.Helper()
		transaction, err := store.writerConn.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer transaction.Rollback()
		var settings []string
		switch mode {
		case "today":
			settings = []string{`DROP INDEX turns_created_idx`}
		case "forced":
			settings = []string{`SET LOCAL enable_seqscan = off`, `SET LOCAL enable_sort = off`, `SET LOCAL enable_bitmapscan = off`}
		}
		for _, setting := range settings {
			if _, err := transaction.ExecContext(ctx, setting); err != nil {
				t.Fatal(err)
			}
		}
		var found []turnCandidate
		if mode == "today" {
			found, err = listTurnCandidates(transaction, keylessCandidateQuery, protocol, before, parentCandidateLimit)
		} else {
			var document string
			if err := transaction.QueryRowContext(ctx, `EXPLAIN (FORMAT JSON) `+keylessCandidateQueries[protocol], before, parentCandidateLimit).Scan(&document); err != nil {
				t.Fatal(err)
			}
			if mode == "forced" && !strings.Contains(document, `"turns_created_idx"`) {
				t.Fatalf("forced plan does not walk turns_created_idx: %s", document)
			}
			found, err = listKeylessCandidates(transaction, protocol, before)
		}
		if err != nil {
			t.Fatal(err)
		}
		var result []string
		for _, candidate := range found {
			result = append(result, candidate.turnID+"/"+candidate.conversationID)
		}
		return result
	}
	cutoffs := []int64{created[len(created)-1] + 1, created[300], created[300] + 1, created[40]}
	for _, protocol := range protocols {
		for _, before := range cutoffs {
			today := candidates("today", protocol, before)
			for _, mode := range []string{"forced", "chosen"} {
				if now := candidates(mode, protocol, before); len(today) == 0 || !slices.Equal(today, now) {
					t.Fatalf("%s before %d: candidates before migration 006 %v, now (%s) %v", protocol, before, today, mode, now)
				}
			}
		}
	}
}
