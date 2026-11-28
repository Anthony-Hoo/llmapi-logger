package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"testing"
)

// These tests need a real PostgreSQL (TEST_DATABASE_URL) and skip otherwise.

func stampOf(t *testing.T, store *Store, auditID string) [32]byte {
	t.Helper()
	var stamp [32]byte
	copy(stamp[:], archiveStampOf(t, store, auditID))
	return stamp
}

// The stamp preimage, rebuilt by hand from the M.1 definition: the domain,
// then for each table in M.1's order the table name and row count, and for
// each row in primary key order (C collation: stage names sort by their
// bytes) the length-prefixed key encoding and xmin.
func TestArchiveChangeStampPreimage(t *testing.T) {
	ctx := context.Background()
	store, _ := openTestStore(t)
	ended := int64(20)
	insertRetentionAudit(t, store, "stamp-shape", 10, &ended, ParseOK, true)
	if _, err := store.writerConn.ExecContext(ctx, `
INSERT INTO http_stages (audit_id, stage, state, proto, method, host, started_at_ns)
VALUES ('stamp-shape', 'request_sent_to_newapi', 'complete', 'HTTP/1.1', 'POST', 'newapi.local', 11)`); err != nil {
		t.Fatal(err)
	}
	xmin := func(table, where string) int64 {
		var value int64
		if err := store.readerDB.QueryRow(`SELECT xmin::text::bigint FROM ` + table + ` WHERE ` + where).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	b := func(value []byte) []byte {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		return append(length[:], value...)
	}
	text := func(value string) []byte { return b([]byte(value)) }
	integer := func(value int64) []byte {
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], uint64(value))
		return b(encoded[:])
	}
	join := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	table := func(name string, rows ...[]byte) []byte {
		return join(append([][]byte{text(name), integer(int64(len(rows)))}, rows...)...)
	}
	row := func(key []byte, xmin int64) []byte { return join(b(key), integer(xmin)) }
	received, sent := StageRequestReceived, StageRequestSent
	want := join([]byte("llmapi-logger/archive-change-stamp/v1\x00"),
		table("audit_records", row(text("stamp-shape"), xmin("audit_records", "audit_id = 'stamp-shape'"))),
		// "request_for_newapi_received_from_nginx" < "request_sent_to_newapi"
		table("http_stages",
			row(join(text("stamp-shape"), text(received)), xmin("http_stages", "stage = '"+received+"'")),
			row(join(text("stamp-shape"), text(sent)), xmin("http_stages", "stage = '"+sent+"'"))),
		table("http_headers", row(join(text("stamp-shape"), text(received), text("header"), text("x-test"), integer(0)), xmin("http_headers", "true"))),
		table("http_header_blocks"),
		table("body_streams", row(join(text("stamp-shape"), text(received)), xmin("body_streams", "true"))),
		table("body_chunks", row(join(text("stamp-shape"), text(received), integer(0)), xmin("body_chunks", "true"))),
		table("stream_timelines"),
		table("parsed_results", row(text("stamp-shape"), xmin("parsed_results", "true"))),
		table("token_links", row(text("stamp-shape"), xmin("token_links", "true"))),
		table("audit_project_identity"),
		table("integrity_events"),
		table("turns"),
		table("turn_context_ops"),
		table("turn_response_items"),
	)
	transaction, err := store.readerDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	var got bytes.Buffer
	exists, err := writeArchiveChangeStampInput(ctx, transaction, "stamp-shape", &got)
	if err != nil || !exists {
		t.Fatalf("stamp input: exists %v, %v", exists, err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("stamp preimage differs from M.1:\n got %x\nwant %x", got.Bytes(), want)
	}
	stamp, _, err := archiveChangeStamp(ctx, transaction, "stamp-shape")
	if err != nil || stamp != sha256.Sum256(want) {
		t.Fatalf("stamp is not SHA-256 of the preimage: %v", err)
	}
	// An audit that does not exist has the stamp of empty row sets.
	if _, exists, err := archiveChangeStamp(ctx, transaction, "stamp-missing"); err != nil || exists {
		t.Fatalf("missing audit: exists %v, %v", exists, err)
	}
}

// The stamp is unchanged by reading and by VACUUM (FREEZE) and VACUUM FULL,
// and by writes that touch only other audits, the shared content objects or
// conversations.updated_at_ns. It changes with each write of M.1 rows 1 to 3
// and with an inserted or deleted row in any per-audit table.
func TestArchiveChangeStampTracksEveryWriteToTheAudit(t *testing.T) {
	ctx := context.Background()
	store, dsn := openTestStore(t)
	cipher := graphTestCipher(t)
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	exec := func(statement string, arguments ...any) {
		t.Helper()
		if _, err := admin.ExecContext(ctx, statement, arguments...); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}

	// A parent turn and its child (the member), and an unrelated audit.
	saveGraphTestTurn(t, store, cipher, "stamp-parent", "", "stamp-response-parent", 100,
		[]graphTestItem{userItem("parent question")}, []graphTestItem{assistantItem("parent answer")})
	saveGraphTestTurn(t, store, cipher, "stamp-member", "stamp-response-parent", "stamp-response-member", 200,
		[]graphTestItem{userItem("parent question"), assistantItem("parent answer"), userItem("member question")},
		[]graphTestItem{assistantItem("member answer")})
	ended := int64(301)
	insertRetentionAudit(t, store, "stamp-other", 300, &ended, ParseOK, true)
	exec(`UPDATE audit_records SET newapi_request_id = 'stamp-member-request', caller_status = 'resolved',
	      caller_attempts = 1, caller_updated_at_ns = 5 WHERE audit_id = 'stamp-member'`)
	exec(`INSERT INTO token_links (audit_id, newapi_user_id, username, newapi_token_id, token_name, linked_at_ns)
	      VALUES ('stamp-member', 1, 'owner', 1, 'personal', 5)`)

	base := stampOf(t, store, "stamp-member")
	if again := stampOf(t, store, "stamp-member"); again != base {
		t.Fatal("re-reading changed the stamp")
	}
	unchanged := func(label string) {
		t.Helper()
		if stampOf(t, store, "stamp-member") != base {
			t.Fatalf("%s changed the stamp", label)
		}
	}
	changed := func(label string) {
		t.Helper()
		next := stampOf(t, store, "stamp-member")
		if next == base {
			t.Fatalf("%s left the stamp unchanged", label)
		}
		base = next
	}

	// VACUUM (FREEZE) must have frozen the rows for the assertion to mean
	// anything: relfrozenxid advances only when no older row version is left.
	var frozenBefore, frozenAfter string
	if err := admin.QueryRow(`SELECT relfrozenxid::text FROM pg_class WHERE oid = to_regclass('audit_records')`).Scan(&frozenBefore); err != nil {
		t.Fatal(err)
	}
	exec(`VACUUM (FREEZE, DISABLE_PAGE_SKIPPING) audit_records, turns, token_links, turn_context_ops, turn_response_items`)
	if err := admin.QueryRow(`SELECT relfrozenxid::text FROM pg_class WHERE oid = to_regclass('audit_records')`).Scan(&frozenAfter); err != nil {
		t.Fatal(err)
	}
	if frozenAfter == frozenBefore {
		t.Fatalf("VACUUM (FREEZE) did not advance relfrozenxid (%s): an older snapshot holds the rows back", frozenBefore)
	}
	unchanged("VACUUM (FREEZE)")
	before := relationFiles(t, admin, "audit_records", "turns")
	exec(`VACUUM FULL audit_records, turns, token_links, turn_context_ops, turn_response_items`)
	if after := relationFiles(t, admin, "audit_records", "turns"); after[0] == before[0] || after[1] == before[1] {
		t.Fatal("VACUUM FULL did not rewrite the tables")
	}
	unchanged("VACUUM FULL")

	// Writes that do not touch the member's rows.
	exec(`INSERT INTO http_stages (audit_id, stage, state, proto, method, host, started_at_ns)
	      VALUES ('stamp-other', 'request_sent_to_newapi', 'complete', 'HTTP/1.1', 'POST', 'newapi.local', 1)`)
	exec(`UPDATE audit_records SET parse_save_failures = parse_save_failures + 1 WHERE audit_id = 'stamp-other'`)
	exec(`UPDATE conversations SET updated_at_ns = updated_at_ns + 1000
	      WHERE conversation_id = (SELECT conversation_id FROM turns WHERE audit_id = 'stamp-member')`)
	exec(`UPDATE content_objects SET created_at_ns = created_at_ns + 1`)
	exec(`INSERT INTO content_objects (object_hash, semantic_hash, kind, compression, plaintext_length, encoded_length, data_enc, created_at_ns)
	      VALUES (decode(repeat('ab', 32), 'hex'), decode(repeat('ab', 32), 'hex'), 'user_message', 'none', 1, 1, '\x01', 1)
	      ON CONFLICT DO NOTHING`)
	unchanged("writes to other audits, shared objects and conversations.updated_at_ns")

	// M.1 row 1: the billing backfill rewrites the token link in place.
	quota, prompt, completion, perUnit := int64(10), int64(3), int64(4), 500000.0
	if err := store.UpdateTokenLinkBilling(ctx, BillingUpdate{AuditID: "stamp-member", State: BillingBilled, Attempts: 1,
		Quota: &quota, QuotaPerUnit: &perUnit, BilledPromptTokens: &prompt, BilledCompletionTokens: &completion}); err != nil {
		t.Fatal(err)
	}
	changed("the billing backfill (M.1 row 1)")
	// M.1 row 2: the project identity is inserted, then rewritten by a newer
	// identity version.
	identity := identityTestRow("stamp-member")
	if err := store.SaveProjectIdentity(ctx, identity); err != nil {
		t.Fatal(err)
	}
	changed("the project identity insert (M.1 row 2)")
	identity.Version = 2
	if err := store.SaveProjectIdentity(ctx, identity); err != nil {
		t.Fatal(err)
	}
	changed("the project identity upgrade (M.1 row 2)")
	// M.1 row 3: retention removes the parent; checkpointRetainedChildren
	// rewrites the member's lineage and context operations.
	result, err := store.DeleteExpired(ctx, 150, 10, 0)
	if err != nil || result.DeletedAudits != 1 {
		t.Fatalf("delete parent = %+v, %v", result, err)
	}
	var reason string
	if err := admin.QueryRow(`SELECT link_reason FROM turns WHERE audit_id = 'stamp-member'`).Scan(&reason); err != nil || reason != "retention_checkpoint" {
		t.Fatalf("member link reason = %q, %v", reason, err)
	}
	changed("checkpointRetainedChildren after the parent was deleted (M.1 row 3)")

	// An inserted and a deleted row in every per-audit table.
	inserts := map[string]string{
		"http_stages": `INSERT INTO http_stages (audit_id, stage, state, proto, method, host, started_at_ns)
		                VALUES ('stamp-member', 'response_received_from_newapi', 'complete', 'HTTP/1.1', 'POST', 'newapi.local', 1)`,
		"http_headers": `INSERT INTO http_headers (audit_id, stage, kind, name, value_index, value_length, value_enc)
		                 VALUES ('stamp-member', 'response_received_from_newapi', 'header', 'x-probe', 0, 1, '\x01')`,
		"http_header_blocks": `INSERT INTO http_header_blocks (audit_id, compression, plaintext_length, block_enc) VALUES ('stamp-member', 'none', 1, '\x01')`,
		"body_streams": `INSERT INTO body_streams (audit_id, stage, source_stage, observed_length, stored_length, hash_complete, eof_seen, state, retention_state)
		                 VALUES ('stamp-member', 'response_received_from_newapi', 'response_received_from_newapi', 1, 1, 0, 0, 'partial', 'full')`,
		"body_chunks": `INSERT INTO body_chunks (audit_id, stage, seq, "offset", plaintext_length, encoded_length, observed_at_ns, compression, data_enc)
		                VALUES ('stamp-member', 'response_received_from_newapi', 0, 0, 1, 1, 1, 'none', '\x01')`,
		"stream_timelines": `INSERT INTO stream_timelines (audit_id, stage, event_count, timeline_complete, compression, plaintext_length)
		                     VALUES ('stamp-member', 'response_received_from_newapi', 0, 1, 'none', 0)`,
		"integrity_events": `INSERT INTO integrity_events (audit_id, event_type, payload_digest, event_mac, created_at_ns)
		                     VALUES ('stamp-member', 'reconstruction_failed', decode(repeat('01', 32), 'hex'), decode(repeat('02', 32), 'hex'), 1)`,
		"turn_context_ops": `INSERT INTO turn_context_ops (turn_id, op_index, operation, item_count)
		                     SELECT turn_id, 1000, 'retain', 1 FROM turns WHERE audit_id = 'stamp-member'`,
		"turn_response_items": `INSERT INTO turn_response_items (turn_id, ordinal, slot, object_hash, semantic_hash)
		                        SELECT turn_id, 1000, 'probe', decode(repeat('ab', 32), 'hex'), decode(repeat('ab', 32), 'hex') FROM turns WHERE audit_id = 'stamp-member'`,
	}
	for _, table := range archiveStampTables {
		statement, ok := inserts[table.name]
		if !ok {
			continue
		}
		exec(statement)
		changed("an inserted " + table.name + " row")
	}
	for _, table := range []string{"turn_response_items", "turn_context_ops"} {
		exec(`DELETE FROM ` + table + ` WHERE turn_id = (SELECT turn_id FROM turns WHERE audit_id = 'stamp-member') AND ` +
			map[string]string{"turn_response_items": "ordinal = 1000", "turn_context_ops": "op_index = 1000"}[table])
		changed("a deleted " + table + " row")
	}
	for _, table := range []string{"integrity_events", "stream_timelines", "body_chunks", "http_headers", "http_header_blocks",
		"audit_project_identity", "token_links", "parsed_results"} {
		exec(`DELETE FROM `+table+` WHERE audit_id = $1`, "stamp-member")
		changed("a deleted " + table + " row")
	}
	exec(`DELETE FROM body_streams WHERE audit_id = 'stamp-member'`)
	changed("a deleted body_streams row")
	exec(`DELETE FROM http_stages WHERE audit_id = 'stamp-member' AND stage = 'response_received_from_newapi'`)
	changed("a deleted http_stages row")
	exec(`UPDATE audit_records SET parse_save_failures = parse_save_failures WHERE audit_id = 'stamp-member'`)
	changed("an UPDATE that writes the same values")
	exec(`DELETE FROM turns WHERE audit_id = 'stamp-member'`)
	changed("a deleted turns row")
	exec(`SELECT 1 FROM audit_records WHERE audit_id = 'stamp-member' FOR UPDATE`)
	unchanged("SELECT ... FOR UPDATE")
	if got := stampOf(t, store, "stamp-other"); got == ([32]byte{}) {
		t.Fatal("other audit has no stamp")
	}
	var deleted int
	if err := admin.QueryRow(`SELECT COUNT(*) FROM audit_records WHERE audit_id = 'stamp-parent'`).Scan(&deleted); err != nil || deleted != 0 {
		t.Fatalf("parent still present: %d, %v", deleted, err)
	}
}
