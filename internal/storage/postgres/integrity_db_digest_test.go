package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"testing"

	"llmapi-logger/internal/security"
)

// recordingTx records every statement a digest path sends, so a test can show
// which columns travel back to the process and how many round trips it costs.
type recordingTx struct {
	dbTransaction
	queries []string
}

func (recorder *recordingTx) Exec(query string, args ...any) (sql.Result, error) {
	recorder.queries = append(recorder.queries, query)
	return recorder.dbTransaction.Exec(query, args...)
}

func (recorder *recordingTx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	recorder.queries = append(recorder.queries, query)
	return recorder.dbTransaction.ExecContext(ctx, query, args...)
}

func (recorder *recordingTx) Query(query string, args ...any) (*sql.Rows, error) {
	recorder.queries = append(recorder.queries, query)
	return recorder.dbTransaction.Query(query, args...)
}

func (recorder *recordingTx) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	recorder.queries = append(recorder.queries, query)
	return recorder.dbTransaction.QueryContext(ctx, query, args...)
}

func (recorder *recordingTx) QueryRow(query string, args ...any) *sql.Row {
	recorder.queries = append(recorder.queries, query)
	return recorder.dbTransaction.QueryRow(query, args...)
}

func (recorder *recordingTx) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	recorder.queries = append(recorder.queries, query)
	return recorder.dbTransaction.QueryRowContext(ctx, query, args...)
}

var (
	ciphertextHashExpression = regexp.MustCompile(`CASE WHEN octet_length\(([a-z_.]+)\) > 0 THEN sha256\(([a-z_.]+)\) END`)
	ciphertextColumn         = regexp.MustCompile(`\b(data_enc|timeline_enc|parsed_json_enc|value_enc|request_uri_enc|user_agent_enc|block_enc)\b`)
)

// rawCiphertextColumns returns the ciphertext columns a statement would hand
// back as stored, after discarding the ones it only hashes in the database.
func rawCiphertextColumns(query string) []string {
	stripped := ciphertextHashExpression.ReplaceAllStringFunc(query, func(match string) string {
		parts := ciphertextHashExpression.FindStringSubmatch(match)
		if parts[1] != parts[2] {
			return match
		}
		return ""
	})
	return ciphertextColumn.FindAllString(stripped, -1)
}

type digestTarget struct {
	AuditID   string
	EventType string
}

// insertDigestCapture writes the capture rows of one terminal audit directly:
// two stages with several header values, a body stream for each, and an
// optional stream timeline on the response stage whose ciphertext may be NULL.
// Ciphertext columns hold synthetic bytes; nothing on these paths decrypts them.
func insertDigestCapture(t *testing.T, store *Store, auditID string, startedAt int64, parseStatus string, timelineRow bool, timeline []byte) {
	t.Helper()
	transaction, err := store.writerConn.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	execute := func(query string, args ...any) {
		t.Helper()
		if _, err := transaction.Exec(query, args...); err != nil {
			t.Fatalf("%s: %v", auditID, err)
		}
	}
	execute(`
INSERT INTO audit_records (
    audit_id, started_at_ns, ended_at_ns, route_id, protocol, parser_name,
    method, path, request_uri_enc, mode, status_code, ttft_ns,
    forward_status, capture_status, parse_status
) VALUES ($1, $2, $3, 'route', 'openai', 'parser', 'POST', '/v1/test', $4,
          'available', 200, 7, 'completed', 'complete', $5)`,
		auditID, startedAt, startedAt+1, []byte("uri-ciphertext-"+auditID), parseStatus)
	for _, stage := range []string{StageRequestReceived, StageResponseReceived} {
		execute(`
INSERT INTO http_stages (
    audit_id, stage, state, proto, method, host, status_code, started_at_ns, ended_at_ns
) VALUES ($1, $2, 'complete', 'HTTP/1.1', 'POST', 'upstream.example.com', 200, $3, $4)`,
			auditID, stage, startedAt, startedAt+1)
		execute(`
INSERT INTO body_streams (
    audit_id, stage, source_stage, observed_length, stored_length, sha256,
    hash_complete, eof_seen, state, retention_state, stream_event_count
) VALUES ($1, $2, $2, 64, 64, $3, 1, 1, 'complete', 'full', 3)`,
			auditID, stage, bytes.Repeat([]byte{0x44}, 32))
	}
	for _, header := range []struct {
		stage, kind, name string
		index             int
	}{
		{StageRequestReceived, "header", "authorization", 0},
		{StageRequestReceived, "header", "x-trace", 0},
		{StageRequestReceived, "header", "x-trace", 1},
		{StageResponseReceived, "header", "content-type", 0},
		{StageResponseReceived, "trailer", "x-done", 0},
	} {
		value := []byte(fmt.Sprintf("header-ciphertext-%s-%s-%d-%s", header.stage, header.name, header.index, auditID))
		execute(`
INSERT INTO http_headers (audit_id, stage, kind, name, value_index, value_length, value_enc)
VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			auditID, header.stage, header.kind, header.name, header.index, len(value), value)
	}
	if timelineRow {
		execute(`
INSERT INTO stream_timelines (
    audit_id, stage, event_count, first_event_at_ns, last_event_at_ns,
    timeline_complete, compression, plaintext_length, timeline_enc
) VALUES ($1, $2, 3, $3, $4, 1, 'gzip', 512, $5)`,
			auditID, StageResponseReceived, startedAt, startedAt+1, nullableBytes(timeline))
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
}

// buildDigestFixture writes audits that between them reach every ciphertext
// column a payload digest covers, without integrity enabled, and returns the
// events they need in the order a writer would append them.
//
//   - turn 1: content objects, two binary objects (one stored gzip), a binary
//     reference and an external file reference, a stream timeline and a parsed
//     result ciphertext;
//   - turn 2: continues turn 1, reusing its objects and binaries, with a
//     timeline row whose ciphertext is NULL and no parsed result ciphertext;
//   - a reconstruction failure with a parsed result ciphertext and no timeline;
//   - a capture-only audit;
//   - two capture version 2 audits, one with a User-Agent and a header block,
//     one with neither (insertDigestCaptureV2).
func buildDigestFixture(t *testing.T, store *Store, cipher security.Cipher) []digestTarget {
	t.Helper()
	ctx := context.Background()
	request, response := graphObjectFixture()
	request = append(request, graphItem("file", map[string]any{"file_id": "file-example"}))

	insertDigestCapture(t, store, "digest-turn-1", 100, ParseProcessing, true, []byte("timeline-ciphertext-one"))
	first := prepareGraphTestTurn(t, cipher, "digest-turn-1", "", "response-digest-1", 100, request, response)
	if err := store.SaveParsedAudit(ctx, ParsedAudit{
		Result: ParsedResult{
			AuditID: "digest-turn-1", ParserName: "parser", ParserVersion: "2", Status: ParseOK,
			ParsedJSONEnc: []byte("parsed-ciphertext-one"), ParsedAtNS: 103,
		},
		Turn: &first,
	}); err != nil {
		t.Fatalf("save first turn: %v", err)
	}

	followUp := graphItem("user_message", map[string]any{"role": "user", "content": "follow-up question"})
	secondRequest := append(append(append([]graphTestItem{}, request...), response...), followUp)
	secondResponse := []graphTestItem{graphItem("assistant_message", map[string]any{"role": "assistant", "content": "follow-up answer"})}
	insertDigestCapture(t, store, "digest-turn-2", 200, ParseProcessing, true, nil)
	second := prepareGraphTestTurn(t, cipher, "digest-turn-2", "response-digest-1", "response-digest-2", 200, secondRequest, secondResponse)
	if err := store.SaveParsedAudit(ctx, ParsedAudit{
		Result: ParsedResult{AuditID: "digest-turn-2", ParserName: "parser", ParserVersion: "2", Status: ParseOK, ParsedAtNS: 203},
		Turn:   &second,
	}); err != nil {
		t.Fatalf("save second turn: %v", err)
	}

	insertDigestCapture(t, store, "digest-failed", 300, ParseProcessing, false, nil)
	failure := "reconstruction_failed"
	if err := store.SaveParsedAudit(ctx, ParsedAudit{Result: ParsedResult{
		AuditID: "digest-failed", ParserName: "parser", ParserVersion: "2", Status: ParseError,
		ErrorCode: &failure, ParsedJSONEnc: []byte("parsed-ciphertext-failed"), ParsedAtNS: 303,
	}}); err != nil {
		t.Fatalf("save reconstruction failure: %v", err)
	}

	insertDigestCapture(t, store, "digest-capture", 400, ParseError, false, nil)
	insertDigestCaptureV2(t, store, "digest-capture-v2", 500, true)
	insertDigestCaptureV2(t, store, "digest-capture-v2-bare", 600, false)

	var conversations, linked, binaries, binaryRefs, externalRefs int
	if err := store.readerDB.QueryRow(`
SELECT (SELECT COUNT(DISTINCT conversation_id) FROM turns),
       (SELECT COUNT(parent_turn_id) FROM turns),
       (SELECT COUNT(*) FROM binary_objects),
       (SELECT COUNT(*) FROM content_binary_refs),
       (SELECT COUNT(*) FROM content_external_refs)`).Scan(&conversations, &linked, &binaries, &binaryRefs, &externalRefs); err != nil {
		t.Fatal(err)
	}
	if conversations != 1 || linked != 1 || binaries < 2 || binaryRefs < 2 || externalRefs < 1 {
		t.Fatalf("fixture: conversations=%d linked=%d binaries=%d binary refs=%d external refs=%d", conversations, linked, binaries, binaryRefs, externalRefs)
	}
	return []digestTarget{
		{"digest-turn-1", integrityCaptureFinalized},
		{"digest-turn-1", integritySemanticCompacted},
		{"digest-turn-2", integrityCaptureFinalized},
		{"digest-turn-2", integritySemanticCompacted},
		{"digest-failed", integrityCaptureFinalized},
		{"digest-failed", integrityReconstructionFailed},
		{"digest-capture", integrityCaptureFinalized},
		{"digest-capture-v2", integrityCaptureFinalized},
		{"digest-capture-v2-bare", integrityCaptureFinalized},
	}
}

// emptyDigestFixtureCiphertext rewrites one row of every ciphertext column to
// zero length, and the nullable ones to NULL as well, so both spellings of an
// absent ciphertext reach the digests.
func emptyDigestFixtureCiphertext(t *testing.T, store *Store) {
	t.Helper()
	for _, statement := range []string{
		`UPDATE audit_records SET request_uri_enc = ''::bytea WHERE audit_id = 'digest-turn-2'`,
		`UPDATE http_headers SET value_enc = ''::bytea WHERE audit_id = 'digest-turn-1' AND name = 'x-trace' AND value_index = 1`,
		`UPDATE content_objects SET data_enc = ''::bytea WHERE object_hash = (SELECT object_hash FROM content_objects WHERE kind = 'user_message' ORDER BY object_hash LIMIT 1)`,
		`UPDATE binary_objects SET data_enc = ''::bytea WHERE binary_hash = (SELECT binary_hash FROM binary_objects ORDER BY binary_hash LIMIT 1)`,
		`UPDATE content_external_refs SET value_enc = ''::bytea`,
		`UPDATE stream_timelines SET timeline_enc = ''::bytea WHERE audit_id = 'digest-turn-1'`,
		`UPDATE parsed_results SET parsed_json_enc = ''::bytea WHERE audit_id = 'digest-turn-1'`,
		`UPDATE parsed_results SET parsed_json_enc = NULL WHERE audit_id = 'digest-failed'`,
		`UPDATE audit_records SET user_agent_enc = ''::bytea WHERE audit_id = 'digest-capture-v2'`,
		`UPDATE http_header_blocks SET block_enc = ''::bytea WHERE audit_id = 'digest-capture-v2'`,
	} {
		result, err := store.writerConn.ExecContext(context.Background(), statement)
		if err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
		if affected, err := result.RowsAffected(); err != nil || affected == 0 {
			t.Fatalf("%s affected %d rows: %v", statement, affected, err)
		}
	}
}

// compareDigestImplementations derives every target's digest with the
// reference and with production code inside one snapshot, both with a cache
// shared across the targets and production also with a single-use cache, and
// requires equal bytes and equal statement counts. Production statements must
// not return any ciphertext column as stored.
func compareDigestImplementations(t *testing.T, store *Store, targets []digestTarget) map[digestTarget][]byte {
	t.Helper()
	ctx := context.Background()
	transaction, err := store.readerDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	reference := &recordingTx{dbTransaction: transaction}
	production := &recordingTx{dbTransaction: transaction}
	// Separate instances: a cache shared between the implementations would
	// hand the reference digests that production computed.
	referenceCache, productionCache := newIntegrityGraphCache(), newIntegrityGraphCache()
	digests := make(map[digestTarget][]byte, len(targets))
	for _, target := range targets {
		referenceBefore, productionBefore := len(reference.queries), len(production.queries)
		want, err := referenceIntegrityPayloadDigest(ctx, reference, referenceCache, target.AuditID, target.EventType)
		if err != nil {
			t.Fatalf("reference %+v: %v", target, err)
		}
		got, err := integrityPayloadDigest(ctx, production, productionCache, target.AuditID, target.EventType)
		if err != nil {
			t.Fatalf("production %+v: %v", target, err)
		}
		single, err := integrityPayloadDigest(ctx, transaction, nil, target.AuditID, target.EventType)
		if err != nil {
			t.Fatalf("production single-use %+v: %v", target, err)
		}
		if !bytes.Equal(got, want) || !bytes.Equal(single, want) {
			t.Fatalf("%+v digest = %x (single-use %x), reference %x", target, got, single, want)
		}
		referenceCount, productionCount := len(reference.queries)-referenceBefore, len(production.queries)-productionBefore
		if productionCount != referenceCount {
			t.Fatalf("%+v issued %d statements, reference %d", target, productionCount, referenceCount)
		}
		digests[target] = got
	}
	for _, query := range production.queries {
		if columns := rawCiphertextColumns(query); len(columns) != 0 {
			t.Fatalf("production digest query returns ciphertext %v:\n%s", columns, query)
		}
	}
	// The check above is only meaningful if it notices the columns the
	// reference does carry.
	seen := make(map[string]bool)
	for _, query := range reference.queries {
		for _, column := range rawCiphertextColumns(query) {
			seen[column] = true
		}
	}
	for _, column := range []string{"data_enc", "timeline_enc", "parsed_json_enc", "value_enc", "request_uri_enc", "user_agent_enc", "block_enc"} {
		if !seen[column] {
			t.Fatalf("reference never selected %s; the fixture does not reach it", column)
		}
	}
	return digests
}

func TestPayloadDigestsMatchTheInProcessHashOfCiphertext(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	targets := buildDigestFixture(t, store, graphTestCipher(t))
	stored := compareDigestImplementations(t, store, targets)

	emptyDigestFixtureCiphertext(t, store)
	emptied := compareDigestImplementations(t, store, targets)
	for _, target := range []digestTarget{
		{"digest-turn-1", integrityCaptureFinalized},
		{"digest-turn-1", integritySemanticCompacted},
		{"digest-turn-2", integrityCaptureFinalized},
		{"digest-turn-2", integritySemanticCompacted},
		{"digest-failed", integrityReconstructionFailed},
		{"digest-capture-v2", integrityCaptureFinalized},
	} {
		if bytes.Equal(stored[target], emptied[target]) {
			t.Fatalf("%+v digest did not change when its ciphertext was emptied", target)
		}
	}

	// Zero-length and NULL are both an absent field, never the hash of the
	// empty string, so the two spellings must give the same digest.
	if _, err := store.writerConn.ExecContext(context.Background(), `UPDATE parsed_results SET parsed_json_enc = NULL WHERE audit_id = 'digest-turn-1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.writerConn.ExecContext(context.Background(), `UPDATE stream_timelines SET timeline_enc = NULL WHERE audit_id = 'digest-turn-1'`); err != nil {
		t.Fatal(err)
	}
	nulled := compareDigestImplementations(t, store, targets)
	target := digestTarget{"digest-turn-1", integritySemanticCompacted}
	if !bytes.Equal(nulled[target], emptied[target]) {
		t.Fatalf("NULL ciphertext digest %x differs from zero-length digest %x", nulled[target], emptied[target])
	}
}

// signDigestFixture appends the integrity events of a fixture written without
// a signer, deriving each payload digest with the given implementation.
func signDigestFixture(t *testing.T, store *Store, signer *security.IntegritySigner, targets []digestTarget, derive func(context.Context, dbTransaction, *integrityGraphCache, string, string) ([]byte, error)) {
	t.Helper()
	ctx := context.Background()
	transaction, err := store.writerConn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	for index, target := range targets {
		digest, err := derive(ctx, transaction, nil, target.AuditID, target.EventType)
		if err != nil {
			t.Fatalf("derive %+v: %v", target, err)
		}
		if err := appendIntegrityEvent(transaction, signer, target.AuditID, target.EventType, digest, int64(1000+index)); err != nil {
			t.Fatal(err)
		}
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestEventsSignedOverInProcessDigestsStillVerify(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x19}, security.KeySize)
	signer, err := security.NewIntegritySigner(key)
	if err != nil {
		t.Fatal(err)
	}
	path := newTestDSN(t)
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	targets := buildDigestFixture(t, store, graphTestCipher(t))
	emptyDigestFixtureCiphertext(t, store)
	signDigestFixture(t, store, signer, targets, referenceIntegrityPayloadDigest)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.EnableIntegrity(ctx, key); err != nil {
		t.Fatalf("startup verification rejected events signed over in-process digests: %v", err)
	}
	if err := reopened.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatalf("payload verification rejected events signed over in-process digests: %v", err)
	}
	if state := reopened.IntegrityPayloadState(); state != "verified" {
		t.Fatalf("payload state = %q", state)
	}

	// The background pass and the import check share this transaction body;
	// run it through the recorder to show it hashes in place as well.
	transaction, err := reopened.readerDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	recorder := &recordingTx{dbTransaction: transaction}
	if err := verifyIntegrityPayloadsTransaction(ctx, recorder, schemaLive); err != nil {
		t.Fatalf("recorded payload verification: %v", err)
	}
	for _, query := range recorder.queries {
		if columns := rawCiphertextColumns(query); len(columns) != 0 {
			t.Fatalf("payload verification returns ciphertext %v:\n%s", columns, query)
		}
	}
}

func TestPayloadVerificationDetectsAFlippedCiphertextByte(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x27}, security.KeySize)
	flip := func(column string) string {
		return column + ` = set_byte(` + column + `, 0, get_byte(` + column + `, 0) # 1)`
	}
	for _, test := range []struct {
		name   string
		mutate string
	}{
		{"content object", `UPDATE content_objects SET ` + flip("data_enc") + ` WHERE object_hash = (SELECT object_hash FROM content_objects ORDER BY object_hash LIMIT 1)`},
		{"binary object", `UPDATE binary_objects SET ` + flip("data_enc") + ` WHERE binary_hash = (SELECT binary_hash FROM binary_objects ORDER BY binary_hash LIMIT 1)`},
		{"stream timeline", `UPDATE stream_timelines SET ` + flip("timeline_enc") + ` WHERE audit_id = 'digest-turn-1'`},
		{"parsed result", `UPDATE parsed_results SET ` + flip("parsed_json_enc") + ` WHERE audit_id = 'digest-turn-1'`},
		{"reconstruction failure parsed result", `UPDATE parsed_results SET ` + flip("parsed_json_enc") + ` WHERE audit_id = 'digest-failed'`},
		{"user agent", `UPDATE audit_records SET ` + flip("user_agent_enc") + ` WHERE audit_id = 'digest-capture-v2'`},
		{"header block", `UPDATE http_header_blocks SET ` + flip("block_enc") + ` WHERE audit_id = 'digest-capture-v2'`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			signer, err := security.NewIntegritySigner(key)
			if err != nil {
				t.Fatal(err)
			}
			store, _ := openTestStore(t)
			targets := buildDigestFixture(t, store, graphTestCipher(t))
			signDigestFixture(t, store, signer, targets, integrityPayloadDigest)
			if err := store.VerifyIntegrityPayloads(ctx); err != nil {
				t.Fatalf("untouched fixture failed verification: %v", err)
			}
			result, err := store.writerConn.ExecContext(ctx, test.mutate)
			if err != nil {
				t.Fatal(err)
			}
			if affected, err := result.RowsAffected(); err != nil || affected != 1 {
				t.Fatalf("tamper affected %d rows: %v", affected, err)
			}
			if err := store.VerifyIntegrityPayloads(ctx); err == nil {
				t.Fatal("payload verification accepted a flipped ciphertext byte")
			}
			if state := store.IntegrityPayloadState(); state != "failed" {
				t.Fatalf("payload state after tamper = %q", state)
			}
		})
	}
}
