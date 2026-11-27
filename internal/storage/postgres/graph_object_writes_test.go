package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/security"
)

// objectTablePattern matches a statement that reads or writes one of the four
// tables a turn's objects live in.
var objectTablePattern = regexp.MustCompile(`\b(content_objects|binary_objects|content_binary_refs|content_external_refs)\b`)

type recordedStatement struct {
	query     string
	arguments []any
}

// objectWriteRecorder records every statement sent through it, so a test can
// see what the writer asks the database for.
type objectWriteRecorder struct {
	tx         *sql.Tx
	statements []recordedStatement
}

func (recorder *objectWriteRecorder) record(query string, arguments []any) {
	recorder.statements = append(recorder.statements, recordedStatement{query: query, arguments: arguments})
}

func (recorder *objectWriteRecorder) Exec(query string, arguments ...any) (sql.Result, error) {
	return recorder.ExecContext(context.Background(), query, arguments...)
}

func (recorder *objectWriteRecorder) ExecContext(ctx context.Context, query string, arguments ...any) (sql.Result, error) {
	recorder.record(query, arguments)
	return recorder.tx.ExecContext(ctx, query, arguments...)
}

func (recorder *objectWriteRecorder) Query(query string, arguments ...any) (*sql.Rows, error) {
	return recorder.QueryContext(context.Background(), query, arguments...)
}

func (recorder *objectWriteRecorder) QueryContext(ctx context.Context, query string, arguments ...any) (*sql.Rows, error) {
	recorder.record(query, arguments)
	return recorder.tx.QueryContext(ctx, query, arguments...)
}

func (recorder *objectWriteRecorder) QueryRow(query string, arguments ...any) *sql.Row {
	return recorder.QueryRowContext(context.Background(), query, arguments...)
}

func (recorder *objectWriteRecorder) QueryRowContext(ctx context.Context, query string, arguments ...any) *sql.Row {
	recorder.record(query, arguments)
	return recorder.tx.QueryRowContext(ctx, query, arguments...)
}

// objectStatements returns the recorded statements that touch an object table,
// split into reads and writes.
func (recorder *objectWriteRecorder) objectStatements() (reads, writes []recordedStatement) {
	for _, statement := range recorder.statements {
		if !objectTablePattern.MatchString(statement.query) {
			continue
		}
		verb := strings.ToUpper(strings.Fields(statement.query)[0])
		if verb == "SELECT" {
			reads = append(reads, statement)
		} else {
			writes = append(writes, statement)
		}
	}
	return reads, writes
}

// openObjectTestDatabase opens a connection of its own to the store's schema.
// The writer connection is not used for a hand-driven transaction because the
// writer goroutine's recovery ticker may send statements on it meanwhile.
func openObjectTestDatabase(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	database, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

// recordPersist runs persistPreparedTurn through a recorder and rolls the
// transaction back, so the call leaves the store unchanged.
func recordPersist(t *testing.T, database *sql.DB, turn auditmodel.PreparedTurn) *objectWriteRecorder {
	t.Helper()
	tx, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	recorder := &objectWriteRecorder{tx: tx}
	if err := persistPreparedTurn(recorder, turn); err != nil {
		t.Fatalf("persist %s: %v", turn.AuditID, err)
	}
	return recorder
}

// legacyInsertTurnObjects is the object write of the writer before it learned
// to send only missing objects, kept verbatim to build a database state the old
// code path would have produced: one INSERT ... ON CONFLICT DO NOTHING with the
// full ciphertext per object and reference, each followed by an identity read.
func legacyInsertTurnObjects(transaction dbTransaction, turn auditmodel.PreparedTurn) error {
	for _, object := range turn.Binaries {
		if _, err := transaction.Exec(`
INSERT INTO binary_objects (
    binary_hash, media_type, compression, plaintext_length,
    encoded_length, data_enc, created_at_ns
) VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT(binary_hash) DO NOTHING`,
			object.Hash, object.MediaType, object.Compression, object.PlaintextLength,
			object.EncodedLength, object.DataEnc, turn.CreatedAtNS,
		); err != nil {
			return err
		}
		var mediaType string
		var plaintextLength int64
		if err := transaction.QueryRow(`
SELECT media_type, plaintext_length
FROM binary_objects
WHERE binary_hash = $1`, object.Hash).Scan(&mediaType, &plaintextLength); err != nil {
			return err
		}
		if mediaType != object.MediaType || plaintextLength != object.PlaintextLength {
			return storedObjectIntegrityError("postgres writer: binary object hash collision or corruption")
		}
	}
	for _, object := range turn.Objects {
		if _, err := transaction.Exec(`
INSERT INTO content_objects (
    object_hash, semantic_hash, kind, compression, plaintext_length,
    encoded_length, data_enc, created_at_ns
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT(object_hash) DO NOTHING`,
			object.Hash, object.SemanticHash, object.Kind, object.Compression,
			object.PlaintextLength, object.EncodedLength, object.DataEnc, turn.CreatedAtNS,
		); err != nil {
			return err
		}
		var semanticHash []byte
		var kind string
		var plaintextLength int64
		if err := transaction.QueryRow(`
SELECT semantic_hash, kind, plaintext_length
FROM content_objects WHERE object_hash = $1`, object.Hash).Scan(&semanticHash, &kind, &plaintextLength); err != nil {
			return err
		}
		if !bytes.Equal(semanticHash, object.SemanticHash) || kind != object.Kind ||
			plaintextLength != object.PlaintextLength {
			return storedObjectIntegrityError("postgres writer: content object hash collision or corruption")
		}
		for _, reference := range object.BinaryRefs {
			if _, err := transaction.Exec(`
INSERT INTO content_binary_refs (
    object_hash, json_pointer, binary_hash, media_type, encoding
) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT(object_hash, json_pointer, binary_hash) DO NOTHING`,
				object.Hash, reference.JSONPointer, reference.BinaryHash, reference.MediaType, reference.Encoding,
			); err != nil {
				return err
			}
			var mediaType, encoding string
			if err := transaction.QueryRow(`
SELECT media_type, encoding
FROM content_binary_refs
WHERE object_hash = $1 AND json_pointer = $2 AND binary_hash = $3`,
				object.Hash, reference.JSONPointer, reference.BinaryHash,
			).Scan(&mediaType, &encoding); err != nil {
				return err
			}
			if mediaType != reference.MediaType || encoding != reference.Encoding {
				return storedObjectIntegrityError("postgres writer: content binary reference collision or corruption")
			}
		}
		for _, reference := range object.ExternalRefs {
			if _, err := transaction.Exec(`
INSERT INTO content_external_refs (
    object_hash, json_pointer, ref_kind, value_hash, value_enc
) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT(object_hash, json_pointer, ref_kind) DO NOTHING`,
				object.Hash, reference.JSONPointer, reference.Kind, reference.ValueHash, reference.ValueEnc,
			); err != nil {
				return err
			}
			var valueHash []byte
			if err := transaction.QueryRow(`
SELECT value_hash
FROM content_external_refs
WHERE object_hash = $1 AND json_pointer = $2 AND ref_kind = $3`,
				object.Hash, reference.JSONPointer, reference.Kind,
			).Scan(&valueHash); err != nil {
				return err
			}
			if !bytes.Equal(valueHash, reference.ValueHash) {
				return storedObjectIntegrityError("postgres writer: content external reference collision or corruption")
			}
		}
	}
	return nil
}

func legacySeedTurnObjects(t *testing.T, database *sql.DB, turn auditmodel.PreparedTurn) {
	t.Helper()
	tx, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacyInsertTurnObjects(tx, turn); err != nil {
		_ = tx.Rollback()
		t.Fatalf("legacy object write: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// prepareLookupTurn prepares a turn the way the parser does: objects the store
// already holds are looked up on a read connection, authenticated and reused.
func prepareLookupTurn(t *testing.T, store *Store, cipher security.Cipher, auditID, responseID string, createdAtNS int64, request, response []graphTestItem) (auditmodel.PreparedTurn, error) {
	t.Helper()
	requestItems, requestValues, requestMarkers := graphSide(request)
	responseItems, responseValues, responseMarkers := graphSide(response)
	return auditmodel.PrepareWithLookup(auditmodel.Turn{
		AuditID: auditID, Protocol: "openai", ParserName: "parser",
		RequestLayout: auditmodel.LayoutMarkerEnvelope, ResponseLayout: auditmodel.LayoutMarkerEnvelope,
		RequestEnvelope:  map[string]any{"model": "model-example", "items": requestMarkers},
		ResponseEnvelope: map[string]any{"id": responseID, "items": responseMarkers},
		RequestItems:     requestItems, ResponseItems: responseItems,
		RequestOriginal:  map[string]any{"model": "model-example", "items": requestValues},
		ResponseOriginal: map[string]any{"id": responseID, "items": responseValues},
		ResponseID:       responseID, CreatedAtNS: createdAtNS,
	}, cipher, func(contentHashes, binaryHashes [][]byte) ([]auditmodel.StoredContent, []auditmodel.StoredBinary, error) {
		return store.LookupAuditObjects(context.Background(), contentHashes, binaryHashes)
	})
}

func parsedLookupAudit(auditID string, createdAtNS int64, turn *auditmodel.PreparedTurn) ParsedAudit {
	return ParsedAudit{
		Result: ParsedResult{AuditID: auditID, ParserName: "parser", ParserVersion: "2", Status: ParseOK, ParsedAtNS: createdAtNS + 2},
		Turn:   turn,
	}
}

func insertLookupAudit(t *testing.T, store *Store, auditID string, createdAtNS int64) {
	t.Helper()
	endedAtNS := createdAtNS + 1
	insertRetentionAudit(t, store, auditID, createdAtNS, &endedAtNS, ParseProcessing, false)
}

// objectFixtureWithFile adds an item carrying an external reference to the
// shared content and binary fixture.
func objectFixtureWithFile() ([]graphTestItem, []graphTestItem) {
	request, response := graphObjectFixture()
	return append(request, graphItem("file", map[string]any{"file_id": "file-example"})), response
}

type objectTableCounts struct {
	contentObjects, binaryObjects, binaryRefs, externalRefs int
}

func countObjectTables(t *testing.T, database *sql.DB) objectTableCounts {
	t.Helper()
	var counts objectTableCounts
	if err := database.QueryRow(`
SELECT (SELECT COUNT(*) FROM content_objects),
       (SELECT COUNT(*) FROM binary_objects),
       (SELECT COUNT(*) FROM content_binary_refs),
       (SELECT COUNT(*) FROM content_external_refs)`).Scan(&counts.contentObjects, &counts.binaryObjects, &counts.binaryRefs, &counts.externalRefs); err != nil {
		t.Fatal(err)
	}
	return counts
}

// assertTurnObjectsStored checks that every object and reference row the turn
// names exists with the identity the turn carries.
func assertTurnObjectsStored(t *testing.T, database *sql.DB, turn auditmodel.PreparedTurn) {
	t.Helper()
	for _, binary := range turn.Binaries {
		var mediaType string
		var plaintextLength int64
		if err := database.QueryRow(`SELECT media_type, plaintext_length FROM binary_objects WHERE binary_hash = $1`, binary.Hash).Scan(&mediaType, &plaintextLength); err != nil {
			t.Fatalf("binary object %x: %v", binary.Hash, err)
		}
		if mediaType != binary.MediaType || plaintextLength != binary.PlaintextLength {
			t.Fatalf("binary object %x stored as %s/%d", binary.Hash, mediaType, plaintextLength)
		}
	}
	for _, object := range turn.Objects {
		var kind string
		if err := database.QueryRow(`SELECT kind FROM content_objects WHERE object_hash = $1`, object.Hash).Scan(&kind); err != nil || kind != object.Kind {
			t.Fatalf("content object %x: kind %q, %v", object.Hash, kind, err)
		}
		for _, reference := range object.BinaryRefs {
			var count int
			if err := database.QueryRow(`SELECT COUNT(*) FROM content_binary_refs WHERE object_hash = $1 AND json_pointer = $2 AND binary_hash = $3 AND media_type = $4 AND encoding = $5`,
				object.Hash, reference.JSONPointer, reference.BinaryHash, reference.MediaType, reference.Encoding).Scan(&count); err != nil || count != 1 {
				t.Fatalf("binary reference %x%s: %d rows, %v", object.Hash, reference.JSONPointer, count, err)
			}
		}
		for _, reference := range object.ExternalRefs {
			var count int
			if err := database.QueryRow(`SELECT COUNT(*) FROM content_external_refs WHERE object_hash = $1 AND json_pointer = $2 AND ref_kind = $3 AND value_hash = $4`,
				object.Hash, reference.JSONPointer, reference.Kind, reference.ValueHash).Scan(&count); err != nil || count != 1 {
				t.Fatalf("external reference %x%s: %d rows, %v", object.Hash, reference.JSONPointer, count, err)
			}
		}
	}
}

// TestObjectWritesRestoreRowsDeletedAfterTheLookup covers the gap between the
// preparation lookup, which runs on a read connection, and the writer
// transaction: retention's object GC may delete an unreferenced object or its
// reference rows in between. The writer must decide existence itself and write
// back what is gone, and integrity verification must still pass.
func TestObjectWritesRestoreRowsDeletedAfterTheLookup(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name   string
		delete func(t *testing.T, database *sql.DB, turn auditmodel.PreparedTurn)
	}{
		{name: "objects", delete: func(t *testing.T, database *sql.DB, turn auditmodel.PreparedTurn) {
			// The rows are unreferenced, as GC requires. Deleting a content
			// object cascades its reference rows, which in turn leaves its
			// binary objects unreferenced and deletable too.
			var owners []any
			for _, object := range turn.Objects {
				if len(object.BinaryRefs) > 0 || len(object.ExternalRefs) > 0 || object.Kind == "user_message" {
					owners = append(owners, object.Hash)
				}
			}
			mustExec(t, database, `DELETE FROM content_objects WHERE object_hash IN (`+placeholders(len(owners))+`)`, owners...)
			mustExec(t, database, `DELETE FROM binary_objects`)
		}},
		{name: "reference rows", delete: func(t *testing.T, database *sql.DB, _ auditmodel.PreparedTurn) {
			mustExec(t, database, `DELETE FROM content_binary_refs`)
			mustExec(t, database, `DELETE FROM content_external_refs`)
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			store, dsn := openTestStore(t)
			database := openObjectTestDatabase(t, dsn)
			cipher := graphTestCipher(t)
			request, response := objectFixtureWithFile()

			// The seed is an earlier write of the same content whose turn has
			// since expired, so its object rows are left unreferenced.
			legacySeedTurnObjects(t, database, prepareGraphTestTurn(t, cipher, "turn-expired", "", "response-expired", 50, request, response))
			if err := store.EnableIntegrity(ctx, bytes.Repeat([]byte{0x2d}, security.KeySize)); err != nil {
				t.Fatal(err)
			}
			insertLookupAudit(t, store, "turn-after-gc", 100)
			prepared, err := prepareLookupTurn(t, store, cipher, "turn-after-gc", "response-after-gc", 100, request, response)
			if err != nil {
				t.Fatal(err)
			}
			// Every request-side object came from the lookup: it carries the
			// stored ciphertext rather than a fresh seal.
			reused := 0
			for _, object := range prepared.Objects {
				var stored []byte
				err := database.QueryRow(`SELECT data_enc FROM content_objects WHERE object_hash = $1`, object.Hash).Scan(&stored)
				if err == nil && bytes.Equal(stored, object.DataEnc) {
					reused++
				}
			}
			for _, binary := range prepared.Binaries {
				var stored []byte
				if err := database.QueryRow(`SELECT data_enc FROM binary_objects WHERE binary_hash = $1`, binary.Hash).Scan(&stored); err != nil || !bytes.Equal(stored, binary.DataEnc) {
					t.Fatalf("binary object %x was not reused from the lookup", binary.Hash)
				}
			}
			// Only the response envelope differs from the seed.
			if reused != len(prepared.Objects)-1 {
				t.Fatalf("lookup reused %d of %d content objects", reused, len(prepared.Objects))
			}

			testCase.delete(t, database, prepared)
			if err := store.SaveParsedAudit(ctx, parsedLookupAudit("turn-after-gc", 100, &prepared)); err != nil {
				t.Fatalf("save after GC: %v", err)
			}
			assertTurnObjectsStored(t, store.readerDB, prepared)
			assertGraphObjectsOpen(t, store, cipher, "turn-after-gc", nil)
			if err := store.VerifyIntegrityPayloads(ctx); err != nil {
				t.Fatalf("verify integrity payloads: %v", err)
			}
			if !store.Healthy() {
				t.Fatal("store unhealthy after restoring collected objects")
			}
		})
	}
}

func mustExec(t *testing.T, database *sql.DB, query string, arguments ...any) {
	t.Helper()
	if _, err := database.ExecContext(context.Background(), query, arguments...); err != nil {
		t.Fatalf("%s: %v", strings.TrimSpace(query), err)
	}
}

// wideObjectFixture builds a request whose object count and reference counts
// each exceed two query batches, so a writer that queried per object or sent a
// statement per reference would show up in the statement count.
func wideObjectFixture() ([]graphTestItem, []graphTestItem) {
	width := 2*graphHashQueryBatch + 50
	request := make([]graphTestItem, 0, width+2)
	for index := range width {
		request = append(request, graphItem("user_message", map[string]any{"role": "user", "content": fmt.Sprintf("context item %d", index)}))
	}
	image := "data:image/png;base64," + base64.StdEncoding.EncodeToString(append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0x33, 0x71}, 128)...))
	references := graphHashQueryBatch + 50
	images := make([]any, 0, references)
	files := make([]any, 0, references)
	for index := range references {
		images = append(images, map[string]any{"type": "input_image", "image_url": image})
		files = append(files, map[string]any{"type": "input_file", "file_id": fmt.Sprintf("file-%d", index)})
	}
	request = append(request,
		graphItem("user_message", map[string]any{"role": "user", "content": images}),
		graphItem("user_message", map[string]any{"role": "user", "content": files}))
	return request, []graphTestItem{graphItem("assistant_message", map[string]any{"role": "assistant", "content": "wide answer"})}
}

func ceilBatches(count int) int {
	return (count + graphHashQueryBatch - 1) / graphHashQueryBatch
}

type turnObjectShape struct {
	binaries, objects, binaryRefs, externalRefs, binaryOwners, externalOwners int
}

func shapeOf(turn auditmodel.PreparedTurn) turnObjectShape {
	shape := turnObjectShape{binaries: len(turn.Binaries), objects: len(turn.Objects)}
	for _, object := range turn.Objects {
		shape.binaryRefs += len(object.BinaryRefs)
		shape.externalRefs += len(object.ExternalRefs)
		if len(object.BinaryRefs) > 0 {
			shape.binaryOwners++
		}
		if len(object.ExternalRefs) > 0 {
			shape.externalOwners++
		}
	}
	return shape
}

// objectRowVersions returns the xmin of every object and reference row, keyed
// by table and primary key, to show that a save left existing rows untouched.
func objectRowVersions(t *testing.T, database *sql.DB) map[string]string {
	t.Helper()
	rows, err := database.Query(`
SELECT 'c:' || encode(object_hash, 'hex'), xmin::text FROM content_objects
UNION ALL SELECT 'b:' || encode(binary_hash, 'hex'), xmin::text FROM binary_objects
UNION ALL SELECT 'r:' || encode(object_hash, 'hex') || json_pointer || encode(binary_hash, 'hex'), xmin::text FROM content_binary_refs
UNION ALL SELECT 'e:' || encode(object_hash, 'hex') || json_pointer || ref_kind, xmin::text FROM content_external_refs`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	versions := make(map[string]string)
	for rows.Next() {
		var key, version string
		if err := rows.Scan(&key, &version); err != nil {
			t.Fatal(err)
		}
		versions[key] = version
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return versions
}

// TestObjectWritesSendOnlyMissingObjects pins what the writer sends for a wide
// turn: on the first save each table gets one insert per batch of new rows,
// and on a save whose objects all exist it sends no ciphertext, writes no
// object row, and needs a number of statements set by the batching alone.
func TestObjectWritesSendOnlyMissingObjects(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, dsn := openTestStore(t)
	database := openObjectTestDatabase(t, dsn)
	cipher := graphTestCipher(t)
	if err := store.EnableIntegrity(ctx, bytes.Repeat([]byte{0x2d}, security.KeySize)); err != nil {
		t.Fatal(err)
	}
	request, response := wideObjectFixture()

	first := buildGraphTestTurn(t, store, cipher, "turn-wide-one", "", "response-wide", 100, request, response)
	shape := shapeOf(*first.Turn)
	if shape.objects <= 2*graphHashQueryBatch || shape.binaryRefs <= graphHashQueryBatch || shape.externalRefs <= graphHashQueryBatch ||
		shape.binaries != 1 || shape.binaryOwners != 1 || shape.externalOwners != 1 {
		t.Fatalf("fixture shape = %+v", shape)
	}

	recorded := recordPersist(t, database, *first.Turn)
	reads, writes := recorded.objectStatements()
	// Everything is new: one existence read per table, none for references of
	// objects that did not exist, then the inserts in batches.
	if want := ceilBatches(shape.binaries) + ceilBatches(shape.objects); len(reads) != want {
		t.Fatalf("first save object reads = %d, want %d", len(reads), want)
	}
	if want := ceilBatches(shape.binaries) + ceilBatches(shape.objects) + ceilBatches(shape.binaryRefs) + ceilBatches(shape.externalRefs); len(writes) != want {
		t.Fatalf("first save object writes = %d, want %d", len(writes), want)
	}
	for _, statement := range writes {
		if len(statement.arguments) > 65535 {
			t.Fatalf("insert binds %d parameters", len(statement.arguments))
		}
	}

	if err := store.SaveParsedAudit(ctx, first); err != nil {
		t.Fatal(err)
	}
	versions := objectRowVersions(t, store.readerDB)
	counts := countObjectTables(t, store.readerDB)

	// The same content again, freshly sealed: every object already exists.
	second := buildGraphTestTurn(t, store, cipher, "turn-wide-two", "", "response-wide", 200, request, response)
	recorded = recordPersist(t, database, *second.Turn)
	reads, writes = recorded.objectStatements()
	if len(writes) != 0 {
		t.Fatalf("save of stored objects wrote %d object statements, first: %s", len(writes), writes[0].query)
	}
	if want := ceilBatches(shape.binaries) + ceilBatches(shape.objects) + ceilBatches(shape.binaryOwners) + ceilBatches(shape.externalOwners); len(reads) != want {
		t.Fatalf("save of stored objects read %d times, want %d", len(reads), want)
	}
	ciphertexts := make([][]byte, 0, shape.objects+shape.binaries+shape.externalRefs)
	for _, object := range second.Turn.Objects {
		ciphertexts = append(ciphertexts, object.DataEnc)
		for _, reference := range object.ExternalRefs {
			ciphertexts = append(ciphertexts, reference.ValueEnc)
		}
	}
	for _, binary := range second.Turn.Binaries {
		ciphertexts = append(ciphertexts, binary.DataEnc)
	}
	for _, statement := range recorded.statements {
		lower := strings.ToLower(statement.query)
		if strings.Contains(lower, "data_enc") || strings.Contains(lower, "value_enc") {
			t.Fatalf("statement names a ciphertext column: %s", statement.query)
		}
		for _, argument := range statement.arguments {
			value, ok := argument.([]byte)
			if !ok {
				continue
			}
			for _, ciphertext := range ciphertexts {
				if bytes.Equal(value, ciphertext) {
					t.Fatalf("statement carried a ciphertext: %s", statement.query)
				}
			}
		}
	}

	if err := store.SaveParsedAudit(ctx, second); err != nil {
		t.Fatal(err)
	}
	if after := countObjectTables(t, store.readerDB); after != counts {
		t.Fatalf("object rows after reuse = %+v, want %+v", after, counts)
	}
	after := objectRowVersions(t, store.readerDB)
	if len(after) != len(versions) {
		t.Fatalf("object row versions = %d, want %d", len(after), len(versions))
	}
	for key, version := range versions {
		if after[key] != version {
			t.Fatalf("row %s rewritten: xmin %s -> %s", key, version, after[key])
		}
	}
	if err := store.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatalf("verify integrity payloads: %v", err)
	}
}

// TestObjectWritesRepairOneMissingReferenceRow keeps the self-healing property:
// an object that exists while one of its reference rows does not gets that row
// back, and only that row is written.
func TestObjectWritesRepairOneMissingReferenceRow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, dsn := openTestStore(t)
	database := openObjectTestDatabase(t, dsn)
	cipher := graphTestCipher(t)
	request, response := objectFixtureWithFile()
	first := saveGraphTestTurn(t, store, cipher, "turn-heal-one", "", "response-heal", 100, request, response)
	counts := countObjectTables(t, store.readerDB)
	var owner []byte
	var pointer string
	if err := database.QueryRow(`SELECT object_hash, json_pointer FROM content_binary_refs ORDER BY object_hash, json_pointer LIMIT 1`).Scan(&owner, &pointer); err != nil {
		t.Fatal(err)
	}
	mustExec(t, database, `DELETE FROM content_binary_refs WHERE object_hash = $1 AND json_pointer = $2`, owner, pointer)
	mustExec(t, database, `DELETE FROM content_external_refs`)

	second := buildGraphTestTurn(t, store, cipher, "turn-heal-two", "", "response-heal", 200, request, response)
	recorded := recordPersist(t, database, *second.Turn)
	_, writes := recorded.objectStatements()
	if len(writes) != 2 || !strings.Contains(writes[0].query, "content_binary_refs") || len(writes[0].arguments) != 5 ||
		!strings.Contains(writes[1].query, "content_external_refs") || len(writes[1].arguments) != 5 {
		t.Fatalf("repair writes = %+v", writes)
	}
	if err := store.SaveParsedAudit(ctx, second); err != nil {
		t.Fatal(err)
	}
	if after := countObjectTables(t, store.readerDB); after != counts {
		t.Fatalf("object rows after repair = %+v, want %+v", after, counts)
	}
	assertTurnObjectsStored(t, store.readerDB, first)
}

// TestObjectIdentityMismatchOnALookupPreparedTurn runs the tamper cases of
// TestObjectIdentityMismatchRejectsTheSecondSave with the second turn prepared
// the way the parser prepares it. The lookup authenticates object rows and
// rejects a tampered one before the writer sees it; reference rows are not
// part of the lookup, so the writer's batched check must catch those with the
// same stored-object integrity classification as before.
func TestObjectIdentityMismatchOnALookupPreparedTurn(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name         string
		tamper       string
		lookupCaught bool
	}{
		{name: "content kind", tamper: `UPDATE content_objects SET kind = 'assistant_message_v2' WHERE kind = 'assistant_message'`, lookupCaught: true},
		{name: "content plaintext length", tamper: `UPDATE content_objects SET plaintext_length = plaintext_length + 1 WHERE kind = 'assistant_message'`, lookupCaught: true},
		{name: "content semantic hash", tamper: `UPDATE content_objects SET semantic_hash = decode(repeat('00', 32), 'hex') WHERE kind = 'assistant_message'`, lookupCaught: true},
		{name: "binary media type", tamper: `UPDATE binary_objects SET media_type = 'image/png'`, lookupCaught: true},
		{name: "binary plaintext length", tamper: `UPDATE binary_objects SET plaintext_length = plaintext_length + 1`, lookupCaught: true},
		{name: "binary reference media type", tamper: `UPDATE content_binary_refs SET media_type = 'image/jpeg'`},
		{name: "binary reference encoding", tamper: `UPDATE content_binary_refs SET encoding = 'base64'`},
		{name: "external reference hash", tamper: `UPDATE content_external_refs SET value_hash = decode(repeat('00', 32), 'hex')`},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			store, dsn := openTestStore(t)
			database := openObjectTestDatabase(t, dsn)
			cipher := graphTestCipher(t)
			request, response := objectFixtureWithFile()
			saveGraphTestTurn(t, store, cipher, "turn-lookup-one", "", "response-lookup-one", 100, request, response)
			mustExec(t, database, testCase.tamper)
			before := countGraphRows(t, store)

			insertLookupAudit(t, store, "turn-lookup-two", 200)
			prepared, err := prepareLookupTurn(t, store, cipher, "turn-lookup-two", "response-lookup-two", 200, request, response)
			if testCase.lookupCaught {
				if !errors.Is(err, auditmodel.ErrIntegrity) {
					t.Fatalf("lookup preparation error = %v, want integrity failure", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("lookup preparation: %v", err)
			}
			err = store.SaveParsedAudit(ctx, parsedLookupAudit("turn-lookup-two", 200, &prepared))
			var integrityFailure storedObjectIntegrityError
			if !errors.As(err, &integrityFailure) || !strings.Contains(err.Error(), "collision or corruption") {
				t.Fatalf("save error = %v, want stored-object integrity failure", err)
			}
			if after := countGraphRows(t, store); after != before {
				t.Fatalf("rows after rejected save = %+v, want %+v", after, before)
			}
			if store.Healthy() || store.IntegrityPayloadState() != "failed" {
				t.Fatal("stored identity mismatch did not latch integrity health")
			}
		})
	}
}

func readSemanticDigest(t *testing.T, store *Store, auditID string) []byte {
	t.Helper()
	tx, err := store.readerDB.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	digest, err := semanticPayloadDigest(context.Background(), tx, nil, auditID)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

// objectRowFingerprints lists every object and reference row with all its
// columns, ciphertexts reduced to a hash, for comparing two databases.
func objectRowFingerprints(t *testing.T, database *sql.DB) []string {
	t.Helper()
	rows, err := database.Query(`
SELECT 'c', encode(object_hash, 'hex') || semantic_hash::text || kind || compression || plaintext_length || ':' || encoded_length || md5(data_enc) || created_at_ns FROM content_objects
UNION ALL SELECT 'b', encode(binary_hash, 'hex') || media_type || compression || plaintext_length || ':' || encoded_length || md5(data_enc) || created_at_ns FROM binary_objects
UNION ALL SELECT 'r', encode(object_hash, 'hex') || json_pointer || encode(binary_hash, 'hex') || media_type || encoding FROM content_binary_refs
UNION ALL SELECT 'e', encode(object_hash, 'hex') || json_pointer || ref_kind || encode(value_hash, 'hex') || md5(value_enc) FROM content_external_refs
ORDER BY 1, 2`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var table, row string
		if err := rows.Scan(&table, &row); err != nil {
			t.Fatal(err)
		}
		result = append(result, table+row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

// TestObjectWritesKeepDigestsOverLegacyRows shows the change leaves digest
// inputs alone. One store gets its object rows from the old write path, the
// other from the new one, for the same prepared turn: the rows and the
// semantic digest agree. A later turn that reuses the legacy rows leaves the
// earlier audit's digest byte-identical, and every recorded event verifies.
func TestObjectWritesKeepDigestsOverLegacyRows(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x2d}, security.KeySize)
	cipher := graphTestCipher(t)
	request, response := objectFixtureWithFile()

	legacy, legacyDSN := openTestStore(t)
	current, _ := openTestStore(t)
	for _, store := range []*Store{legacy, current} {
		if err := store.EnableIntegrity(ctx, key); err != nil {
			t.Fatal(err)
		}
		insertLookupAudit(t, store, "turn-digest-one", 100)
	}
	prepared := prepareGraphTestTurn(t, cipher, "turn-digest-one", "", "response-digest-one", 100, request, response)
	// The legacy store's object rows come from the old code; the save that
	// follows finds them all and writes only the graph, which this change does
	// not touch, so the state is the one the old writer would have left.
	legacySeedTurnObjects(t, openObjectTestDatabase(t, legacyDSN), prepared)
	for _, store := range []*Store{legacy, current} {
		turn := prepared
		if err := store.SaveParsedAudit(ctx, parsedLookupAudit("turn-digest-one", 100, &turn)); err != nil {
			t.Fatal(err)
		}
	}
	legacyRows, currentRows := objectRowFingerprints(t, legacy.readerDB), objectRowFingerprints(t, current.readerDB)
	if strings.Join(legacyRows, "\n") != strings.Join(currentRows, "\n") {
		t.Fatalf("object rows differ between write paths:\nlegacy  %v\ncurrent %v", legacyRows, currentRows)
	}
	digest := readSemanticDigest(t, legacy, "turn-digest-one")
	if currentDigest := readSemanticDigest(t, current, "turn-digest-one"); !bytes.Equal(digest, currentDigest) {
		t.Fatalf("semantic digest legacy %x, current %x", digest, currentDigest)
	}

	saveGraphTestTurn(t, legacy, cipher, "turn-digest-two", "response-digest-one", "response-digest-two", 200,
		append(append([]graphTestItem(nil), request...), response...),
		[]graphTestItem{graphItem("assistant_message", map[string]any{"role": "assistant", "content": "a later answer"})})
	if after := readSemanticDigest(t, legacy, "turn-digest-one"); !bytes.Equal(after, digest) {
		t.Fatalf("digest of the earlier audit changed: %x -> %x", digest, after)
	}
	for _, store := range []*Store{legacy, current} {
		if err := store.VerifyIntegrityPayloads(ctx); err != nil {
			t.Fatalf("verify integrity payloads: %v", err)
		}
	}
	var events int
	if err := legacy.readerDB.QueryRow(`SELECT COUNT(*) FROM integrity_events WHERE event_type = $1`, integritySemanticCompacted).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 2 {
		t.Fatalf("semantic_compacted events = %d, want 2", events)
	}
}
