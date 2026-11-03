package postgres

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/auditmodel"
)

func TestPostgresFilterParameterOffsets(t *testing.T) {
	token := int64(42)
	filter := InsightsFilter{FromNS: 1, ToNS: 100, SessionIDs: []string{"a", "b"}, RootPrefix: []byte{1}, RootFPRs: [][]byte{bytes.Repeat([]byte{1}, 32)}, Scope: &AuditScope{Fingerprint: bytes.Repeat([]byte{2}, 32), TokenID: &token}}
	where, args, err := insightsWhere(filter)
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 11 {
		t.Fatalf("parameter count = %d", len(args))
	}
	for i := 1; i <= len(args); i++ {
		if !strings.Contains(where, fmt.Sprintf("$%d", i)) {
			t.Fatalf("missing bind %d in %s", i, where)
		}
	}
	if strings.Contains(where, "?") {
		t.Fatal("SQLite placeholder remains")
	}
	if got := placeholders(3, 7); got != "$8,$9,$10" {
		t.Fatalf("placeholders = %s", got)
	}
}

func TestPostgresDayBucketsIgnoreServerTimezone(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	// The connection setting must not affect calendar buckets requested by UI.
	store.readerDB.SetMaxOpenConns(1)
	if _, err := store.readerDB.ExecContext(ctx, `SET TIME ZONE 'Pacific/Honolulu'`); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 10, 23, 59, 59, 999999999, time.UTC)
	seedInsights(t, store, insightsSeed{id: "timezone", at: at, key: keyA, session: sessionShared, system: 1})
	for offset, want := range map[int]string{0: "2026-10-10", 1: "2026-10-11", -840: "2026-10-10", 840: "2026-10-11"} {
		rows, err := store.InsightsDayCounts(ctx, InsightsFilter{}, offset)
		if err != nil || len(rows) != 1 || rows[0].Day != want {
			t.Fatalf("offset %d: %+v %v", offset, rows, err)
		}
	}
}

func TestPostgresAuditOrderingUsesBinaryCollation(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	for _, id := range []string{"z", "Z", "é", "a"} {
		record := testAudit(id)
		record.StartedAtNS = 100
		if err := store.BeginAudit(ctx, record); err != nil {
			t.Fatal(err)
		}
	}
	first, err := store.ListAudits(ctx, AuditQueryFilter{}, AuditQueryCursor{}, 2)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.ListAudits(ctx, AuditQueryFilter{}, AuditQueryCursor{BeforeStartedAtNS: 100, BeforeID: first.Rows[1].AuditID}, 2)
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, row := range append(first.Rows, second.Rows...) {
		got = append(got, row.AuditID)
	}
	if !reflect.DeepEqual(got, []string{"é", "z", "a", "Z"}) {
		t.Fatalf("binary order: %v", got)
	}
}

func TestPostgresLookupObjectsReturnsPartialDeduplicatedHits(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	contentHash := bytes.Repeat([]byte{0x11}, 32)
	binaryHash := bytes.Repeat([]byte{0x22}, 32)
	missing := bytes.Repeat([]byte{0x33}, 32)
	contentCipher := []byte{0, 0xff, 0x81, 0}
	binaryCipher := []byte{0xfe, 0, 0x80}
	if _, err := store.writerConn.ExecContext(ctx, `INSERT INTO content_objects(object_hash,semantic_hash,kind,compression,plaintext_length,encoded_length,data_enc,created_at_ns) VALUES($1,$1,'test','none',4294967296,4294967296,$2,1)`, contentHash, contentCipher); err != nil {
		t.Fatal(err)
	}
	if _, err := store.writerConn.ExecContext(ctx, `INSERT INTO binary_objects(binary_hash,media_type,compression,plaintext_length,encoded_length,data_enc,created_at_ns) VALUES($1,'application/octet-stream','none',3,3,$2,1)`, binaryHash, binaryCipher); err != nil {
		t.Fatal(err)
	}
	content, binary, err := store.LookupAuditObjects(ctx, [][]byte{contentHash, missing, contentHash}, [][]byte{binaryHash, missing, binaryHash})
	if err != nil {
		t.Fatal(err)
	}
	if len(content) != 1 || !bytes.Equal(content[0].DataEnc, contentCipher) || content[0].PlaintextLength != 4294967296 {
		t.Fatalf("content lookup: %+v", content)
	}
	if len(binary) != 1 || !bytes.Equal(binary[0].DataEnc, binaryCipher) {
		t.Fatalf("binary lookup: %+v", binary)
	}
	if _, _, err := store.LookupAuditObjects(ctx, [][]byte{{1}}, nil); err == nil {
		t.Fatal("malformed hash accepted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := store.LookupAuditObjects(cancelled, [][]byte{contentHash}, nil); err == nil {
		t.Fatal("cancelled lookup accepted")
	}
	// Hit count may exceed one SQL batch. Duplicated requests remain bounded by
	// unique hashes and the result omits every genuinely missing object.
	many := make([][]byte, graphHashQueryBatch+5)
	for i := range many {
		many[i] = make([]byte, 32)
		many[i][0] = byte(i)
		many[i][1] = byte(i >> 8)
	}
	many = append(many, contentHash)
	content, _, err = store.LookupAuditObjects(ctx, many, nil)
	if err != nil || len(content) != 1 {
		t.Fatalf("batched lookup count=%d err=%v", len(content), err)
	}
}

func TestPostgresBackfillCursorAndExists(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	if has, err := store.HasAudits(ctx); err != nil || has {
		t.Fatalf("empty has audits=%v err=%v", has, err)
	}
	at := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	for _, id := range []string{"b", "a", "c"} {
		seedInsights(t, store, insightsSeed{id: id, at: at, key: keyA, system: 1})
	}
	if has, err := store.HasAudits(ctx); err != nil || !has {
		t.Fatalf("has audits=%v err=%v", has, err)
	}
	first, err := store.ListAnalysisBackfillCandidates(ctx, 2, nil, 2)
	if err != nil || len(first) != 2 || first[0].AuditID != "a" || first[1].AuditID != "b" {
		t.Fatalf("first backfill=%+v err=%v", first, err)
	}
	next, err := store.ListAnalysisBackfillCandidates(ctx, 2, &AnalysisBackfillCursor{StartedAtNS: at.UnixNano(), AuditID: "b"}, 2)
	if err != nil || len(next) != 1 || next[0].AuditID != "c" {
		t.Fatalf("next backfill=%+v err=%v", next, err)
	}
	current, err := store.ListAnalysisBackfillCandidates(ctx, 1, nil, 2)
	if err != nil || len(current) != 0 {
		t.Fatalf("current backfill=%+v err=%v", current, err)
	}
}

func TestPostgresPrepareLookupReusesAndAuthenticatesStoredObjects(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	cipher := graphTestCipher(t)
	request, response := graphObjectFixture()
	original := saveGraphTestTurn(t, store, cipher, "lookup-first", "", "response-shared", 100, request, response)
	requestItems, requestValues, requestMarkers := graphSide(request)
	responseItems, responseValues, responseMarkers := graphSide(response)
	turn := auditmodel.Turn{
		AuditID: "lookup-second", Protocol: "openai", ParserName: "parser",
		RequestLayout: auditmodel.LayoutMarkerEnvelope, ResponseLayout: auditmodel.LayoutMarkerEnvelope,
		RequestEnvelope:  map[string]any{"model": "model-example", "items": requestMarkers},
		ResponseEnvelope: map[string]any{"id": "response-shared", "items": responseMarkers},
		RequestItems:     requestItems, ResponseItems: responseItems,
		RequestOriginal:  map[string]any{"model": "model-example", "items": requestValues},
		ResponseOriginal: map[string]any{"id": "response-shared", "items": responseValues},
		ResponseID:       "response-shared", CreatedAtNS: 200,
	}
	lookup := func(content, binary [][]byte) ([]auditmodel.StoredContent, []auditmodel.StoredBinary, error) {
		return store.LookupAuditObjects(ctx, content, binary)
	}
	reused, err := auditmodel.PrepareWithLookup(turn, cipher, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if len(reused.Objects) != len(original.Objects) || len(reused.Binaries) != len(original.Binaries) {
		t.Fatal("object count changed")
	}
	for i := range original.Objects {
		if !bytes.Equal(original.Objects[i].DataEnc, reused.Objects[i].DataEnc) {
			t.Fatal("cached content was reencrypted")
		}
	}
	for i := range original.Binaries {
		if !bytes.Equal(original.Binaries[i].DataEnc, reused.Binaries[i].DataEnc) {
			t.Fatal("cached binary was reencrypted")
		}
	}
	ended := int64(201)
	insertRetentionAudit(t, store, "lookup-second", 200, &ended, ParseProcessing, false)
	if err := store.SaveParsedAudit(ctx, ParsedAudit{Result: ParsedResult{AuditID: "lookup-second", ParserName: "parser", ParserVersion: "2", Status: ParseOK, ParsedAtNS: 202}, Turn: &reused}); err != nil {
		t.Fatal(err)
	}
	// Database presence must never bypass the codec's authenticated opening.
	if _, err := store.writerConn.ExecContext(ctx, `UPDATE content_objects SET data_enc=$1 WHERE object_hash=$2`, []byte("invalid-authenticated-ciphertext"), original.Objects[0].Hash); err != nil {
		t.Fatal(err)
	}
	if _, err := auditmodel.PrepareWithLookup(turn, cipher, lookup); err == nil {
		t.Fatal("corrupt stored object accepted")
	}
}
