package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"llmapi-logger/internal/headerblock"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// These tests need a real PostgreSQL (TEST_DATABASE_URL) and skip otherwise.
// They write capture version 2 audits through the store's own operations with
// blocks sealed by internal/headerblock, as the unified session does.

var v2TestKey = bytes.Repeat([]byte{0x5c}, security.KeySize)

func v2TestCipher(t *testing.T) security.Cipher {
	t.Helper()
	cipher, err := security.NewAESGCM(v2TestKey)
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

func openSignedStore(t *testing.T) (*Store, string) {
	t.Helper()
	store, dsn := openTestStore(t)
	if err := store.EnableIntegrity(context.Background(), v2TestKey); err != nil {
		t.Fatal(err)
	}
	return store, dsn
}

// v2Stage is one stage of a synthetic version 2 audit: its Header map as the
// session snapshots it at stage start, and its Trailers.
type v2Stage struct {
	name     string
	headers  http.Header
	trailers http.Header
}

func v2TestStages() []v2Stage {
	return []v2Stage{
		{name: StageRequestReceived, headers: http.Header{
			"Content-Type":  {"application/json"},
			"User-Agent":    {"client.example/1.0", "second-agent"},
			"Authorization": {"Bearer synthetic-secret"},
			"X-Agent-Id":    {"agent-7"},
		}, trailers: http.Header{"X-Request-Trailer": {"done"}}},
		{name: StageRequestSent, headers: http.Header{
			"Content-Type":    {"application/json"},
			"Accept-Encoding": {"identity"},
			"Authorization":   {"Bearer synthetic-secret"},
		}},
		{name: StageResponseReceived, headers: http.Header{
			"Content-Type":     {"text/event-stream"},
			"Content-Encoding": {"", "gzip"},
		}},
		{name: StageResponseSent, headers: http.Header{
			"Content-Type": {"text/event-stream"},
		}, trailers: http.Header{"X-Done": {"1"}}},
	}
}

func sealV2Block(t *testing.T, cipher security.Cipher, auditID string, stages []v2Stage, withTrailers map[string]bool) *HeaderBlock {
	t.Helper()
	sections := make([]headerblock.Stage, 0, len(stages))
	for _, stage := range stages {
		section := headerblock.Stage{Name: stage.name, Headers: headerblock.Snapshot(stage.headers)}
		if withTrailers[stage.name] {
			section.Trailers = headerblock.Snapshot(stage.trailers)
		}
		sections = append(sections, section)
	}
	block, err := headerblock.SealBlock(cipher, auditID, sections)
	if err != nil {
		t.Fatal(err)
	}
	return &block
}

func v2StageRow(auditID string, stage v2Stage, at int64) HTTPStage {
	row := HTTPStage{AuditID: auditID, Stage: stage.name, State: StageStateStreaming, Proto: "HTTP/1.1", StartedAtNS: at}
	if stage.name == StageRequestReceived || stage.name == StageRequestSent {
		row.Method, row.Host = "POST", "upstream.example.com"
	} else {
		status := 200
		row.StatusCode = &status
	}
	return row
}

func v2Content(stage v2Stage) StageContent {
	contentType, contentEncoding := headerblock.ContentHeaders(headerblock.Snapshot(stage.headers))
	return StageContent{Stage: stage.name, ContentType: contentType, ContentEncoding: contentEncoding}
}

// v2Audit drives one version 2 audit through BeginAudit (with the inbound
// stage and its one-stage block), checkpoint 1 (request_sent) and the commit
// (both response stages, the full block). stopAfter ends it early: 1 after
// BeginAudit, 2 after the checkpoint.
type v2Audit struct {
	id        string
	stages    []v2Stage
	stopAfter int
	// commitBlock replaces the commit's block, for tests that need a block
	// whose stages do not match the stage rows.
	commitBlock func(t *testing.T, cipher security.Cipher, id string, stages []v2Stage) *HeaderBlock
}

func writeV2Audit(t *testing.T, store *Store, cipher security.Cipher, audit v2Audit) {
	t.Helper()
	ctx := context.Background()
	stages := audit.stages
	if stages == nil {
		stages = v2TestStages()
	}
	values := headerblock.UserAgentValues(headerblock.Snapshot(stages[0].headers))
	userAgent, err := headerblock.SealUserAgent(cipher, audit.id, values)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := cipher.Encrypt([]byte(audit.id+"\x00request_uri"), []byte("/v1/chat/completions"))
	if err != nil {
		t.Fatal(err)
	}
	inbound := v2Content(stages[0])
	record := testAudit(audit.id)
	record.StartedAtNS = 1000
	record.RequestURIEnc = uri
	record.CaptureVersion = CaptureVersion2
	record.UserAgentEnc = userAgent
	record.Inbound = &InboundStage{
		Stage:           v2StageRow(audit.id, stages[0], 1001),
		HeaderBlock:     sealV2Block(t, cipher, audit.id, stages[:1], nil),
		ContentType:     inbound.ContentType,
		ContentEncoding: inbound.ContentEncoding,
	}
	if err := store.BeginAudit(ctx, record); err != nil {
		t.Fatalf("BeginAudit: %v", err)
	}
	if audit.stopAfter == 1 {
		writerBarrier(t, store)
		return
	}
	trailers := map[string]bool{StageRequestReceived: true}
	if err := store.Checkpoint(ctx, AuditCheckpoint{
		AuditID:        audit.id,
		CaptureVersion: CaptureVersion2,
		Stages:         []HTTPStage{v2StageRow(audit.id, stages[1], 1002)},
		Contents:       []StageContent{v2Content(stages[1])},
		HeaderBlock:    sealV2Block(t, cipher, audit.id, stages[:2], trailers),
	}); err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	if audit.stopAfter == 2 {
		writerBarrier(t, store)
		return
	}
	trailers[StageResponseSent] = true
	block := sealV2Block(t, cipher, audit.id, stages, trailers)
	if audit.commitBlock != nil {
		block = audit.commitBlock(t, cipher, audit.id, stages)
	}
	commit := AuditCommit{CaptureVersion: CaptureVersion2, HeaderBlock: block, Finish: AuditFinish{
		AuditID: audit.id, EndedAtNS: 2000, ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParsePending,
	}}
	status := 200
	commit.Finish.StatusCode = &status
	for index, stage := range stages {
		final := v2StageRow(audit.id, stage, int64(1001+index))
		final.State = StageStateComplete
		ended := int64(1900 + index)
		final.EndedAtNS = &ended
		content := v2Content(stage)
		commit.Stages = append(commit.Stages, StageCommit{Stage: final, StageWritten: index < 2,
			ContentType: content.ContentType, ContentEncoding: content.ContentEncoding})
	}
	if _, err := store.CommitAudit(ctx, commit); err != nil {
		t.Fatalf("CommitAudit: %v", err)
	}
}

// writeV1Audit is the same request stored as capture version 1 through the
// same operations: per-value header rows, no block.
func writeV1Audit(t *testing.T, store *Store, cipher security.Cipher, auditID string) {
	t.Helper()
	ctx := context.Background()
	stages := v2TestStages()
	rows := func(stage v2Stage, kind string, headers http.Header) []HTTPHeader {
		var out []HTTPHeader
		for _, field := range headerblock.Snapshot(headers) {
			for index, value := range field.Values {
				aad, _ := security.AAD(auditID, "header", stage.name, kind, field.Name, strconv.Itoa(index))
				enc, err := cipher.Encrypt(aad, value)
				if err != nil {
					t.Fatal(err)
				}
				out = append(out, HTTPHeader{AuditID: auditID, Stage: stage.name, Kind: kind, Name: field.Name, ValueIndex: index, ValueLength: len(value), ValueEnc: enc})
			}
		}
		return out
	}
	record := testAudit(auditID)
	record.StartedAtNS = 1000
	record.Inbound = &InboundStage{Stage: v2StageRow(auditID, stages[0], 1001), Headers: rows(stages[0], "header", stages[0].headers)}
	if err := store.BeginAudit(ctx, record); err != nil {
		t.Fatal(err)
	}
	commit := AuditCommit{Finish: AuditFinish{AuditID: auditID, EndedAtNS: 2000, ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParsePending}}
	status := 200
	commit.Finish.StatusCode = &status
	for index, stage := range stages {
		final := v2StageRow(auditID, stage, int64(1001+index))
		final.State = StageStateComplete
		ended := int64(1900 + index)
		final.EndedAtNS = &ended
		commit.Stages = append(commit.Stages, StageCommit{Stage: final, StageWritten: index == 0})
		if index > 0 {
			commit.Headers = append(commit.Headers, rows(stage, "header", stage.headers)...)
		}
		if stage.trailers != nil {
			commit.Headers = append(commit.Headers, rows(stage, "trailer", stage.trailers)...)
		}
	}
	if _, err := store.CommitAudit(ctx, commit); err != nil {
		t.Fatal(err)
	}
}

// expandDetail reads an audit's Headers the way the query service does.
func expandDetail(t *testing.T, store *Store, cipher security.Cipher, auditID string) ([]headerblock.Value, error) {
	t.Helper()
	detail, err := store.QueryAuditDetail(context.Background(), auditID, nil)
	if err != nil {
		t.Fatal(err)
	}
	return headerblock.Expand(cipher, auditID, detail.HeaderSource())
}

func flatHeaders(values []headerblock.Value) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value.Stage+" "+value.Kind+" "+value.Name+" "+strconv.Itoa(value.ValueIndex)+" "+string(value.Value))
	}
	return out
}

// compareCaptureDigests requires the production capture digest of each audit
// to equal the in-process reference and the digest its event signed.
func compareCaptureDigests(t *testing.T, store *Store, auditIDs ...string) {
	t.Helper()
	ctx := context.Background()
	transaction, err := store.readerDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	for _, auditID := range auditIDs {
		production, err := integrityPayloadDigest(ctx, transaction, nil, auditID, integrityCaptureFinalized)
		if err != nil {
			t.Fatal(err)
		}
		reference, err := referenceIntegrityPayloadDigest(ctx, transaction, nil, auditID, integrityCaptureFinalized)
		if err != nil {
			t.Fatal(err)
		}
		var signed []byte
		if err := transaction.QueryRowContext(ctx, `SELECT payload_digest FROM integrity_events WHERE audit_id = $1 AND event_type = 'capture_finalized'`, auditID).Scan(&signed); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(production, reference) || !bytes.Equal(production, signed) {
			t.Fatalf("%s: production %x, reference %x, signed %x", auditID, production, reference, signed)
		}
	}
}

func TestCaptureV2WritesAndReadsBack(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cipher := v2TestCipher(t)
	store, _ := openSignedStore(t)
	writeV2Audit(t, store, cipher, v2Audit{id: "v2-full"})
	writeV1Audit(t, store, cipher, "v1-full")

	var version, headerRows, blocks int
	var userAgent []byte
	if err := store.readerDB.QueryRow(`
SELECT a.capture_version, a.user_agent_enc,
       (SELECT COUNT(*) FROM http_headers WHERE audit_id = a.audit_id),
       (SELECT COUNT(*) FROM http_header_blocks WHERE audit_id = a.audit_id)
FROM audit_records AS a WHERE a.audit_id = 'v2-full'`).Scan(&version, &userAgent, &headerRows, &blocks); err != nil {
		t.Fatal(err)
	}
	if version != 2 || len(userAgent) == 0 || headerRows != 0 || blocks != 1 {
		t.Fatalf("v2 audit: version %d, user agent %d bytes, %d header rows, %d blocks", version, len(userAgent), headerRows, blocks)
	}
	contents := map[string]string{}
	rows, err := store.readerDB.Query(`SELECT stage, COALESCE(content_type, '<null>'), COALESCE(content_encoding, '<null>') FROM http_stages WHERE audit_id = 'v2-full'`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var stage, contentType, contentEncoding string
		if err := rows.Scan(&stage, &contentType, &contentEncoding); err != nil {
			t.Fatal(err)
		}
		contents[stage] = contentType + " " + contentEncoding
	}
	rows.Close()
	wantContents := map[string]string{
		StageRequestReceived:  "application/json <null>",
		StageRequestSent:      "application/json <null>",
		StageResponseReceived: "text/event-stream gzip",
		StageResponseSent:     "text/event-stream <null>",
	}
	if !reflect.DeepEqual(contents, wantContents) {
		t.Fatalf("content columns = %v", contents)
	}

	// The detail of the version 2 audit expands to the same flat list as the
	// same request stored as version 1.
	v1, err := expandDetail(t, store, cipher, "v1-full")
	if err != nil {
		t.Fatal(err)
	}
	v2, err := expandDetail(t, store, cipher, "v2-full")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(flatHeaders(v1), flatHeaders(v2)) || len(v2) != 14 {
		t.Fatalf("expanded headers differ:\n v1 %v\n v2 %v", flatHeaders(v1), flatHeaders(v2))
	}

	page, err := store.ListAudits(ctx, AuditQueryFilter{}, AuditQueryCursor{}, 10)
	if err != nil || len(page.Rows) != 2 {
		t.Fatalf("list: %d rows, %v", len(page.Rows), err)
	}
	for _, row := range page.Rows {
		switch row.AuditID {
		case "v2-full":
			values, err := headerblock.OpenUserAgent(cipher, row.AuditID, row.UserAgentEnc)
			if row.CaptureVersion != 2 || err != nil || !reflect.DeepEqual(values, []string{"client.example/1.0", "second-agent"}) {
				t.Fatalf("v2 list row: version %d, user agent %v, %v", row.CaptureVersion, values, err)
			}
		case "v1-full":
			if row.CaptureVersion != 1 || row.UserAgentEnc != nil {
				t.Fatalf("v1 list row: version %d, user agent %v", row.CaptureVersion, row.UserAgentEnc)
			}
		}
	}

	for _, stage := range []string{StageRequestReceived, StageResponseReceived} {
		loaded, err := store.LoadParserStage(ctx, "v2-full", stage)
		if err != nil || loaded.CaptureVersion != 2 || len(loaded.Headers) != 0 || loaded.ContentType == nil {
			t.Fatalf("parser stage %s: %+v, %v", stage, loaded, err)
		}
		if stage == StageResponseReceived && (loaded.ContentEncoding == nil || *loaded.ContentEncoding != "gzip") {
			t.Fatalf("parser content encoding = %v", loaded.ContentEncoding)
		}
		legacy, err := store.LoadParserStage(ctx, "v1-full", stage)
		if err != nil || legacy.CaptureVersion != 1 || len(legacy.Headers) == 0 || legacy.ContentType != nil {
			t.Fatalf("v1 parser stage %s: %+v, %v", stage, legacy, err)
		}
	}
	source, err := store.LoadParserHeaderSource(ctx, "v2-full", []string{"x-agent-id"})
	if err != nil || source.CaptureVersion != 2 || source.Block == nil || len(source.Rows) != 0 || len(source.StageSet) != 4 {
		t.Fatalf("parser header source: %+v, %v", source, err)
	}
	legacySource, err := store.LoadParserHeaderSource(ctx, "v1-full", []string{"x-agent-id"})
	if err != nil || legacySource.CaptureVersion != 1 || legacySource.Block != nil || len(legacySource.Rows) != 1 {
		t.Fatalf("v1 parser header source: %+v, %v", legacySource, err)
	}
	snapshot, err := store.Snapshot(ctx, "v2-full")
	if err != nil || snapshot.HeaderBlock == nil || snapshot.Audit.CaptureVersion != 2 || len(snapshot.Audit.UserAgentEnc) == 0 || len(snapshot.Headers) != 0 {
		t.Fatalf("snapshot: %+v, %v", snapshot.Audit, err)
	}

	if err := store.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatalf("v1 and v2 side by side: %v", err)
	}
	compareCaptureDigests(t, store, "v2-full", "v1-full")
}

// The block of a version 2 audit is overwritten by each write and, at the
// commit, left as the last checkpoint wrote it when nothing changed.
func TestCaptureV2CommitWithoutBlockKeepsTheCheckpointBlock(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cipher := v2TestCipher(t)
	store, _ := openSignedStore(t)
	stages := v2TestStages()[:2]
	writeV2Audit(t, store, cipher, v2Audit{id: "v2-short", stages: stages, stopAfter: 2})
	var before []byte
	if err := store.readerDB.QueryRow(`SELECT block_enc FROM http_header_blocks WHERE audit_id = 'v2-short'`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	commit := AuditCommit{CaptureVersion: CaptureVersion2, Finish: AuditFinish{AuditID: "v2-short", EndedAtNS: 2000, ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParsePending}}
	for index, stage := range stages {
		final := v2StageRow("v2-short", stage, int64(1001+index))
		final.State = StageStateComplete
		ended := int64(1900)
		final.EndedAtNS = &ended
		commit.Stages = append(commit.Stages, StageCommit{Stage: final, StageWritten: true})
	}
	if _, err := store.CommitAudit(ctx, commit); err != nil {
		t.Fatal(err)
	}
	var after []byte
	if err := store.readerDB.QueryRow(`SELECT block_enc FROM http_header_blocks WHERE audit_id = 'v2-short'`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("a commit without a block rewrote the block")
	}
	if _, err := expandDetail(t, store, cipher, "v2-short"); err != nil {
		t.Fatal(err)
	}
	// A commit of the other version is rejected and leaves the audit open.
	writeV2Audit(t, store, cipher, v2Audit{id: "v2-mismatch", stopAfter: 1})
	mismatch := AuditCommit{Finish: AuditFinish{AuditID: "v2-mismatch", EndedAtNS: 2000, ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParsePending}}
	if _, err := store.CommitAudit(ctx, mismatch); err == nil || !strings.Contains(err.Error(), "capture version differs") {
		t.Fatalf("version 1 commit of a version 2 audit = %v", err)
	}
	if err := store.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatal(err)
	}
}

// Recovery after a crash signs the incomplete block the last checkpoint wrote
// (D.4), and the record still reads.
func TestCaptureV2RecoverySignsTheIncompleteBlock(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cipher := v2TestCipher(t)
	store, _ := openSignedStore(t)
	writeV2Audit(t, store, cipher, v2Audit{id: "v2-begin", stopAfter: 1})
	writeV2Audit(t, store, cipher, v2Audit{id: "v2-checkpoint", stopAfter: 2})
	recovered, err := store.RecoverInterruptedAudits(ctx, 5000)
	if err != nil || recovered != 2 {
		t.Fatalf("recovered %d: %v", recovered, err)
	}
	for id, stages := range map[string]int{"v2-begin": 1, "v2-checkpoint": 2} {
		values, err := expandDetail(t, store, cipher, id)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		seen := map[string]bool{}
		trailers := 0
		for _, value := range values {
			seen[value.Stage] = true
			if value.Kind == storage.HeaderKindTrailer {
				trailers++
			}
		}
		if len(seen) != stages || (id == "v2-checkpoint") != (trailers == 1) {
			t.Fatalf("%s: headers of %d stages, %d trailers", id, len(seen), trailers)
		}
	}
	if err := store.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatal(err)
	}
	compareCaptureDigests(t, store, "v2-begin", "v2-checkpoint")
}

// A rejected inbound part keeps the start row on version 2 as on version 1:
// a rejected block keeps the stage (marked capture_headers_failed), a
// rejected stage row reports storage.ErrInboundStageNotStored.
func TestCaptureV2InboundRejectionKeepsTheStartRow(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		table, condition string
		lost             bool
	}{
		{"http_header_blocks", "true", false},
		{"http_stages", "NEW.stage = 'request_for_newapi_received_from_nginx'", true},
	} {
		t.Run(test.table, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			cipher := v2TestCipher(t)
			store, _ := openSignedStore(t)
			injectInsertFailure(t, store, test.table, test.condition)
			stages := v2TestStages()
			userAgent, _ := headerblock.SealUserAgent(cipher, "v2-inbound", headerblock.UserAgentValues(headerblock.Snapshot(stages[0].headers)))
			record := testAudit("v2-inbound")
			record.CaptureVersion = CaptureVersion2
			record.UserAgentEnc = userAgent
			record.Inbound = &InboundStage{Stage: v2StageRow("v2-inbound", stages[0], 2), HeaderBlock: sealV2Block(t, cipher, "v2-inbound", stages[:1], nil)}
			err := store.BeginAudit(ctx, record)
			if test.lost != errors.Is(err, storage.ErrInboundStageNotStored) || (!test.lost && err != nil) {
				t.Fatalf("BeginAudit = %v", err)
			}
			var captureStatus, errorCode string
			var stageState, stageError sql.NullString
			if err := store.readerDB.QueryRow(`
SELECT a.capture_status, a.error_code, s.state, s.error_code
FROM audit_records AS a LEFT JOIN http_stages AS s ON s.audit_id = a.audit_id
WHERE a.audit_id = 'v2-inbound'`).Scan(&captureStatus, &errorCode, &stageState, &stageError); err != nil {
				t.Fatal(err)
			}
			if captureStatus != CaptureFailed || errorCode != "capture_write_failed" || test.lost == stageState.Valid {
				t.Fatalf("start row: %s %s, stage %v %v", captureStatus, errorCode, stageState, stageError)
			}
			if !test.lost && (stageState.String != StageStatePartial || stageError.String != "capture_headers_failed") {
				t.Fatalf("inbound stage not marked: %v %v", stageState, stageError)
			}
			assertTableCount(t, store.readerDB, "http_header_blocks", 0)
			dropInjectedFailure(t, store, test.table)
			if _, err := store.RecoverInterruptedAudits(ctx, 5000); err != nil {
				t.Fatal(err)
			}
			if err := store.VerifyIntegrityPayloads(ctx); err != nil {
				t.Fatal(err)
			}
			// With the block rejected and no later write (an interceptor
			// rejection, or a crash before checkpoint 1), the stage row has no
			// block. The audit is failed, so it reads like legacy after a
			// rejected header write: the stage's Headers are absent.
			values, err := expandDetail(t, store, cipher, "v2-inbound")
			if err != nil || len(values) != 0 {
				t.Fatalf("Expand = %v, %v", flatHeaders(values), err)
			}
		})
	}
}

// I.5: every tamper of a version 1 or 2 audit is detected, each by the layer
// that can see it.
func TestCaptureV2TamperIsDetected(t *testing.T) {
	t.Parallel()
	flip := func(column string) string {
		return column + ` = set_byte(` + column + `, 0, get_byte(` + column + `, 0) # 1)`
	}
	for _, test := range []struct {
		name   string
		mutate []string
	}{
		{"capture_version 2 to 1", []string{`UPDATE audit_records SET capture_version = 1 WHERE audit_id = 'v2-tamper'`}},
		{"capture_version 1 to 2", []string{`UPDATE audit_records SET capture_version = 2 WHERE audit_id = 'v1-tamper'`}},
		{"capture_version another value", []string{
			`ALTER TABLE audit_records DROP CONSTRAINT audit_records_capture_version_check`,
			`UPDATE audit_records SET capture_version = 3 WHERE audit_id = 'v2-tamper'`}},
		{"user_agent_enc", []string{`UPDATE audit_records SET ` + flip("user_agent_enc") + ` WHERE audit_id = 'v2-tamper'`}},
		{"user_agent_enc removed", []string{`UPDATE audit_records SET user_agent_enc = NULL WHERE audit_id = 'v2-tamper'`}},
		{"block ciphertext", []string{`UPDATE http_header_blocks SET ` + flip("block_enc") + ` WHERE audit_id = 'v2-tamper'`}},
		{"block length", []string{`UPDATE http_header_blocks SET plaintext_length = plaintext_length + 1 WHERE audit_id = 'v2-tamper'`}},
		{"block compression", []string{`UPDATE http_header_blocks SET compression = CASE compression WHEN 'gzip' THEN 'none' ELSE 'gzip' END WHERE audit_id = 'v2-tamper'`}},
		{"content_type", []string{`UPDATE http_stages SET content_type = 'text/plain' WHERE audit_id = 'v2-tamper' AND stage = 'response_received_from_newapi'`}},
		{"content_encoding", []string{`UPDATE http_stages SET content_encoding = NULL WHERE audit_id = 'v2-tamper' AND stage = 'response_received_from_newapi'`}},
		{"block row deleted", []string{`DELETE FROM http_header_blocks WHERE audit_id = 'v2-tamper'`}},
		// capture_status is a field of both digests, so marking a healthy
		// audit failed, alone or to hide a removed block from the read path,
		// fails payload verification.
		{"capture_status flipped to failed", []string{`UPDATE audit_records SET capture_status = 'failed' WHERE audit_id = 'v2-tamper'`}},
		{"block deleted and capture_status flipped", []string{
			`DELETE FROM http_header_blocks WHERE audit_id = 'v2-tamper'`,
			`UPDATE audit_records SET capture_status = 'failed' WHERE audit_id = 'v2-tamper'`}},
		{"version 1 capture_status flipped to failed", []string{`UPDATE audit_records SET capture_status = 'failed' WHERE audit_id = 'v1-tamper'`}},
		// forward_status is a field of both digests too: marking a healthy
		// audit interrupted, the other way into the relaxed read, fails
		// payload verification as well.
		{"forward_status flipped to interrupted", []string{`UPDATE audit_records SET forward_status = 'interrupted' WHERE audit_id = 'v2-tamper'`}},
		{"block deleted and forward_status flipped", []string{
			`DELETE FROM http_header_blocks WHERE audit_id = 'v2-tamper'`,
			`UPDATE audit_records SET forward_status = 'interrupted' WHERE audit_id = 'v2-tamper'`}},
		{"version 1 forward_status flipped to interrupted", []string{`UPDATE audit_records SET forward_status = 'interrupted' WHERE audit_id = 'v1-tamper'`}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			cipher := v2TestCipher(t)
			store, _ := openSignedStore(t)
			writeV2Audit(t, store, cipher, v2Audit{id: "v2-tamper"})
			writeV1Audit(t, store, cipher, "v1-tamper")
			if err := store.VerifyIntegrityPayloads(ctx); err != nil {
				t.Fatalf("untouched audits failed verification: %v", err)
			}
			for _, statement := range test.mutate {
				result, err := store.writerConn.ExecContext(ctx, statement)
				if err != nil {
					t.Fatalf("%s: %v", statement, err)
				}
				if affected, _ := result.RowsAffected(); strings.HasPrefix(statement, "UPDATE") && affected != 1 {
					t.Fatalf("%s affected %d rows", statement, affected)
				}
			}
			if err := store.VerifyIntegrityPayloads(ctx); err == nil {
				t.Fatal("payload verification accepted the tampered audit")
			}
			if state := store.IntegrityPayloadState(); state != "failed" {
				t.Fatalf("payload state = %q", state)
			}
		})
	}
	// Header rows inserted into a version 2 audit and a block added to a
	// version 1 audit are outside that version's digest (D.1, D.2), and a
	// block whose stages do not match the stage rows is signed as written; all
	// three are caught where the Headers are read.
	t.Run("read path", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		cipher := v2TestCipher(t)
		store, _ := openSignedStore(t)
		writeV2Audit(t, store, cipher, v2Audit{id: "v2-short-block", commitBlock: func(t *testing.T, cipher security.Cipher, id string, stages []v2Stage) *HeaderBlock {
			return sealV2Block(t, cipher, id, stages[:3], nil)
		}})
		writeV2Audit(t, store, cipher, v2Audit{id: "v2-rows"})
		writeV1Audit(t, store, cipher, "v1-block")
		if err := store.VerifyIntegrityPayloads(ctx); err != nil {
			t.Fatalf("payload verification: %v", err)
		}
		if _, err := store.writerConn.ExecContext(ctx, `INSERT INTO http_header_blocks SELECT 'v1-block', compression, plaintext_length, block_enc FROM http_header_blocks WHERE audit_id = 'v2-rows'`); err != nil {
			t.Fatal(err)
		}
		if _, err := store.writerConn.ExecContext(ctx, `INSERT INTO http_headers (audit_id, stage, kind, name, value_index, value_length, value_enc)
VALUES ('v2-rows', 'request_for_newapi_received_from_nginx', 'header', 'X-Injected', 0, 1, '\x01')`); err != nil {
			t.Fatal(err)
		}
		if err := store.VerifyIntegrityPayloads(ctx); err != nil {
			t.Fatalf("payload verification after the read-path tampers: %v", err)
		}
		for _, id := range []string{"v2-short-block", "v2-rows", "v1-block"} {
			if _, err := expandDetail(t, store, cipher, id); !errors.Is(err, headerblock.ErrIntegrity) {
				t.Fatalf("%s: Expand = %v", id, err)
			}
		}
	})
}

// I.5: a version 6 database with version 1 audits and every kind of
// integrity event upgrades to 7 and verifies in full, and keeps verifying
// once version 2 audits join it.
func TestVersionSixDatabaseUpgradesAndVerifies(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, dsn := openTestStore(t)
	targets := buildDigestFixture(t, store, graphTestCipher(t))
	var v1Targets []digestTarget
	for _, target := range targets {
		if !strings.HasPrefix(target.AuditID, "digest-capture-v2") {
			v1Targets = append(v1Targets, target)
		}
	}
	if _, err := store.writerConn.ExecContext(ctx, `DELETE FROM audit_records WHERE capture_version = 2`); err != nil {
		t.Fatal(err)
	}
	signer, err := security.NewIntegritySigner(v2TestKey)
	if err != nil {
		t.Fatal(err)
	}
	signDigestFixture(t, store, signer, v1Targets, integrityPayloadDigest)
	kinds := map[string]bool{}
	for _, target := range v1Targets {
		kinds[target.EventType] = true
	}
	if len(kinds) != 3 {
		t.Fatalf("fixture event kinds = %v", kinds)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.ExecContext(ctx, rollbackToSchemaSixSQL); err != nil {
		t.Fatal(err)
	}
	requireVersions(t, appliedSchemaVersions(t, admin), 1, 2, 3, 4, 5, 6)
	// The version 6 database verifies without a capture_version column.
	transaction, err := admin.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyIntegrityChainTransaction(ctx, transaction, signer); err != nil {
		t.Fatal(err)
	}
	if err := verifyIntegrityPayloadsTransaction(ctx, transaction, schemaBaseline); err != nil {
		t.Fatalf("version 6 payloads: %v", err)
	}
	_ = transaction.Rollback()

	upgraded, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upgraded.Close() })
	if err := upgraded.EnableIntegrity(ctx, v2TestKey); err != nil {
		t.Fatalf("chain after upgrade: %v", err)
	}
	if err := upgraded.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatalf("payloads after upgrade: %v", err)
	}
	cipher := v2TestCipher(t)
	writeV2Audit(t, upgraded, cipher, v2Audit{id: "v2-after-upgrade"})
	writeV1Audit(t, upgraded, cipher, "v1-after-upgrade")
	if err := upgraded.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatalf("v1 and v2 side by side: %v", err)
	}
	if state := upgraded.IntegrityPayloadState(); state != "verified" {
		t.Fatalf("payload state = %q", state)
	}
}

// A checkpoint rejected inside the writer is rolled back whole, and the
// session, which is not told, sends a later block that still names the
// stage it inserted. The store cannot open the block to drop that section,
// so it writes it as sent. The audit is finalized failed, its payload
// verifies, and it stays readable: the section of the stage without a row is
// shown (it is stored and authentic). A healthy audit with the same mismatch
// is an integrity error (TestCaptureV2TamperIsDetected, read path).
func TestCaptureV2RejectedCheckpointStaysReadable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cipher := v2TestCipher(t)
	store, _ := openSignedStore(t)
	injectInsertFailure(t, store, "http_stages", "NEW.stage = 'request_sent_to_newapi'")
	writeV2Audit(t, store, cipher, v2Audit{id: "v2-rejected"})
	var captureStatus string
	var stages int
	if err := store.readerDB.QueryRow(`SELECT capture_status, (SELECT COUNT(*) FROM http_stages WHERE audit_id = 'v2-rejected') FROM audit_records WHERE audit_id = 'v2-rejected'`).Scan(&captureStatus, &stages); err != nil {
		t.Fatal(err)
	}
	if captureStatus != CaptureFailed || stages != 3 {
		t.Fatalf("audit %s with %d stage rows", captureStatus, stages)
	}
	if err := store.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatalf("payload verification: %v", err)
	}
	values, err := expandDetail(t, store, cipher, "v2-rejected")
	if err != nil {
		t.Fatalf("Expand of a failed capture = %v", err)
	}
	expanded := map[string]bool{}
	for _, value := range values {
		expanded[value.Stage] = true
	}
	if len(expanded) != 4 || !expanded[StageRequestSent] {
		t.Fatalf("expanded stages %v", expanded)
	}
}
