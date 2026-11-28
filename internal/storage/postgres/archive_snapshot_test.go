package postgres

import (
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/archive/bundle"
	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/security"
)

// These tests need a real PostgreSQL (TEST_DATABASE_URL) and skip otherwise.
// They are the first end-to-end proof that the export snapshot, the format
// core (internal/archive) and the bundle layer (internal/archive/bundle) fit.

func archiveTestKeys(t *testing.T) *security.ArchiveKeys {
	t.Helper()
	keys, err := security.DeriveArchiveKeys(v2TestKey)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func archiveTestSigner(t *testing.T) *security.IntegritySigner {
	t.Helper()
	signer, err := security.NewIntegritySigner(v2TestKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func openArchiveSnapshot(t *testing.T, store *Store, cipher security.Cipher) *ArchiveSnapshot {
	t.Helper()
	snapshot, err := store.OpenArchiveSnapshot(context.Background(), ArchiveSnapshotOptions{Cipher: cipher, Fingerprinter: archiveTestKeys(t)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = snapshot.Close() })
	return snapshot
}

// archiveTurnSpec is how parseArchiveAudit finishes an audit's parse: a turn
// built from synthetic items, or no turn, and the parsed JSON to store.
type archiveTurnSpec struct {
	request, response              []graphTestItem
	previousResponseID, responseID string
	createdAtNS                    int64
	conversationKey                string
	requestOnly                    bool
	noTurn                         bool
	status                         string
	errorCode                      string
	parsedJSON                     []byte
}

// parseArchiveAudit claims a pending parse and saves its result through the
// store as the parse worker does.
func parseArchiveAudit(t *testing.T, store *Store, cipher security.Cipher, auditID string, spec archiveTurnSpec) {
	t.Helper()
	ctx := context.Background()
	claimed, err := store.ClaimPendingParse(ctx, auditID)
	if err != nil || !claimed {
		t.Fatalf("claim %s = %v, %v", auditID, claimed, err)
	}
	status := spec.status
	if status == "" {
		status = ParseOK
	}
	parsed := ParsedAudit{Result: ParsedResult{AuditID: auditID, ParserName: "openai.chat_completions", ParserVersion: "2",
		Status: status, ParsedAtNS: spec.createdAtNS + 1}}
	if spec.errorCode != "" {
		code := spec.errorCode
		parsed.Result.ErrorCode = &code
	}
	if spec.parsedJSON != nil {
		if parsed.Result.ParsedJSONEnc, err = auditmodel.SealParsedResult(cipher, auditID, "openai.chat_completions", spec.parsedJSON); err != nil {
			t.Fatal(err)
		}
	}
	if !spec.noTurn {
		requestItems, requestValues, requestMarkers := graphSide(spec.request)
		responseItems, responseValues, responseMarkers := graphSide(spec.response)
		turn := auditmodel.Turn{
			AuditID: auditID, Protocol: "openai", ParserName: "openai.chat_completions",
			RequestLayout: auditmodel.LayoutMarkerEnvelope, ResponseLayout: auditmodel.LayoutMarkerEnvelope,
			RequestEnvelope:  map[string]any{"model": "model-example", "items": requestMarkers},
			ResponseEnvelope: map[string]any{"id": spec.responseID, "items": responseMarkers},
			RequestItems:     requestItems, ResponseItems: responseItems,
			RequestOriginal:    map[string]any{"model": "model-example", "items": requestValues},
			ResponseOriginal:   map[string]any{"id": spec.responseID, "items": responseValues},
			PreviousResponseID: spec.previousResponseID, ResponseID: spec.responseID,
			ConversationKey: spec.conversationKey, CreatedAtNS: spec.createdAtNS,
		}
		if spec.requestOnly {
			turn.ResponseLayout, turn.ResponseEnvelope, turn.ResponseOriginal, turn.ResponseItems = auditmodel.LayoutNone, nil, nil, nil
		}
		prepared, err := auditmodel.Prepare(turn, cipher)
		if err != nil {
			t.Fatalf("prepare %s: %v", auditID, err)
		}
		parsed.Turn = &prepared
	}
	if err := store.SaveParsedAudit(ctx, parsed); err != nil {
		t.Fatalf("save %s: %v", auditID, err)
	}
}

func fallbackJSON(t *testing.T, key string, size int) []byte {
	t.Helper()
	messages := []map[string]any{}
	for index := 0; index < size; index++ {
		messages = append(messages, map[string]any{"role": "user", "content": strings.Repeat("fallback text ", 4)})
	}
	value, err := json.Marshal(map[string]any{"status": "ok", key: map[string]any{"schema_version": conversation.SchemaVersion, "messages": messages}})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

// exportAll exports every id in one snapshot and requires each record to be
// canonical and its digest to recompute.
func exportAll(t *testing.T, snapshot *ArchiveSnapshot, ids []string) map[string]*ArchiveExport {
	t.Helper()
	exports := map[string]*ArchiveExport{}
	for _, id := range ids {
		export, err := snapshot.Export(id, 1)
		if err != nil {
			t.Fatalf("export %s: %v", id, err)
		}
		if err := export.Record.CheckCanonical(); err != nil {
			t.Fatalf("export %s is not canonical: %v", id, err)
		}
		digest, err := archive.Digest(export.Record)
		if err != nil || digest != export.Digest {
			t.Fatalf("export %s digest does not recompute: %v", id, err)
		}
		exports[id] = export
	}
	return exports
}

// writeAndVerifyBundle writes the given audits, in order, as one segment
// from a fresh snapshot (which serves the payloads), publishes it, re-reads
// it with bundle.Open(...).Verify and requires the report's digests to equal
// the snapshot's. It returns the report and the exports.
// archiveTestRuns gives every test bundle its own run id: bundle names carry
// its first eight digits, and two bundles of one conversation written in the
// same second would otherwise get the same name.
var archiveTestRuns atomic.Uint64

func writeAndVerifyBundle(t *testing.T, store *Store, cipher security.Cipher, root string, spec bundle.Spec, ids []string) (*bundle.Report, map[string]*ArchiveExport, map[string]string) {
	t.Helper()
	keys := archiveTestKeys(t)
	snapshot := openArchiveSnapshot(t, store, cipher)
	exports := exportAll(t, snapshot, ids)
	writer, err := bundle.NewSegment(bundle.Options{
		Root: root, Signer: keys, Encrypt: true, EncryptionKey: keys.EncryptionKey(),
		SourceSchemaVersion: "8", RunID: fmt.Sprintf("%08x%024x", archiveTestRuns.Add(1), 0),
	}, spec, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if err := writer.Add(exports[id].Record); err != nil {
			t.Fatalf("add %s: %v", id, err)
		}
	}
	sealed, err := writer.Seal()
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := snapshot.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sealed.Publish(); err != nil {
		t.Fatalf("publish: %v", err)
	}
	opened, err := bundle.Open(sealed.ManifestPath(), bundle.ReadOptions{Signer: keys, EncryptionKey: keys.EncryptionKey(), Events: archiveTestSigner(t)})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	report, err := opened.Verify(context.Background())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(report.Members) != len(ids) {
		t.Fatalf("report members = %d, want %d", len(report.Members), len(ids))
	}
	for index, member := range report.Members {
		export := exports[ids[index]]
		if member.AuditID != ids[index] || member.Revision != 1 || member.Digest != export.Digest {
			t.Fatalf("member %d = %+v, want %s with the snapshot's digest", index, member, ids[index])
		}
	}
	// The request context form each turn's line carries (C.4).
	forms := map[string]string{}
	if err := opened.Records(context.Background(), func(line bundle.Line) error {
		if line.Record.Turn != nil {
			forms[line.Record.Audit.AuditID] = line.Record.Turn.Context.Form
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return report, exports, forms
}

func imageItem() graphTestItem {
	data := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0x61, 0x17}, 300)...)
	return graphItem("image", map[string]any{"image_url": "data:image/png;base64," + base64.StdEncoding.EncodeToString(data)})
}

func userItem(text string) graphTestItem {
	return graphItem("user_message", map[string]any{"role": "user", "content": text})
}

func assistantItem(text string) graphTestItem {
	return graphItem("assistant_message", map[string]any{"role": "assistant", "content": text})
}

func parsedJSONStoredCompressed(t *testing.T, store *Store, cipher security.Cipher, auditID string) bool {
	t.Helper()
	var enc []byte
	if err := store.readerDB.QueryRow(`SELECT parsed_json_enc FROM parsed_results WHERE audit_id = $1`, auditID).Scan(&enc); err != nil {
		t.Fatal(err)
	}
	aad, _ := security.AAD(auditID, "parsed_json", "openai.chat_completions")
	payload, err := cipher.Decrypt(aad, enc)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.HasPrefix(payload, []byte{0x1f, 0x8b})
}

func TestArchiveSnapshotExportsVerifiableBundles(t *testing.T) {
	ctx := context.Background()
	store, _ := openSignedStore(t)
	cipher := v2TestCipher(t)
	root := t.TempDir()

	// Capture version 2 through the real unified session; turns saved
	// through the store as the parse worker saves them.
	root1 := runSession(t, store, cipher, typicalV2Drive(), crashNone)
	parseArchiveAudit(t, store, cipher, root1, archiveTurnSpec{
		request: []graphTestItem{userItem("first question")}, response: []graphTestItem{assistantItem("first answer")},
		responseID: "resp-1", createdAtNS: 100, conversationKey: "conversation-example", parsedJSON: []byte(`{"status":"ok"}`),
	})
	child := runSession(t, store, cipher, typicalV2Drive(), crashNone)
	parseArchiveAudit(t, store, cipher, child, archiveTurnSpec{
		request:    []graphTestItem{userItem("first question"), assistantItem("first answer"), userItem("second"), imageItem()},
		response:   []graphTestItem{assistantItem("second answer")},
		responseID: "resp-2", previousResponseID: "resp-1", createdAtNS: 200, conversationKey: "conversation-example",
	})
	// A second child of the same parent (a branch), request-only with the
	// half answer in parsed_json, large enough to be stored compressed.
	branch := runSession(t, store, cipher, typicalV2Drive(), crashNone)
	parseArchiveAudit(t, store, cipher, branch, archiveTurnSpec{
		request:    []graphTestItem{userItem("first question"), assistantItem("first answer"), userItem("branch")},
		responseID: "resp-3", previousResponseID: "resp-1", createdAtNS: 300, conversationKey: "conversation-example",
		requestOnly: true, status: ParsePartial, parsedJSON: fallbackJSON(t, "partial_response_messages", 200),
	})
	// No turn: the fallback conversation in parsed_json (compressed), raw kept.
	turnless := runSession(t, store, cipher, typicalV2Drive(), crashNone)
	parseArchiveAudit(t, store, cipher, turnless, archiveTurnSpec{noTurn: true, createdAtNS: 400, parsedJSON: fallbackJSON(t, "conversation", 200)})
	// An interrupted capture with partial bodies, finalized by recovery.
	interrupted := runSession(t, store, cipher, typicalV2Drive(), crashResponseHalf)
	if _, err := store.RecoverInterruptedAudits(ctx, 5_000_000_000_000_000_000); err != nil {
		t.Fatal(err)
	}
	parseArchiveAudit(t, store, cipher, interrupted, archiveTurnSpec{noTurn: true, createdAtNS: 500, status: ParseError, errorCode: "parse_failed"})
	// Capture version 1 built with the store's per-operation writes: a
	// normal turn, and a failed capture with a partial request body, no turn
	// and a small plain fallback.
	writePerSideAudit(t, store, cipher, perSideAudit{id: "v1-turn", status: perSideStatus(200), forward: ForwardCompleted, capture: CaptureComplete})
	writePerSideAudit(t, store, cipher, perSideAudit{id: "v1-failed", status: perSideStatus(502), forward: ForwardNewAPIError, capture: CaptureFailed,
		mismatch: true, noTurn: true, parse: ParsePartial, fallback: &conversation.Conversation{SchemaVersion: conversation.SchemaVersion}})

	if !parsedJSONStoredCompressed(t, store, cipher, turnless) || parsedJSONStoredCompressed(t, store, cipher, root1) {
		t.Fatal("fixture: parsed_json_enc forms are not one compressed and one plain")
	}

	// The conversation bundle: parent first, then its two children.
	conversationID := ""
	if err := store.readerDB.QueryRow(`SELECT conversation_id FROM turns WHERE audit_id = $1`, root1).Scan(&conversationID); err != nil {
		t.Fatal(err)
	}
	conversationIDs := []string{root1, child, branch}
	_, exports, forms := writeAndVerifyBundle(t, store, cipher, root, bundle.Spec{Kind: archive.BundleConversation, Protocol: "openai", ConversationID: conversationID, Index: 1}, conversationIDs)
	for _, id := range conversationIDs {
		turn := exports[id].Record.Turn
		if turn == nil || turn.Row.ConversationID != conversationID || exports[id].TurnCreatedAtNS == nil || *exports[id].TurnCreatedAtNS != turn.Row.CreatedAtNS {
			t.Fatalf("%s turn = %+v", id, turn)
		}
	}
	if forms[root1] != archive.ContextDelta || forms[child] != archive.ContextDelta || forms[branch] != archive.ContextDelta {
		t.Fatalf("context forms in the conversation bundle = %v", forms)
	}
	if parent := exports[child].Record.Turn.Row.ParentTurnID; parent == nil || *parent != exports[root1].Record.Turn.Row.TurnID {
		t.Fatalf("child parent = %v", parent)
	}
	if parent := exports[branch].Record.Turn.Row.ParentTurnID; parent == nil || *parent != exports[root1].Record.Turn.Row.TurnID {
		t.Fatalf("branch parent = %v", parent)
	}
	if len(exports[child].Record.Turn.Binaries) != 1 || len(exports[child].Record.Turn.BinaryRefs) != 1 {
		t.Fatalf("child binaries = %+v", exports[child].Record.Turn.Binaries)
	}
	if exports[branch].Record.Turn.Row.ResponseLayout != auditmodel.LayoutNone || !bytes.Contains(exports[branch].Record.ParsedResult.ParsedJSON, []byte("partial_response_messages")) {
		t.Fatal("branch is not a request-only turn with its half answer")
	}
	// The unified session merged the identical request pair.
	merged := false
	for _, body := range exports[root1].Record.Bodies {
		merged = merged || body.Stage == StageRequestSent && body.SourceStage == StageRequestReceived
	}
	if !merged || exports[root1].Record.Headers.CaptureVersion != CaptureVersion2 || !exports[root1].Record.Headers.BlockPresent {
		t.Fatalf("root bodies %+v, headers %+v", exports[root1].Record.Bodies, exports[root1].Record.Headers.BlockStages)
	}

	// The bucket: the v1 turn's conversation first, then the audits without a
	// turn by (started_at_ns, audit_id).
	turnlessIDs := []string{turnless, interrupted, "v1-failed"}
	starts := map[string]int64{}
	for _, id := range turnlessIDs {
		var started int64
		if err := store.readerDB.QueryRow(`SELECT started_at_ns FROM audit_records WHERE audit_id = $1`, id).Scan(&started); err != nil {
			t.Fatal(err)
		}
		starts[id] = started
	}
	slices.SortFunc(turnlessIDs, func(left, right string) int {
		return cmp.Or(cmp.Compare(starts[left], starts[right]), strings.Compare(left, right))
	})
	bucketIDs := append([]string{"v1-turn"}, turnlessIDs...)
	_, bucketExports, _ := writeAndVerifyBundle(t, store, cipher, root, bundle.Spec{Kind: archive.BundleBucket, Protocol: "openai", Index: 1}, bucketIDs)
	if record := bucketExports["v1-turn"].Record; record.Headers.CaptureVersion != CaptureVersion1 || record.Headers.BlockPresent || record.Turn == nil {
		t.Fatalf("v1 turn record headers %+v", record.Headers)
	}
	failed := bucketExports["v1-failed"].Record
	partial := false
	for _, body := range failed.Bodies {
		partial = partial || body.State == StageStatePartial
	}
	if failed.Audit.CaptureStatus != CaptureFailed || !partial || len(failed.RawChunks) == 0 || failed.Turn != nil {
		t.Fatalf("failed v1 record: capture %s, bodies %+v, chunks %d", failed.Audit.CaptureStatus, failed.Bodies, len(failed.RawChunks))
	}
	interruptedRecord := bucketExports[interrupted].Record
	partial = false
	for _, body := range interruptedRecord.Bodies {
		partial = partial || body.State == StageStatePartial && body.RetentionState == RetentionFull
	}
	if interruptedRecord.Audit.ForwardStatus != ForwardInterrupted || !partial {
		t.Fatalf("interrupted record forward status %s, bodies %+v", interruptedRecord.Audit.ForwardStatus, interruptedRecord.Bodies)
	}
	if record := bucketExports[turnless].Record; len(record.RawChunks) == 0 || !bytes.Contains(record.ParsedResult.ParsedJSON, []byte(`"conversation"`)) {
		t.Fatalf("turnless record chunks %d", len(record.RawChunks))
	}

	// The digests are stable across snapshots.
	all := append(append([]string(nil), conversationIDs...), bucketIDs...)
	again := exportAll(t, openArchiveSnapshot(t, store, cipher), all)
	for _, id := range all {
		if again[id].Digest != exportsOf(exports, bucketExports, id).Digest || again[id].ChangeStamp != exportsOf(exports, bucketExports, id).ChangeStamp {
			t.Fatalf("%s: digest or stamp differs between snapshots", id)
		}
	}

	// A conversation spanning two exports: a grandchild exported later, in a
	// segment of its own, carries its context materialised and verifies alone.
	grandchild := runSession(t, store, cipher, typicalV2Drive(), crashNone)
	parseArchiveAudit(t, store, cipher, grandchild, archiveTurnSpec{
		request:    []graphTestItem{userItem("first question"), assistantItem("first answer"), userItem("second"), imageItem(), assistantItem("second answer"), userItem("third")},
		response:   []graphTestItem{assistantItem("third answer")},
		responseID: "resp-4", previousResponseID: "resp-2", createdAtNS: 600, conversationKey: "conversation-example",
	})
	report, later, laterForms := writeAndVerifyBundle(t, store, cipher, root, bundle.Spec{Kind: archive.BundleConversation, Protocol: "openai", ConversationID: conversationID, Index: 1}, []string{grandchild})
	if parent := later[grandchild].Record.Turn.Row.ParentTurnID; parent == nil || *parent != exports[child].Record.Turn.Row.TurnID || report.ContentObjects == 0 || report.BinaryObjects != 1 {
		t.Fatalf("grandchild parent %v, report %+v", parent, report)
	}
	if laterForms[grandchild] != archive.ContextMaterialized {
		t.Fatalf("grandchild context form = %q", laterForms[grandchild])
	}
	if state := store.IntegrityPayloadState(); state == "failed" {
		t.Fatal("a clean export latched the payload state failed")
	}
}

func exportsOf(first, second map[string]*ArchiveExport, id string) *ArchiveExport {
	if export, ok := first[id]; ok {
		return export
	}
	return second[id]
}

// A damaged ciphertext and a tampered event exclude only their member: the
// other audits of the same snapshot export and bundle as before, and the
// store's payload state is failed, as after the background verification
// finds damage.
func TestArchiveSnapshotExcludesDamagedMembersOnly(t *testing.T) {
	ctx := context.Background()
	store, _ := openSignedStore(t)
	cipher := v2TestCipher(t)
	good := runSession(t, store, cipher, typicalV2Drive(), crashNone)
	parseArchiveAudit(t, store, cipher, good, archiveTurnSpec{noTurn: true, createdAtNS: 100})
	damaged := runSession(t, store, cipher, typicalV2Drive(), crashNone)
	parseArchiveAudit(t, store, cipher, damaged, archiveTurnSpec{noTurn: true, createdAtNS: 200})
	tampered := runSession(t, store, cipher, typicalV2Drive(), crashNone)
	parseArchiveAudit(t, store, cipher, tampered, archiveTurnSpec{noTurn: true, createdAtNS: 300})
	forged := runSession(t, store, cipher, typicalV2Drive(), crashNone)
	parseArchiveAudit(t, store, cipher, forged, archiveTurnSpec{noTurn: true, createdAtNS: 400})

	// No event covers the chunk ciphertext: AEAD catches it.
	if _, err := store.writerConn.ExecContext(ctx, `
UPDATE body_chunks SET data_enc = set_byte(data_enc, 20, get_byte(data_enc, 20) # 1)
WHERE audit_id = $1 AND seq = 0 AND stage = (SELECT MIN(stage) FROM body_chunks WHERE audit_id = $1)`, damaged); err != nil {
		t.Fatal(err)
	}
	if _, err := store.writerConn.ExecContext(ctx, `
UPDATE integrity_events SET payload_digest = set_byte(payload_digest, 0, get_byte(payload_digest, 0) # 1)
WHERE audit_id = $1 AND event_type = 'capture_finalized'`, tampered); err != nil {
		t.Fatal(err)
	}
	if _, err := store.writerConn.ExecContext(ctx, `
UPDATE integrity_events SET event_mac = set_byte(event_mac, 0, get_byte(event_mac, 0) # 1)
WHERE audit_id = $1 AND event_type = 'capture_finalized'`, forged); err != nil {
		t.Fatal(err)
	}

	snapshot := openArchiveSnapshot(t, store, cipher)
	want := map[string]string{damaged: ArchiveReasonDecrypt, tampered: ArchiveReasonEventPayload, forged: ArchiveReasonEventMAC}
	for _, id := range []string{damaged, good, tampered, forged, "missing-audit"} {
		export, err := snapshot.Export(id, 1)
		var member *ArchiveMemberError
		switch {
		case id == good:
			if err != nil || export == nil {
				t.Fatalf("good member: %v", err)
			}
		case id == "missing-audit":
			if !errors.As(err, &member) || member.Reason != ArchiveReasonNotFound || member.Integrity() {
				t.Fatalf("missing audit = %v", err)
			}
		default:
			if !errors.As(err, &member) || member.AuditID != id || member.Reason != want[id] || !member.Integrity() {
				t.Fatalf("%s = %v, want %s", id, err, want[id])
			}
		}
	}
	if err := snapshot.Close(); err != nil {
		t.Fatal(err)
	}
	if state := store.IntegrityPayloadState(); state != "failed" {
		t.Fatalf("payload state = %q", state)
	}
	_, _, _ = writeAndVerifyBundle(t, store, cipher, t.TempDir(), bundle.Spec{Kind: archive.BundleBucket, Protocol: "openai", Index: 1}, []string{good})
}

func TestArchiveSnapshotNeedsIntegrity(t *testing.T) {
	store, _ := openTestStore(t)
	if _, err := store.OpenArchiveSnapshot(context.Background(), ArchiveSnapshotOptions{Cipher: v2TestCipher(t), Fingerprinter: archiveTestKeys(t)}); err == nil {
		t.Fatal("snapshot opened without integrity")
	}
}

// Two shapes the main test does not bundle: a version 1 audit with header
// rows, one of them a credential, and a version 2 failed capture whose block
// has a section for a stage that has no row (the loose rule of
// headerblock.Expand).
func TestArchiveSnapshotBundlesHeaderShapes(t *testing.T) {
	ctx := context.Background()
	store, _ := openSignedStore(t)
	cipher := v2TestCipher(t)
	keys := archiveTestKeys(t)

	writeV1Audit(t, store, cipher, "v1-credential")
	uriAAD, _ := security.AAD("v1-credential", "request_uri")
	uri, err := cipher.Encrypt(uriAAD, []byte("/v1/chat/completions?key=synthetic-query-key&alt=sse"))
	if err != nil {
		t.Fatal(err)
	}
	mustExecWriter(t, store, `UPDATE audit_records SET request_uri_enc = $1 WHERE audit_id = 'v1-credential'`, uri)
	resignArchiveEvents(t, store, "v1-credential")
	parseArchiveAudit(t, store, cipher, "v1-credential", archiveTurnSpec{noTurn: true, createdAtNS: 3000})

	injectInsertFailure(t, store, "http_stages", "NEW.stage = 'request_sent_to_newapi'")
	writeV2Audit(t, store, cipher, v2Audit{id: "v2-rejected"})
	dropInjectedFailure(t, store, "http_stages")
	parseArchiveAudit(t, store, cipher, "v2-rejected", archiveTurnSpec{noTurn: true, createdAtNS: 3000, status: ParseError, errorCode: "parse_failed"})
	if err := store.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatal(err)
	}

	_, exports, _ := writeAndVerifyBundle(t, store, cipher, t.TempDir(), bundle.Spec{Kind: archive.BundleBucket, Protocol: "openai", Index: 1}, []string{"v1-credential", "v2-rejected"})

	v1 := exports["v1-credential"].Record
	if v1.Headers.CaptureVersion != CaptureVersion1 || v1.Headers.BlockPresent || v1.Headers.BlockStages != nil || len(v1.Headers.Values) == 0 {
		t.Fatalf("v1 headers = %+v", v1.Headers)
	}
	secret := []byte("Bearer synthetic-secret")
	credentials := 0
	for _, value := range v1.Headers.Values {
		if value.Name != "Authorization" {
			if value.Value.Omitted {
				t.Fatalf("%s omitted", value.Name)
			}
			continue
		}
		credentials++
		if !value.Value.Omitted || value.Value.Value != "" || value.Value.Length != int64(len(secret)) || value.Value.Fingerprint != keys.CredentialFingerprint(secret) {
			t.Fatalf("Authorization projected as %+v", value.Value)
		}
	}
	if credentials != 2 {
		t.Fatalf("credential values = %d, want both stages' Authorization", credentials)
	}
	query := v1.Audit.RequestURI
	if !query.HasQuery || len(query.Segments) != 2 || !query.Segments[0].Credential || query.Segments[0].RawName != "key" ||
		query.Segments[0].Fingerprint != keys.CredentialFingerprint([]byte("synthetic-query-key")) || query.Segments[1].Raw != "alt=sse" {
		t.Fatalf("request URI projected as %+v", query)
	}

	v2 := exports["v2-rejected"].Record
	rows := map[string]bool{}
	for _, stage := range v2.Stages {
		rows[stage.Stage] = true
	}
	if v2.Audit.CaptureStatus != CaptureFailed || rows[StageRequestSent] || !slices.Contains(v2.Headers.BlockStages, StageRequestSent) || !v2.Headers.BlockPresent {
		t.Fatalf("v2 failed capture: status %s, stage rows %v, block stages %v", v2.Audit.CaptureStatus, rows, v2.Headers.BlockStages)
	}
	sectionValues := 0
	for _, value := range v2.Headers.Values {
		if value.Stage == StageRequestSent {
			sectionValues++
		}
	}
	if sectionValues == 0 {
		t.Fatal("the section of the stage without a row is not in the record")
	}
	if v2.Audit.UserAgent == nil || len(v2.Audit.UserAgent) != 2 {
		t.Fatalf("v2 user agent = %+v", v2.Audit.UserAgent)
	}
}
