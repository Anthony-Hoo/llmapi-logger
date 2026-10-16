package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"llmapi-logger/internal/security"
)

func testAnalysisRow(auditID string, startedAtNS int64) AnalysisRow {
	model, stop, link, role, client, source := "model-example", "tool_use", "inferred", "subagent", "custom", "header"
	uncached, cacheRead, cacheWrite, output, reasoning := int64(120), int64(800), int64(0), int64(64), int64(16)
	appended, confidence := 2, 100
	session := "ses_0123abcd"
	firstEvent := int64(1500)
	return AnalysisRow{
		AuditID: auditID, AnalysisVersion: 1, AnalyzedAtNS: startedAtNS + 10,
		Protocol: "openai", Model: &model, StartedAtNS: startedAtNS,
		UncachedInput: &uncached, CacheRead: &cacheRead, CacheWrite: &cacheWrite,
		Output: &output, Reasoning: &reasoning,
		EstSystem: 300, EstTools: 200, EstUser: 50, EstAssistant: 40, EstToolResult: 330,
		Items: 6, ToolDefs: 3, ToolResults: 1,
		StopReason: &stop, RespKinds: 3, RespToolCalls: 1, ToolKindCounts: `{"file_read":1}`,
		AnalysisSessionID: &session, SessionLink: &link, TurnStart: true, AppendedItems: &appended,
		EventFlags: 4, SystemFPR: bytes.Repeat([]byte{0x11}, AnalysisFingerprintSize),
		FirstEventNS: &firstEvent,
		AgentClient:  &client, AgentRole: &role,
		AgentNodeFPR:    bytes.Repeat([]byte{0x22}, AnalysisFingerprintSize),
		AgentParentFPR:  bytes.Repeat([]byte{0x23}, AnalysisFingerprintSize),
		AgentLinkSource: &source, AgentLinkConfidence: &confidence,
		DetailEnc:  []byte{0xde, 0x7a, 0x11},
		SpawnHints: [][]byte{bytes.Repeat([]byte{0x31}, AnalysisFingerprintSize)},
	}
}

type evidenceDigests struct {
	capture, parsed, semantic []byte
}

func readEvidenceDigests(t *testing.T, store *Store, auditID string) evidenceDigests {
	t.Helper()
	ctx := context.Background()
	transaction, err := store.readerDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	var digests evidenceDigests
	if digests.capture, err = capturePayloadDigest(ctx, transaction, auditID); err != nil {
		t.Fatal(err)
	}
	encoder := newDigestEncoder("analysis-test")
	if err := appendParsedResultDigest(ctx, transaction, encoder, auditID); err != nil {
		t.Fatal(err)
	}
	digests.parsed = encoder.sum()
	if digests.semantic, err = semanticPayloadDigest(ctx, transaction, nil, auditID); err != nil {
		t.Fatal(err)
	}
	return digests
}

func TestAnalysisRowsStayOutsideTheEvidenceChain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x73}, security.KeySize)
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnableIntegrity(ctx, key); err != nil {
		t.Fatal(err)
	}
	const auditID = "audit-analysis-chain"
	user := graphItem("user_message", map[string]any{"role": "user", "content": "question"})
	assistant := graphItem("assistant_message", map[string]any{"role": "assistant", "content": "answer"})
	saveIntegrityChainTurn(t, store, graphTestCipher(t), auditID, "", "response-analysis", 100,
		[]graphTestItem{user}, []graphTestItem{assistant})
	before := readEvidenceDigests(t, store, auditID)

	// audit_analysis and agent_spawn_hints are recomputable derived data, like
	// api_key_fpr. Inserting, rewriting or deleting them must leave every
	// signed digest unchanged; folding them into a digest would invalidate
	// every audit written before migration 008.
	row := testAnalysisRow(auditID, 100)
	steps := []struct {
		name  string
		apply func() error
	}{
		{"insert", func() error { return store.SaveAnalysis(ctx, row) }},
		{"update", func() error {
			updated := row
			updated.AnalysisVersion = 2
			updated.EstUser = 999
			updated.SpawnHints = [][]byte{bytes.Repeat([]byte{0x32}, AnalysisFingerprintSize)}
			return store.SaveAnalysis(ctx, updated)
		}},
		{"delete", func() error {
			if _, err := store.writerDB.ExecContext(ctx, `DELETE FROM agent_spawn_hints WHERE audit_id = ?`, auditID); err != nil {
				return err
			}
			_, err := store.writerDB.ExecContext(ctx, `DELETE FROM audit_analysis WHERE audit_id = ?`, auditID)
			return err
		}},
		{"reinsert", func() error { return store.SaveAnalysis(ctx, row) }},
	}
	for _, step := range steps {
		if err := step.apply(); err != nil {
			t.Fatalf("%s analysis: %v", step.name, err)
		}
		after := readEvidenceDigests(t, store, auditID)
		if !bytes.Equal(before.capture, after.capture) || !bytes.Equal(before.parsed, after.parsed) || !bytes.Equal(before.semantic, after.semantic) {
			t.Fatalf("%s analysis changed an evidence digest", step.name)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.EnableIntegrity(ctx, key); err != nil {
		t.Fatalf("analysis rows must not participate in the integrity chain: %v", err)
	}
	if err := reopened.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatalf("payload verification with analysis rows: %v", err)
	}
	if state := reopened.IntegrityPayloadState(); state != "verified" {
		t.Fatalf("payload state = %q", state)
	}
	if _, err := reopened.LoadAnalysis(ctx, auditID); err != nil {
		t.Fatalf("analysis row lost across reopen: %v", err)
	}
}

func TestRetentionCascadesAnalysisRows(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, _ := openTestStore(t)
	const auditID = "audit-analysis-retention"
	if err := store.BeginAudit(ctx, testAudit(auditID)); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishAudit(ctx, AuditFinish{
		AuditID: auditID, EndedAtNS: 2, ForwardStatus: ForwardCompleted,
		CaptureStatus: CaptureComplete, ParseStatus: ParsePending,
	}); err != nil {
		t.Fatal(err)
	}
	row := testAnalysisRow(auditID, 1)
	row.SpawnHints = append(row.SpawnHints, bytes.Repeat([]byte{0x33}, AnalysisFingerprintSize))
	if err := store.SaveAnalysis(ctx, row); err != nil {
		t.Fatal(err)
	}
	result, err := store.DeleteExpired(ctx, 2, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if result.DeletedAudits != 1 {
		t.Fatalf("deleted audits = %d", result.DeletedAudits)
	}
	var analyses, hints int
	if err := store.readerDB.QueryRow(`SELECT (SELECT COUNT(*) FROM audit_analysis), (SELECT COUNT(*) FROM agent_spawn_hints)`).Scan(&analyses, &hints); err != nil {
		t.Fatal(err)
	}
	if analyses != 0 || hints != 0 {
		t.Fatalf("retention left %d analysis and %d hint rows", analyses, hints)
	}
}

func TestSaveAnalysisUpsertsAndReplacesHints(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, _ := openTestStore(t)
	const auditID = "audit-analysis-upsert"
	if err := store.BeginAudit(ctx, testAudit(auditID)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadAnalysis(ctx, auditID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("load before save = %v, want sql.ErrNoRows", err)
	}

	first := testAnalysisRow(auditID, 1)
	hintA := bytes.Repeat([]byte{0xa1}, AnalysisFingerprintSize)
	hintB := bytes.Repeat([]byte{0x0b}, AnalysisFingerprintSize)
	first.SpawnHints = [][]byte{hintA, hintB, hintA}
	if err := store.SaveAnalysis(ctx, first); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadAnalysis(ctx, auditID)
	if err != nil {
		t.Fatal(err)
	}
	want := cloneAnalysisRow(first)
	want.SpawnHints = [][]byte{hintB, hintA}
	if !reflect.DeepEqual(loaded, want) {
		t.Fatalf("loaded analysis = %+v\nwant %+v", loaded, want)
	}

	// The second save replaces every column, including clearing optional ones,
	// and replaces the hint set rather than merging it.
	second := AnalysisRow{
		AuditID: auditID, AnalysisVersion: 2, AnalyzedAtNS: 50, Protocol: "anthropic", StartedAtNS: 1,
		EstUser: 7, Items: 1,
		SpawnHints: [][]byte{bytes.Repeat([]byte{0xc3}, AnalysisFingerprintSize)},
	}
	if err := store.SaveAnalysis(ctx, second); err != nil {
		t.Fatal(err)
	}
	loaded, err = store.LoadAnalysis(ctx, auditID)
	if err != nil {
		t.Fatal(err)
	}
	want = cloneAnalysisRow(second)
	want.ToolKindCounts = "{}"
	if !reflect.DeepEqual(loaded, want) {
		t.Fatalf("updated analysis = %+v\nwant %+v", loaded, want)
	}
	var rows, hints int
	if err := store.readerDB.QueryRow(`SELECT (SELECT COUNT(*) FROM audit_analysis), (SELECT COUNT(*) FROM agent_spawn_hints)`).Scan(&rows, &hints); err != nil {
		t.Fatal(err)
	}
	if rows != 1 || hints != 1 {
		t.Fatalf("analysis rows = %d, hint rows = %d", rows, hints)
	}

	second.SpawnHints = nil
	if err := store.SaveAnalysis(ctx, second); err != nil {
		t.Fatal(err)
	}
	if loaded, err = store.LoadAnalysis(ctx, auditID); err != nil || len(loaded.SpawnHints) != 0 {
		t.Fatalf("hints after clearing = %v, %v", loaded.SpawnHints, err)
	}
}

func TestSaveAnalysisRejectsInvalidRowsAndIsolatesMissingAudits(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, _ := openTestStore(t)
	short := []byte{0x01, 0x02}
	negative := int64(-1)
	badRole := "orchestrator"
	for name, mutate := range map[string]func(*AnalysisRow){
		"missing version":    func(row *AnalysisRow) { row.AnalysisVersion = 0 },
		"negative usage":     func(row *AnalysisRow) { row.CacheRead = &negative },
		"negative estimate":  func(row *AnalysisRow) { row.EstTools = -1 },
		"short fingerprint":  func(row *AnalysisRow) { row.SystemFPR = short },
		"short spawn hint":   func(row *AnalysisRow) { row.SpawnHints = [][]byte{short} },
		"unknown agent role": func(row *AnalysisRow) { row.AgentRole = &badRole },
		"tool counts array":  func(row *AnalysisRow) { row.ToolKindCounts = `[1]` },
	} {
		row := testAnalysisRow("audit-invalid", 1)
		mutate(&row)
		if err := store.SaveAnalysis(ctx, row); !errors.Is(err, errInvalidAnalysis) {
			t.Fatalf("%s: SaveAnalysis = %v, want invalid analysis", name, err)
		}
	}

	// Race a missing-audit save against an unrelated capture write so the two
	// usually share one writer batch. Only the analysis may fail.
	var wait sync.WaitGroup
	var analysisErr, auditErr error
	wait.Add(2)
	go func() {
		defer wait.Done()
		analysisErr = store.SaveAnalysis(ctx, testAnalysisRow("audit-missing", 1))
	}()
	go func() {
		defer wait.Done()
		auditErr = store.BeginAudit(ctx, testAudit("audit-neighbor"))
	}()
	wait.Wait()
	if !errors.Is(analysisErr, sql.ErrNoRows) {
		t.Fatalf("missing audit analysis = %v, want sql.ErrNoRows", analysisErr)
	}
	if auditErr != nil {
		t.Fatalf("neighbor write failed: %v", auditErr)
	}
	if !store.Healthy() {
		t.Fatal("store unhealthy after an isolated analysis failure")
	}
	var count int
	if err := store.readerDB.QueryRow(`SELECT COUNT(*) FROM audit_records WHERE audit_id = 'audit-neighbor'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("neighbor audit rows = %d, %v", count, err)
	}
}

func TestLoadParserRequestHeadersFiltersNamesAndStage(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, _ := openTestStore(t)
	const auditID = "audit-parser-headers"
	if err := store.BeginAudit(ctx, testAudit(auditID)); err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{StageRequestReceived, StageRequestSent} {
		if err := store.StartStage(ctx, HTTPStage{
			AuditID: auditID, Stage: stage, Proto: "HTTP/1.1", Method: "POST", Host: "example.com", StartedAtNS: 2,
		}); err != nil {
			t.Fatal(err)
		}
	}
	header := func(stage, kind, name string, index int, value string) HTTPHeader {
		return HTTPHeader{AuditID: auditID, Stage: stage, Kind: kind, Name: name, ValueIndex: index, ValueLength: len(value), ValueEnc: []byte(value)}
	}
	if err := store.AddHeaders(ctx, []HTTPHeader{
		header(StageRequestReceived, HeaderKindHeader, "X-Agent-Id", 0, "enc-node-0"),
		header(StageRequestReceived, HeaderKindHeader, "X-Agent-Id", 1, "enc-node-1"),
		header(StageRequestReceived, HeaderKindHeader, "x-agent-parent-id", 0, "enc-parent"),
		header(StageRequestReceived, HeaderKindHeader, "Authorization", 0, "enc-secret"),
		header(StageRequestReceived, HeaderKindTrailer, "X-Agent-Id", 0, "enc-trailer"),
		header(StageRequestSent, HeaderKindHeader, "X-Agent-Id", 0, "enc-forwarded"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishAudit(ctx, AuditFinish{
		AuditID: auditID, EndedAtNS: 3, ForwardStatus: ForwardCompleted,
		CaptureStatus: CaptureComplete, ParseStatus: ParsePending,
	}); err != nil {
		t.Fatal(err)
	}

	headers, err := store.LoadParserRequestHeaders(ctx, auditID, []string{"x-agent-id", " X-AGENT-PARENT-ID ", "X-Agent-Id", "x-missing"})
	if err != nil {
		t.Fatal(err)
	}
	want := []HeaderEvidence{
		{Stage: StageRequestReceived, Kind: HeaderKindHeader, Name: "X-Agent-Id", ValueIndex: 0, ValueLength: 10, ValueEnc: []byte("enc-node-0")},
		{Stage: StageRequestReceived, Kind: HeaderKindHeader, Name: "X-Agent-Id", ValueIndex: 1, ValueLength: 10, ValueEnc: []byte("enc-node-1")},
		{Stage: StageRequestReceived, Kind: HeaderKindHeader, Name: "x-agent-parent-id", ValueIndex: 0, ValueLength: 10, ValueEnc: []byte("enc-parent")},
	}
	if !reflect.DeepEqual(headers, want) {
		t.Fatalf("headers = %+v\nwant %+v", headers, want)
	}
	for _, names := range [][]string{nil, {"", "  "}} {
		empty, err := store.LoadParserRequestHeaders(ctx, auditID, names)
		if err != nil || len(empty) != 0 {
			t.Fatalf("empty allowlist %q = %+v, %v", names, empty, err)
		}
	}
}
