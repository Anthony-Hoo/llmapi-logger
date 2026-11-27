package postgres

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/headerblock"
	"llmapi-logger/internal/routing"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// These tests drive the real unified capture session on the PostgreSQL store,
// which makes it write capture version 2. They need TEST_DATABASE_URL.

// Crash points of design B.7 / I.2: the request stops there and the process
// is gone; nothing of the session is written afterwards.
const (
	crashNone         = iota
	crashInterceptor  // after BeginAudit, while interceptors run
	crashRequestRead  // the request body was read, the response has not come
	crashResponseHalf // the response headers were forwarded, half the body
	crashBeforeFinish // the response ended, Finish never ran
	crashPointsCount
)

var crashPointNames = map[int]string{
	crashInterceptor: "interceptor", crashRequestRead: "request read", crashResponseHalf: "response half", crashBeforeFinish: "before finish",
}

type v2Drive struct {
	request          []byte
	requestTrailers  http.Header
	response         []byte
	responseTrailers http.Header
}

func typicalV2Drive() v2Drive {
	return v2Drive{
		request:          jsonRequest(200 << 10),
		requestTrailers:  http.Header{"X-Request-Checksum": {"sum-1"}},
		response:         sseResponse(300 << 10),
		responseTrailers: http.Header{"X-Response-Usage": {"tokens=42"}},
	}
}

// runSession drives one request through a real Session as the proxy does,
// stopping at stopAt. It returns the audit id.
func runSession(t *testing.T, store audit.Store, cipher security.Cipher, writePath string, drive v2Drive, stopAt int) string {
	t.Helper()
	manager, err := audit.NewManagerWithOptions(store, cipher, nil, "available", slog.New(slog.NewTextHandler(io.Discard, nil)), audit.Options{WritePath: writePath})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	inbound := httptest.NewRequest(http.MethodPost, "http://proxy.example.com/v1/chat/completions?trace=x", &fixedReads{data: drive.request, size: 32 << 10})
	inbound.RequestURI = "/v1/chat/completions?trace=x"
	inbound.ContentLength = int64(len(drive.request))
	inbound.Header = inboundHeaders("application/json")
	inbound.Header["user-agent"] = []string{"lower-case-key"}
	inbound.Trailer = drive.requestTrailers
	session, err := manager.Begin(ctx, inbound, routing.Match{RouteID: "openai-chat", Parser: "openai.chat_completions"})
	if err != nil {
		t.Fatal(err)
	}
	if stopAt == crashInterceptor {
		return session.ID()
	}
	outbound := inbound.Clone(ctx)
	outbound.Host = "upstream.example.com"
	outbound.Header = outboundHeaders("application/json")
	outbound.Body = inbound.Body
	outbound.Trailer = drive.requestTrailers
	session.WrapRequestSent(outbound)
	buffer := make([]byte, 64<<10)
	for {
		if _, err := outbound.Body.Read(buffer); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if stopAt == crashRequestRead {
		return session.ID()
	}
	headers := streamResponseHeaders()
	headers.Set("Trailer", "X-Response-Usage")
	response := &http.Response{StatusCode: 200, Proto: "HTTP/1.1", Header: headers, ContentLength: -1,
		Body: io.NopCloser(&fixedReads{data: drive.response, size: 16 << 10}), Trailer: drive.responseTrailers, Request: outbound}
	session.WrapResponseReceived(response)
	writer := session.WrapResponseWriter(httptest.NewRecorder(), inbound)
	for name, values := range response.Header {
		writer.Header()[name] = append([]string(nil), values...)
	}
	writer.WriteHeader(200)
	written := 0
	for {
		if stopAt == crashResponseHalf && written >= len(drive.response)/2 {
			return session.ID()
		}
		count, err := response.Body.Read(buffer)
		if count > 0 {
			if _, err := writer.Write(buffer[:count]); err != nil {
				t.Fatal(err)
			}
			written += count
		}
		if err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if stopAt == crashBeforeFinish {
		return session.ID()
	}
	for name, values := range drive.responseTrailers {
		writer.Header()[name] = values
	}
	writer.CaptureTrailers()
	if err := session.Finish(); err != nil {
		t.Fatal(err)
	}
	return session.ID()
}

// flatSourceHeaders expands an audit's stored Headers, whatever its version.
func flatSourceHeaders(t *testing.T, store *Store, cipher security.Cipher, auditID string) []string {
	t.Helper()
	values, err := expandDetail(t, store, cipher, auditID)
	if err != nil {
		t.Fatalf("%s: %v", auditID, err)
	}
	return flatHeaders(values)
}

// The whole request through the real session: version 2 on PostgreSQL stores
// the same Headers as legacy (version 1), and every other table as legacy.
func TestSessionWritesCaptureV2OnPostgreSQL(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cipher := v2TestCipher(t)
	legacyStore, _ := openSignedStore(t)
	unifiedStore, _ := openSignedStore(t)
	drive := typicalV2Drive()
	legacyID := runSession(t, legacyStore, cipher, audit.WritePathLegacy, drive, crashNone)
	unifiedID := runSession(t, unifiedStore, cipher, audit.WritePathUnified, drive, crashNone)

	var version int
	var headerRows, blocks int
	if err := unifiedStore.readerDB.QueryRow(`SELECT capture_version, (SELECT COUNT(*) FROM http_headers), (SELECT COUNT(*) FROM http_header_blocks) FROM audit_records WHERE audit_id = $1`, unifiedID).
		Scan(&version, &headerRows, &blocks); err != nil || version != 2 || headerRows != 0 || blocks != 1 {
		t.Fatalf("unified audit: version %d, %d header rows, %d blocks, %v", version, headerRows, blocks, err)
	}
	legacyHeaders, unifiedHeaders := flatSourceHeaders(t, legacyStore, cipher, legacyID), flatSourceHeaders(t, unifiedStore, cipher, unifiedID)
	if !reflect.DeepEqual(legacyHeaders, unifiedHeaders) {
		t.Fatalf("headers differ:\n legacy  %v\n unified %v", legacyHeaders, unifiedHeaders)
	}
	if !strings.Contains(strings.Join(unifiedHeaders, "|"), StageResponseSent+" trailer X-Response-Usage 0 tokens=42") {
		t.Fatalf("response trailer missing: %v", unifiedHeaders)
	}
	// user_agent_enc holds the inbound User-Agent values (C.5): every key equal
	// to user-agent ignoring case, in byte order of the key.
	page, err := unifiedStore.ListAudits(ctx, AuditQueryFilter{}, AuditQueryCursor{}, 1)
	if err != nil || len(page.Rows) != 1 {
		t.Fatal(err)
	}
	agents, err := headerblock.OpenUserAgent(cipher, unifiedID, page.Rows[0].UserAgentEnc)
	if err != nil || !reflect.DeepEqual(agents, []string{"harness-client/1.0", "harness-client/1.0"}) {
		t.Fatalf("user agent = %v, %v", agents, err)
	}
	// The content columns hold what the parser chooses from the legacy rows.
	for _, stage := range []string{StageRequestReceived, StageResponseReceived} {
		legacy, err := legacyStore.LoadParserStage(ctx, legacyID, stage)
		if err != nil {
			t.Fatal(err)
		}
		unified, err := unifiedStore.LoadParserStage(ctx, unifiedID, stage)
		if err != nil {
			t.Fatal(err)
		}
		var want string
		for _, header := range legacy.Headers {
			if strings.EqualFold(header.Name, "content-type") {
				aad, _ := security.AAD(legacyID, "header", stage, header.Kind, header.Name, "0")
				plaintext, err := cipher.Decrypt(aad, header.ValueEnc)
				if err == nil && want == "" {
					want = string(plaintext)
				}
			}
		}
		if unified.ContentType == nil || *unified.ContentType != want || unified.ContentEncoding != nil {
			t.Fatalf("%s content type = %v, legacy rows say %q", stage, unified.ContentType, want)
		}
	}
	legacyDump, unifiedDump := dumpAudit(t, legacyStore.readerDB, harnessCipherOf(t, cipher), legacyID), dumpAudit(t, unifiedStore.readerDB, harnessCipherOf(t, cipher), unifiedID)
	for _, dump := range []harnessDump{legacyDump, unifiedDump} {
		dump.dropRows("http_headers", func(harnessRow) bool { return true })
	}
	if differences := diffDumps(normalizeSessionDump(legacyDump), normalizeSessionDump(unifiedDump)); len(differences) != 0 {
		t.Fatalf("rows differ:\n%s", strings.Join(differences, "\n"))
	}
	for _, store := range []*Store{legacyStore, unifiedStore} {
		if err := store.VerifyIntegrityPayloads(ctx); err != nil {
			t.Fatal(err)
		}
	}
	compareCaptureDigests(t, unifiedStore, unifiedID)
}

// I.2 on PostgreSQL for version 2: at every crash point of B.7, recovery
// finalizes the audit with the block the last write left, the payload
// verifies, and the Headers read back are what legacy has after the same
// crash.
func TestSessionCrashPointsRecoverCaptureV2(t *testing.T) {
	t.Parallel()
	cipher := v2TestCipher(t)
	for point := crashInterceptor; point < crashPointsCount; point++ {
		t.Run(crashPointNames[point], func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			legacyStore, _ := openSignedStore(t)
			unifiedStore, _ := openSignedStore(t)
			drive := typicalV2Drive()
			legacyID := runSession(t, legacyStore, cipher, audit.WritePathLegacy, drive, point)
			unifiedID := runSession(t, unifiedStore, cipher, audit.WritePathUnified, drive, point)
			for _, store := range []*Store{legacyStore, unifiedStore} {
				writerBarrier(t, store)
				if recovered, err := store.RecoverInterruptedAudits(ctx, 9_000_000_000_000_000_000); err != nil || recovered != 1 {
					t.Fatalf("recovered %d: %v", recovered, err)
				}
				if err := store.VerifyIntegrityPayloads(ctx); err != nil {
					t.Fatalf("payload verification after recovery: %v", err)
				}
			}
			stages := map[int][]string{
				crashInterceptor:  {StageRequestReceived},
				crashRequestRead:  {StageRequestReceived, StageRequestSent},
				crashResponseHalf: {StageRequestReceived, StageRequestSent, StageResponseReceived, StageResponseSent},
				crashBeforeFinish: {StageRequestReceived, StageRequestSent, StageResponseReceived, StageResponseSent},
			}[point]
			stored, err := unifiedStore.QueryAuditDetail(ctx, unifiedID, nil)
			if err != nil {
				t.Fatal(err)
			}
			if source := stored.HeaderSource(); !reflect.DeepEqual(source.StageSet, stages) || source.Block == nil {
				t.Fatalf("stage rows %v, block %v; want %v", source.StageSet, source.Block != nil, stages)
			}
			legacyHeaders, unifiedHeaders := flatSourceHeaders(t, legacyStore, cipher, legacyID), flatSourceHeaders(t, unifiedStore, cipher, unifiedID)
			if point == crashBeforeFinish {
				// The upstream's trailers arrive with the end of its body,
				// after checkpoint 2: legacy wrote them at once, the unified
				// path keeps them for the commit, like the rest of the
				// response side (B.7, last column).
				kept := legacyHeaders[:0:0]
				for _, header := range legacyHeaders {
					if !strings.HasPrefix(header, StageResponseReceived+" trailer ") {
						kept = append(kept, header)
					}
				}
				if len(kept) == len(legacyHeaders) {
					t.Fatalf("legacy kept no upstream trailer: %v", legacyHeaders)
				}
				legacyHeaders = kept
			}
			if !reflect.DeepEqual(legacyHeaders, unifiedHeaders) {
				t.Fatalf("headers after recovery differ:\n legacy  %v\n unified %v", legacyHeaders, unifiedHeaders)
			}
			compareCaptureDigests(t, unifiedStore, unifiedID)
		})
	}
}

// v2RecordingStore records the version 2 operations of a real session, so
// their statements can be counted on PostgreSQL.
type v2RecordingStore struct {
	mu  sync.Mutex
	ops []hOp
}

func (store *v2RecordingStore) add(kind writeKind, data any) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.ops = append(store.ops, hOp{kind: kind, data: data, event: -1})
}
func (store *v2RecordingStore) Healthy() bool             { return true }
func (store *v2RecordingStore) SupportsHeaderBlock() bool { return true }
func (store *v2RecordingStore) BeginAudit(_ context.Context, record storage.AuditRecord) error {
	store.add(writeBeginAudit, record)
	return nil
}
func (store *v2RecordingStore) Checkpoint(_ context.Context, checkpoint storage.AuditCheckpoint) error {
	store.add(writeCheckpoint, checkpoint)
	return nil
}
func (store *v2RecordingStore) CommitAudit(_ context.Context, commit storage.AuditCommit) (storage.AuditFinish, error) {
	store.add(writeCommitAudit, commit)
	return commit.Finish, nil
}
func (*v2RecordingStore) StartStage(context.Context, storage.HTTPStage) error       { return nil }
func (*v2RecordingStore) StartBody(context.Context, storage.BodyStream) error       { return nil }
func (*v2RecordingStore) AddHeaders(context.Context, []storage.HTTPHeader) error    { return nil }
func (*v2RecordingStore) AddChunk(context.Context, storage.BodyChunk) error         { return nil }
func (*v2RecordingStore) FinishStage(context.Context, storage.StageFinish) error    { return nil }
func (*v2RecordingStore) InsertAuditGaps(context.Context, []storage.AuditGap) error { return nil }
func (*v2RecordingStore) FinishAuditWithResult(_ context.Context, finish storage.AuditFinish) (storage.AuditFinish, error) {
	return finish, nil
}

// The statements of a typical unified version 2 request (B.9: four stages,
// bodies under 8 MiB, both pairs merged, here with request and response
// trailers), counted as TestStagedWriteStatementCounts counts version 1.
func TestCaptureV2StatementCounts(t *testing.T) {
	t.Parallel()
	cipher := v2TestCipher(t)
	store, dsn := openSignedStore(t)
	for _, test := range []struct {
		name  string
		drive v2Drive
	}{
		{"no trailers", v2Drive{request: jsonRequest(200 << 10), response: sseResponse(300 << 10)}},
		{"request and response trailers", typicalV2Drive()},
	} {
		recorder := &v2RecordingStore{}
		runSession(t, recorder, cipher, audit.WritePathUnified, test.drive, crashNone)
		total, perKind := countStatements(t, store, dsn, recorder.ops)
		var blocks []string
		for _, op := range recorder.ops {
			switch value := op.data.(type) {
			case storage.AuditRecord:
				blocks = append(blocks, "begin:"+boolText(value.Inbound != nil && value.Inbound.HeaderBlock != nil))
			case storage.AuditCheckpoint:
				blocks = append(blocks, "checkpoint:"+boolText(value.HeaderBlock != nil))
			case storage.AuditCommit:
				blocks = append(blocks, "commit:"+boolText(value.HeaderBlock != nil))
			}
		}
		t.Logf("%s: %d operations, %d statements (%s); header block written by %v", test.name, len(recorder.ops), total, describeCounts(recorder.ops, perKind), blocks)
		if len(recorder.ops) != 4 {
			t.Fatalf("%s: %d operations", test.name, len(recorder.ops))
		}
		// Without response trailers the commit's block equals checkpoint 2's
		// and is not sent again (C.8).
		if commitBlock := blocks[3] == "commit:block"; commitBlock != (test.drive.responseTrailers != nil) {
			t.Fatalf("%s: blocks %v", test.name, blocks)
		}
	}
	if err := store.VerifyIntegrityPayloads(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func boolText(value bool) string {
	if value {
		return "block"
	}
	return "none"
}

// harnessCipherOf returns the AES-GCM cipher dumpAudit opens rows with.
func harnessCipherOf(t *testing.T, cipher security.Cipher) *security.AESGCM {
	t.Helper()
	concrete, ok := cipher.(*security.AESGCM)
	if !ok {
		t.Fatalf("cipher %T", cipher)
	}
	return concrete
}

// normalizeSessionDump blanks what two runs of the real session cannot agree
// on: the audit id, the clock (times, the timeline plaintext) and the version
// columns that differ by design (B.10).
func normalizeSessionDump(dump harnessDump) harnessDump {
	normalized := harnessDump{}
	for table, rows := range dump {
		for _, row := range rows {
			copied := harnessRow{}
			for column, value := range row {
				switch {
				case column == "audit_id", strings.HasSuffix(column, "_at_ns"), column == "ttft_ns",
					column == "capture_version", column == "user_agent_enc", column == "content_type", column == "content_encoding",
					column == "payload_digest", column == "event_mac", column == "previous_mac",
					// The timeline plaintext holds observation times.
					column == "timeline_enc":
					continue
				}
				copied[column] = value
			}
			normalized[table] = append(normalized[table], copied)
		}
	}
	return normalized
}

// storage.ErrInboundStageNotStored on version 2 through the real session: the
// start row stays, the inbound stage is never put in a block, and the
// finished audit verifies and reads back the three stages it has.
func TestSessionWithoutTheInboundStageWritesConsistentBlocks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cipher := v2TestCipher(t)
	store, _ := openSignedStore(t)
	injectInsertFailure(t, store, "http_stages", "NEW.stage = 'request_for_newapi_received_from_nginx'")
	auditID := runSession(t, store, cipher, audit.WritePathUnified, typicalV2Drive(), crashNone)
	var captureStatus string
	if err := store.readerDB.QueryRow(`SELECT capture_status FROM audit_records WHERE audit_id = $1`, auditID).Scan(&captureStatus); err != nil || captureStatus != CaptureFailed {
		t.Fatalf("capture status %q, %v", captureStatus, err)
	}
	stored, err := store.QueryAuditDetail(ctx, auditID, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{StageRequestSent, StageResponseReceived, StageResponseSent}
	if source := stored.HeaderSource(); !reflect.DeepEqual(source.StageSet, want) || source.Block == nil {
		t.Fatalf("stage rows %v, block %v", source.StageSet, source.Block != nil)
	}
	values, err := expandDetail(t, store, cipher, auditID)
	if err != nil {
		t.Fatalf("Expand = %v", err)
	}
	for _, value := range values {
		if value.Stage == StageRequestReceived {
			t.Fatalf("block holds the inbound stage: %v", flatHeaders(values))
		}
	}
	if err := store.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatal(err)
	}
	compareCaptureDigests(t, store, auditID)
}
