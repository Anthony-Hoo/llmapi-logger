package proxy

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

// A write the store rejects as an operation (a trigger standing in for a
// constraint failure) leaves an audit that ends failed with
// capture_write_failed, keeps what the other writes stored readable with raw
// in full, and verifies. Where the rejected row is decides what is lost
// (design B.8): a rejected checkpoint is rolled back whole, so checkpoint 1
// takes the request side's rows with it; a rejected commit is final at once
// and the audit is finalized by the writer's recovery with what the
// checkpoints wrote, without the response bodies (R.6 item 2). The
// completion log says what the session knew when Finish returned: failed
// when the commit saw the failure, partial with audit_finalize_failed when
// the commit itself was rejected.
func TestCaptureWriteFailuresEndTheAuditFailed(t *testing.T) {
	valueOrEmpty := func(value *string) string {
		if value == nil {
			return ""
		}
		return *value
	}
	requestBody := `{"model":"model-example","messages":[{"role":"user","content":"hello"}]}`
	responseBody := `{"id":"response-example","choices":[{"message":{"role":"assistant","content":"hi"}}]}`
	large := strings.Repeat("A", 1<<20) + strings.Repeat("B", 1<<20) + strings.Repeat("C", 1<<20)
	sse := ""
	for _, fill := range []string{"A", "B", "C"} {
		sse += "data: " + strings.Repeat(fill, 1<<20-8) + "\n\n"
	}
	for _, test := range []struct {
		name, trigger     string
		request, response string
		eventStream       bool
		commitRejected    bool
		requestKept       bool
		responseKept      bool
		stages            int
	}{
		// The inbound Headers are rejected inside BeginAudit (only they roll
		// back, R.1 item 7) and checkpoint 1 carries request_sent's: it is
		// rolled back whole, and the commit, which sees the audit failed,
		// writes the response side.
		{name: "header insert", trigger: `CREATE TRIGGER fail_capture_header BEFORE INSERT ON http_headers
WHEN NEW.name = 'X-Fail-Capture' BEGIN SELECT RAISE(ABORT, 'test capture failure'); END`,
			request: requestBody, response: responseBody, responseKept: true, stages: 3},
		// The commit finishes the bodies: it is rejected; the request side of
		// checkpoint 1 stays.
		{name: "stage finalization", trigger: `CREATE TRIGGER fail_capture_finish BEFORE UPDATE OF state ON body_streams
WHEN NEW.state = 'complete' BEGIN SELECT RAISE(ABORT, 'test capture failure'); END`,
			request: requestBody, response: responseBody, commitRejected: true, requestKept: true, stages: 4},
		// A chunk of each side is rejected: checkpoint 1 with the request
		// chunk, and the commit with the response chunk.
		{name: "first chunk", trigger: `CREATE TRIGGER fail_chunk BEFORE INSERT ON body_chunks WHEN NEW.seq = 0 BEGIN SELECT RAISE(ABORT, 'test capture failure'); END`,
			request: large, response: large, commitRejected: true, stages: 3},
		{name: "middle chunk", trigger: `CREATE TRIGGER fail_chunk BEFORE INSERT ON body_chunks WHEN NEW.seq = 1 BEGIN SELECT RAISE(ABORT, 'test capture failure'); END`,
			request: large, response: large, commitRejected: true, stages: 3},
		{name: "middle chunk SSE", trigger: `CREATE TRIGGER fail_chunk BEFORE INSERT ON body_chunks WHEN NEW.seq = 1 BEGIN SELECT RAISE(ABORT, 'test capture failure'); END`,
			request: sse, response: sse, eventStream: true, commitRejected: true, stages: 3},
		{name: "last chunk", trigger: `CREATE TRIGGER fail_chunk BEFORE INSERT ON body_chunks WHEN NEW.seq = 2 BEGIN SELECT RAISE(ABORT, 'test capture failure'); END`,
			request: large, response: large, commitRejected: true, stages: 3},
		{name: "all chunks", trigger: `CREATE TRIGGER fail_chunk BEFORE INSERT ON body_chunks BEGIN SELECT RAISE(ABORT, 'test capture failure'); END`,
			request: large, response: large, commitRejected: true, stages: 3},
		{name: "last chunk and stage finish", trigger: `CREATE TRIGGER fail_chunk BEFORE INSERT ON body_chunks WHEN NEW.seq = 2 BEGIN SELECT RAISE(ABORT, 'test capture failure'); END;
CREATE TRIGGER fail_finish BEFORE UPDATE OF state ON body_streams WHEN NEW.state = 'complete' BEGIN SELECT RAISE(ABORT, 'test finish failure'); END`,
			request: large, response: large, commitRejected: true, stages: 3},
		{name: "all chunks and stage finish", trigger: `CREATE TRIGGER fail_chunk BEFORE INSERT ON body_chunks BEGIN SELECT RAISE(ABORT, 'test capture failure'); END;
CREATE TRIGGER fail_finish BEFORE UPDATE OF state ON body_streams WHEN NEW.state = 'complete' BEGIN SELECT RAISE(ABORT, 'test finish failure'); END`,
			request: large, response: large, commitRejected: true, stages: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Each case has its own store and upstream; most wait for a
			// recovery round of the writer.
			t.Parallel()
			ctx := context.Background()
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil || string(body) != test.request {
					t.Error("capture failure changed upstream request bytes")
				}
				w.Header().Set("Content-Type", "application/json")
				if test.eventStream {
					w.Header().Set("Content-Type", "text/event-stream")
				}
				_, _ = io.WriteString(w, test.response)
			}))
			defer upstream.Close()
			path := filepath.Join(t.TempDir(), "audit.db")
			store, err := sqlite.Open(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			key := bytes.Repeat([]byte{0x35}, security.KeySize)
			cipher, err := security.NewAESGCM(key)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.EnableIntegrity(ctx, key); err != nil {
				t.Fatal(err)
			}
			injection, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer injection.Close()
			if _, err := injection.Exec(test.trigger); err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, nil))
			manager := newTestManager(t, store, cipher, nil, logger, audit.Options{Sleep: func(time.Duration) { t.Error("an operation failure was retried") }})
			handler := newTestHandlerWithOptions(t, upstream.URL, manager, logger, nil, defaultTestRoutes())
			request := httptest.NewRequest(http.MethodPost, "http://example.com/v1/chat/completions", strings.NewReader(test.request))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Fail-Capture", "fixture")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK || response.Body.String() != test.response {
				t.Fatal("capture failure changed the downstream response")
			}
			record := singleCompletionLogRecord(t, logs.Bytes())
			auditID, ok := record["audit_id"].(string)
			if !ok {
				t.Fatal("completion log is missing its audit ID")
			}
			assertLogField(t, record, "forward_status", sqlite.ForwardCompleted)
			if test.commitRejected {
				assertLogField(t, record, "capture_status", sqlite.CapturePartial)
				assertLogField(t, record, "error_code", "audit_finalize_failed")
			} else {
				assertLogField(t, record, "capture_status", sqlite.CaptureFailed)
				assertLogField(t, record, "error_code", "capture_write_failed")
			}
			// A rejected commit is finalized by the writer's recovery.
			var snapshot sqlite.Snapshot
			for deadline := time.Now().Add(recoveryWait); ; {
				if snapshot, err = store.Snapshot(ctx, auditID); err != nil {
					t.Fatal(err)
				}
				if snapshot.Audit.EndedAtNS != nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("the audit was never finalized")
				}
				time.Sleep(20 * time.Millisecond)
			}
			if snapshot.Audit.CaptureStatus != sqlite.CaptureFailed || snapshot.Audit.ErrorCode == nil || *snapshot.Audit.ErrorCode != "capture_write_failed" {
				t.Fatalf("audit %s/%v, want failed/capture_write_failed", snapshot.Audit.CaptureStatus, snapshot.Audit.ErrorCode)
			}
			if len(snapshot.Stages) != test.stages {
				t.Fatalf("%d stages, want %d", len(snapshot.Stages), test.stages)
			}
			// What the session reached stays as it was; what the failed
			// write left streaming is closed by finalizeIncompleteCapture:
			// partial, capture_write_failed, hash and EOF not confirmed.
			for _, stage := range snapshot.Stages {
				wantState, wantCode := sqlite.StageStatePartial, "capture_write_failed"
				if !test.commitRejected {
					// The rejected inbound Headers mark only that stage.
					wantState, wantCode = sqlite.StageStateComplete, ""
					if stage.Stage == sqlite.StageRequestReceived {
						wantState, wantCode = sqlite.StageStatePartial, "capture_headers_failed"
					}
				}
				if stage.EndedAtNS == nil || stage.State != wantState || valueOrEmpty(stage.ErrorCode) != wantCode {
					t.Errorf("stage %s %s/%s, want %s/%s", stage.Stage, stage.State, valueOrEmpty(stage.ErrorCode), wantState, wantCode)
				}
			}
			kept := map[string]bool{}
			chunks := map[string]int64{}
			for _, chunk := range snapshot.Chunks {
				chunks[chunk.Stage]++
			}
			for _, body := range snapshot.Bodies {
				kept[body.Stage] = true
				if body.RetentionState != sqlite.RetentionFull || body.StoredLength != body.ObservedLength || body.ChunkCount != chunks[body.SourceStage] {
					t.Errorf("body %s: raw %s, stored %d of %d, %d chunks of %d", body.Stage, body.RetentionState, body.StoredLength, body.ObservedLength, body.ChunkCount, chunks[body.SourceStage])
				}
				if test.commitRejected && (body.State != sqlite.StageStatePartial || body.HashComplete || body.EOFSeen || valueOrEmpty(body.ErrorCode) != "capture_write_failed") {
					t.Errorf("body %s not closed as partial: %+v", body.Stage, body)
				}
				if !test.commitRejected && (body.State != sqlite.StageStateComplete || !body.HashComplete || !body.EOFSeen) {
					t.Errorf("unaffected body %s downgraded: %+v", body.Stage, body)
				}
			}
			queries, err := query.New(store, cipher)
			if err != nil {
				t.Fatal(err)
			}
			for side, want := range map[query.Side]struct {
				stages []string
				kept   bool
				body   string
			}{
				query.SideRequest:  {[]string{sqlite.StageRequestReceived, sqlite.StageRequestSent}, test.requestKept, test.request},
				query.SideResponse: {[]string{sqlite.StageResponseReceived, sqlite.StageResponseSent}, test.responseKept, test.response},
			} {
				for _, stage := range want.stages {
					if kept[stage] != want.kept {
						t.Fatalf("%s body row present %v, want %v", stage, kept[stage], want.kept)
					}
				}
				if !want.kept {
					// No body row: the side reads as missing, never as empty.
					var raw bytes.Buffer
					if err := queries.StreamRaw(ctx, auditID, side, &raw); err == nil {
						t.Fatalf("%s raw without a body row read as %d bytes", side, raw.Len())
					}
					continue
				}
				var raw bytes.Buffer
				if err := queries.StreamRaw(ctx, auditID, side, &raw); err != nil || raw.String() != want.body {
					t.Fatalf("kept %s raw is not readable as observed: %v", side, err)
				}
			}
			if err := store.VerifyIntegrityPayloads(ctx); err != nil {
				t.Fatalf("terminal metadata repair invalidated evidence signatures: %v", err)
			}
		})
	}
}
