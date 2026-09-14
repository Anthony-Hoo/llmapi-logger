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
	"slices"
	"strings"
	"testing"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

func TestAsyncCaptureFailuresMatchCompletionLogAndAllowRetainedRaw(t *testing.T) {
	for _, test := range []struct {
		name, trigger string
		missing       []int
	}{
		{"header insert", `CREATE TRIGGER fail_capture_header BEFORE INSERT ON http_headers
WHEN NEW.name = 'X-Fail-Capture' BEGIN SELECT RAISE(ABORT, 'test capture failure'); END`, nil},
		{"stage finalization", `CREATE TRIGGER fail_capture_finish BEFORE UPDATE OF state ON body_streams
WHEN NEW.state = 'complete' BEGIN SELECT RAISE(ABORT, 'test capture failure'); END`, nil},
		{"stage enqueue", "", nil},
		{"first chunk", `CREATE TRIGGER fail_chunk BEFORE INSERT ON body_chunks WHEN NEW.seq = 0 BEGIN SELECT RAISE(ABORT, 'test capture failure'); END`, []int{0}},
		{"middle chunk", `CREATE TRIGGER fail_chunk BEFORE INSERT ON body_chunks WHEN NEW.seq = 1 BEGIN SELECT RAISE(ABORT, 'test capture failure'); END`, []int{1}},
		{"middle chunk SSE", `CREATE TRIGGER fail_chunk BEFORE INSERT ON body_chunks WHEN NEW.seq = 1 BEGIN SELECT RAISE(ABORT, 'test capture failure'); END`, []int{1}},
		{"last chunk", `CREATE TRIGGER fail_chunk BEFORE INSERT ON body_chunks WHEN NEW.seq = 2 BEGIN SELECT RAISE(ABORT, 'test capture failure'); END`, []int{2}},
		{"all chunks", `CREATE TRIGGER fail_chunk BEFORE INSERT ON body_chunks BEGIN SELECT RAISE(ABORT, 'test capture failure'); END`, []int{0, 1, 2}},
		{"last chunk and stage finish", `CREATE TRIGGER fail_chunk BEFORE INSERT ON body_chunks WHEN NEW.seq = 2 BEGIN SELECT RAISE(ABORT, 'test capture failure'); END;
CREATE TRIGGER fail_finish BEFORE UPDATE OF state ON body_streams WHEN NEW.state = 'complete' BEGIN SELECT RAISE(ABORT, 'test finish failure'); END`, []int{2}},
		{"all chunks and stage finish", `CREATE TRIGGER fail_chunk BEFORE INSERT ON body_chunks BEGIN SELECT RAISE(ABORT, 'test capture failure'); END;
CREATE TRIGGER fail_finish BEFORE UPDATE OF state ON body_streams WHEN NEW.state = 'complete' BEGIN SELECT RAISE(ABORT, 'test finish failure'); END`, []int{0, 1, 2}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			requestBody := `{"model":"model-example","messages":[{"role":"user","content":"hello"}]}`
			responseBody := `{"id":"response-example","choices":[{"message":{"role":"assistant","content":"hi"}}]}`
			expectedChunks := int64(1)
			retained := ""
			if test.missing != nil {
				parts := []string{strings.Repeat("A", 1<<20), strings.Repeat("B", 1<<20), strings.Repeat("C", 1<<20)}
				if test.name == "middle chunk SSE" {
					for i := range parts {
						parts[i] = "data: " + parts[i][:len(parts[i])-8] + "\n\n"
					}
				}
				requestBody, responseBody = strings.Join(parts, ""), strings.Join(parts, "")
				expectedChunks = int64(len(parts) - len(test.missing))
				for seq, part := range parts {
					if !slices.Contains(test.missing, seq) {
						retained += part
					}
				}
			}
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil || string(body) != requestBody {
					t.Error("capture failure changed upstream request bytes")
				}
				w.Header().Set("Content-Type", "application/json")
				if test.name == "middle chunk SSE" {
					w.Header().Set("Content-Type", "text/event-stream")
				}
				_, _ = io.WriteString(w, responseBody)
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
			if test.trigger != "" {
				if _, err := injection.Exec(test.trigger); err != nil {
					t.Fatal(err)
				}
			}
			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, nil))
			var persistence audit.Store = store
			wantStatus, wantCode := sqlite.CaptureFailed, "capture_write_failed"
			if test.name == "stage enqueue" {
				persistence = &rejectStageFinishStore{Store: store}
				wantStatus, wantCode = sqlite.CapturePartial, "audit_finalize_failed"
			}
			manager, err := audit.NewManager(persistence, cipher, nil, audit.ModeAvailable, logger)
			if err != nil {
				t.Fatal(err)
			}
			handler := newTestHandlerWithOptions(t, upstream.URL, manager, logger, nil, defaultTestRoutes())
			request := httptest.NewRequest(http.MethodPost, "http://example.com/v1/chat/completions", strings.NewReader(requestBody))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Fail-Capture", "fixture")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK || response.Body.String() != responseBody {
				t.Fatal("capture failure changed the downstream response")
			}
			record := singleCompletionLogRecord(t, logs.Bytes())
			auditID, ok := record["audit_id"].(string)
			if !ok {
				t.Fatal("completion log is missing its audit ID")
			}
			snapshot, err := store.Snapshot(ctx, auditID)
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.Audit.CaptureStatus != wantStatus || snapshot.Audit.ErrorCode == nil || *snapshot.Audit.ErrorCode != wantCode {
				t.Fatal("fault injection did not persist a failed capture")
			}
			assertLogField(t, record, "capture_status", snapshot.Audit.CaptureStatus)
			assertLogField(t, record, "error_code", *snapshot.Audit.ErrorCode)
			assertLogField(t, record, "forward_status", sqlite.ForwardCompleted)
			if test.name != "header insert" {
				for _, stage := range snapshot.Stages {
					if stage.State != sqlite.StageStatePartial || stage.EndedAtNS == nil {
						t.Errorf("stage %s not terminated after rollback: %s", stage.Stage, stage.State)
					}
				}
				for _, body := range snapshot.Bodies {
					if body.State != sqlite.StageStatePartial || body.RetentionState != sqlite.RetentionFull || body.HashComplete || body.EOFSeen || body.ChunkCount != expectedChunks {
						t.Errorf("body %s did not recover a partial raw aggregate", body.Stage)
					}
					if test.missing != nil && (body.StoredLength != int64(len(retained)) || body.ObservedLength != int64(len(requestBody)) || body.ErrorCode == nil || *body.ErrorCode != sqlite.CaptureChunkMissing) {
						t.Error("chunk loss did not reconcile the actual retained aggregate")
					}
				}
			}
			queries, err := query.New(store, cipher)
			if err != nil {
				t.Fatal(err)
			}
			if test.name == "middle chunk SSE" {
				timeline, err := queries.Timeline(ctx, auditID, query.SideResponse)
				if err != nil || timeline.Complete || timeline.EventCount != 3 || len(timeline.Points) != 3 {
					t.Fatalf("timeline did not respect reconciled body completeness: %+v, %v", timeline, err)
				}
			}
			for side, expected := range map[query.Side]string{query.SideRequest: requestBody, query.SideResponse: responseBody} {
				if test.missing != nil {
					expected = retained
					metadata, err := queries.RawMeta(ctx, auditID, side)
					if err != nil || metadata.Complete || !metadata.MissingChunks || metadata.StoredLength != int64(len(retained)) {
						t.Fatalf("raw loss metadata is not explicit: %+v, %v", metadata, err)
					}
				}
				var raw bytes.Buffer
				if err := queries.StreamRaw(ctx, auditID, side, &raw); err != nil {
					t.Errorf("retained %s raw cannot be downloaded: %v", side, err)
				}
				if raw.String() != expected {
					t.Errorf("retained %s raw differs from the expected saved fragments", side)
				}
			}
			if err := store.VerifyIntegrityPayloads(ctx); err != nil {
				t.Fatalf("terminal metadata repair invalidated evidence signatures: %v", err)
			}
		})
	}
}

type rejectStageFinishStore struct{ *sqlite.Store }

func (*rejectStageFinishStore) FinishStage(context.Context, sqlite.StageFinish) error {
	return sqlite.ErrQueueFull
}
