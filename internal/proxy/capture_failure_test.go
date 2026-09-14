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

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

func TestAsyncCaptureFailuresMatchCompletionLogAndAllowRetainedRaw(t *testing.T) {
	for _, test := range []struct {
		name, trigger string
	}{
		{"header insert", `CREATE TRIGGER fail_capture_header BEFORE INSERT ON http_headers
WHEN NEW.name = 'X-Fail-Capture' BEGIN SELECT RAISE(ABORT, 'test capture failure'); END`},
		{"stage finalization", `CREATE TRIGGER fail_capture_finish BEFORE UPDATE OF state ON body_streams
WHEN NEW.state = 'complete' BEGIN SELECT RAISE(ABORT, 'test capture failure'); END`},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			const requestBody = `{"model":"model-example","messages":[{"role":"user","content":"hello"}]}`
			const responseBody = `{"id":"response-example","choices":[{"message":{"role":"assistant","content":"hi"}}]}`
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil || string(body) != requestBody {
					t.Error("capture failure changed upstream request bytes")
				}
				w.Header().Set("Content-Type", "application/json")
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
			if _, err := injection.Exec(test.trigger); err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, nil))
			manager, err := audit.NewManager(store, cipher, nil, audit.ModeAvailable, logger)
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
			if snapshot.Audit.CaptureStatus != sqlite.CaptureFailed || snapshot.Audit.ErrorCode == nil || *snapshot.Audit.ErrorCode != "capture_write_failed" {
				t.Fatal("fault injection did not persist a failed capture")
			}
			assertLogField(t, record, "capture_status", snapshot.Audit.CaptureStatus)
			assertLogField(t, record, "error_code", *snapshot.Audit.ErrorCode)
			assertLogField(t, record, "forward_status", sqlite.ForwardCompleted)
			if test.name == "stage finalization" {
				for _, stage := range snapshot.Stages {
					if stage.State != sqlite.StageStatePartial || stage.EndedAtNS == nil {
						t.Errorf("stage %s not terminated after rollback: %s", stage.Stage, stage.State)
					}
				}
				for _, body := range snapshot.Bodies {
					if body.State != sqlite.StageStatePartial || body.RetentionState != sqlite.RetentionFull || body.HashComplete || body.EOFSeen || body.ChunkCount != 1 || body.StoredLength == 0 {
						t.Errorf("body %s did not recover a partial raw aggregate", body.Stage)
					}
				}
			}
			queries, err := query.New(store, cipher)
			if err != nil {
				t.Fatal(err)
			}
			for side, expected := range map[query.Side]string{query.SideRequest: requestBody, query.SideResponse: responseBody} {
				var raw bytes.Buffer
				if err := queries.StreamRaw(ctx, auditID, side, &raw); err != nil {
					t.Errorf("retained %s raw cannot be downloaded: %v", side, err)
				}
				if raw.String() != expected {
					t.Errorf("retained %s raw differs from the forwarded bytes", side)
				}
			}
			if err := store.VerifyIntegrityPayloads(ctx); err != nil {
				t.Fatalf("terminal metadata repair invalidated evidence signatures: %v", err)
			}
		})
	}
}
