package app

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/bodycodec"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/routing"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/postgres"
	"llmapi-logger/internal/storage/sqlite"
)

// legacyWriter is the per-operation write surface the removed legacy session
// used; both stores keep it (their Checkpoint and CommitAudit, version 1
// fixtures and the offline importer are built on it).
type legacyWriter interface {
	EnableIntegrity(context.Context, []byte) error
	BeginAudit(context.Context, storage.AuditRecord) error
	StartStage(context.Context, storage.HTTPStage) error
	StartBody(context.Context, storage.BodyStream) error
	AddHeaders(context.Context, []storage.HTTPHeader) error
	AddChunk(context.Context, storage.BodyChunk) error
	Close() error
}

// An audit the previous binary left open on the legacy write path (capture
// version 1) is finalized at the first start of this one: the rows below are
// what the legacy session had committed while the response streamed (design
// A.4, the third row): the start row, all four stages with their Header rows,
// the request bodies with their chunks and the request trailer, and the first
// full chunk of each response body. The start imports the empty staging
// directory, recovers the audit as interrupted with what was committed, raw
// kept in full, and every payload verifies; the stored bytes read back.
func TestFirstStartRecoversAnAuditTheLegacyPathLeftOpen(t *testing.T) {
	for _, backend := range failureBackends() {
		t.Run(backend.name, func(t *testing.T) {
			ctx := context.Background()
			directory := t.TempDir()
			cfg := testConfig(t)
			cfg.KeyPath = filepath.Join(directory, "key", "audit.key")
			backend.database(t, &cfg, directory)
			key, err := security.LoadOrCreateKey(cfg.KeyPath, true)
			if err != nil {
				t.Fatal(err)
			}
			cipher, err := security.NewAESGCM(key)
			if err != nil {
				t.Fatal(err)
			}
			var writer legacyWriter
			if backend.name == "sqlite" {
				writer, err = sqlite.Open(ctx, cfg.DBPath)
			} else {
				writer, err = postgres.Open(ctx, cfg.DatabaseURL)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := writer.EnableIntegrity(ctx, key); err != nil {
				t.Fatal(err)
			}
			const id = "apx_legacy_left_open"
			request := bytes.Repeat([]byte(`{"role":"user","content":"legacy"}`), 40_000)
			response := bytes.Repeat([]byte("data: {\"delta\":\"x\"}\n\n"), 60_000)
			stored := writeLegacyMidStream(t, ctx, writer, cipher, id, request, response)
			// Closing drains the writer: what was enqueued is committed, as it
			// was within milliseconds before the old process stopped.
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}

			runtime := backend.assemble(ctx, cfg)
			if runtime.store == nil || runtime.stager == nil || !runtime.manager.Healthy() {
				t.Fatal("the audit did not start")
			}
			defer runtime.store.Close()
			defer runtime.stager.Close()
			snapshot, err := backend.snapshot(ctx, runtime.store, id)
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.Audit.EndedAtNS == nil || snapshot.Audit.ForwardStatus != storage.ForwardInterrupted ||
				snapshot.Audit.CaptureStatus != storage.CapturePartial || snapshot.Audit.CaptureVersion != storage.CaptureVersion1 {
				t.Fatalf("recovered audit %+v", snapshot.Audit)
			}
			if len(snapshot.Stages) != 4 || len(snapshot.Bodies) != 4 || snapshot.HeaderBlock != nil {
				t.Fatalf("%d stages, %d bodies, block %v", len(snapshot.Stages), len(snapshot.Bodies), snapshot.HeaderBlock != nil)
			}
			for _, stage := range snapshot.Stages {
				if stage.State != storage.StageStatePartial || stage.EndedAtNS == nil {
					t.Fatalf("stage %+v", stage)
				}
			}
			for _, body := range snapshot.Bodies {
				if body.State != storage.StageStatePartial || body.RetentionState != storage.RetentionFull || body.StoredLength != stored[body.Stage] {
					t.Fatalf("body %s: %+v, %d bytes were committed", body.Stage, body, stored[body.Stage])
				}
			}
			if err := runtime.store.VerifyIntegrityPayloads(ctx); err != nil {
				t.Fatalf("integrity after recovery: %v", err)
			}
			queries, err := query.New(runtime.store, cipher)
			if err != nil {
				t.Fatal(err)
			}
			var raw bytes.Buffer
			if err := queries.StreamRaw(ctx, id, query.SideRequest, &raw); err != nil || !bytes.Equal(raw.Bytes(), request) {
				t.Fatalf("request raw: %d bytes, %v", raw.Len(), err)
			}
			detail, err := queries.Get(ctx, id, nil)
			if err != nil || len(detail.Headers) == 0 {
				t.Fatalf("detail: %d headers, %v", len(detail.Headers), err)
			}
			// The audit is finalized; a session of this binary is admitted.
			session, err := runtime.manager.Begin(ctx, httptest.NewRequest(http.MethodGet, "http://proxy.example.com/v1/models", nil),
				routing.Match{RouteID: "chat", Parser: "openai.chat_completions"})
			if err != nil {
				t.Fatal(err)
			}
			if err := session.Finish(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// writeLegacyMidStream writes, operation by operation, what the legacy
// session had committed while the response streamed, and returns the bytes
// stored per stage.
func writeLegacyMidStream(t *testing.T, ctx context.Context, writer legacyWriter, cipher security.Cipher, id string, request, response []byte) map[string]int64 {
	t.Helper()
	now := time.Now().Add(-time.Minute).UnixNano()
	tick := func() int64 { now++; return now }
	uriAAD, _ := security.AAD(id, "request_uri")
	uri, err := cipher.Encrypt(uriAAD, []byte("/v1/chat/completions"))
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.BeginAudit(ctx, storage.AuditRecord{AuditID: id, StartedAtNS: tick(), RouteID: "chat", Protocol: "openai",
		ParserName: "openai.chat_completions", Method: http.MethodPost, Path: "/v1/chat/completions", RequestURIEnc: uri,
		Mode: audit.ModeAvailable, ForwardStatus: storage.ForwardInProgress, CaptureStatus: storage.CapturePending, ParseStatus: storage.ParsePending}); err != nil {
		t.Fatal(err)
	}
	headers := func(stage, kind string, fields ...string) {
		var rows []storage.HTTPHeader
		for index := 0; index < len(fields); index += 2 {
			aad, _ := security.AAD(id, "header", stage, kind, fields[index], "0")
			value, err := cipher.Encrypt(aad, []byte(fields[index+1]))
			if err != nil {
				t.Fatal(err)
			}
			rows = append(rows, storage.HTTPHeader{AuditID: id, Stage: stage, Kind: kind, Name: fields[index], ValueIndex: 0, ValueLength: len(fields[index+1]), ValueEnc: value})
		}
		if err := writer.AddHeaders(ctx, rows); err != nil {
			t.Fatal(err)
		}
	}
	stored := map[string]int64{}
	chunks := func(stage, contentType string, data []byte, whole bool) {
		encoder := &bodycodec.Encoder{}
		for seq, offset := int64(0), 0; offset < len(data); seq++ {
			end := min(offset+1<<20, len(data))
			if end-offset < 1<<20 && !whole {
				return // the open chunk had not been flushed
			}
			compression, encoded, err := encoder.Encode(data[offset:end], contentType)
			if err != nil {
				t.Fatal(err)
			}
			aad, _ := security.AAD(id, "body_chunk_v2", stage, strconv.FormatInt(seq, 10), compression)
			sealed, err := cipher.Encrypt(aad, encoded)
			if err != nil {
				t.Fatal(err)
			}
			if err := writer.AddChunk(ctx, storage.BodyChunk{AuditID: id, Stage: stage, Seq: seq, Offset: int64(offset), PlaintextLength: end - offset,
				EncodedLength: len(encoded), ObservedAtNS: tick(), Compression: compression, DataEnc: sealed}); err != nil {
				t.Fatal(err)
			}
			stored[stage] += int64(end - offset)
			offset = end
		}
	}
	stage := func(name string, status *int, length int64, contentType string, data []byte, whole bool, headerFields ...string) {
		if err := writer.StartStage(ctx, storage.HTTPStage{AuditID: id, Stage: name, State: storage.StageStateStreaming, Proto: "HTTP/1.1",
			Method: http.MethodPost, Host: "proxy.example.com", StatusCode: status, ContentLength: &length, StartedAtNS: tick()}); err != nil {
			t.Fatal(err)
		}
		headers(name, storage.HeaderKindHeader, append([]string{"Content-Type", contentType}, headerFields...)...)
		if err := writer.StartBody(ctx, storage.BodyStream{AuditID: id, Stage: name, SourceStage: name, State: storage.StageStateStreaming,
			RetentionState: storage.RetentionPending}); err != nil {
			t.Fatal(err)
		}
		chunks(name, contentType, data, whole)
	}
	ok := http.StatusOK
	stage(storage.StageRequestReceived, nil, int64(len(request)), "application/json", request, true, "User-Agent", "client-example/1.0")
	headers(storage.StageRequestReceived, storage.HeaderKindTrailer, "X-Request-Checksum", "sum-1")
	stage(storage.StageRequestSent, nil, int64(len(request)), "application/json", request, true)
	stage(storage.StageResponseReceived, &ok, -1, "text/event-stream", response, false)
	stage(storage.StageResponseSent, &ok, -1, "text/event-stream", response, false)
	return stored
}
