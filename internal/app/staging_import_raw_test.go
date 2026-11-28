package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/audit/staging"
	"llmapi-logger/internal/bodycodec"
	"llmapi-logger/internal/config"
	"llmapi-logger/internal/headerblock"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/postgres"
	"llmapi-logger/internal/storage/sqlite"
)

// The start-up import stores the staged ciphertext byte for byte: after the
// import and recovery, the raw bodies read back through the query layer are
// exactly the staged plaintext. Chunks of equal and of different sizes, in
// one stage and in two, cover a reader that reused one buffer for every
// record while the store still held earlier chunks in its insert batch.
// An integrity check alone would not notice: it covers whatever ciphertext
// was stored.
func TestStartImportStoresTheStagedBytesOnPostgreSQL(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required for PostgreSQL")
	}
	schemaURL := newStagingSchema(t, dsn)
	importAndReadRawBack(t, t.TempDir(), 2,
		func(ctx context.Context) (seedStore, error) { return postgres.Open(ctx, schemaURL) },
		func(configuration *config.Config) { configuration.DatabaseURL = schemaURL },
		func(ctx context.Context, configuration config.Config) auditRuntime {
			return assembleAudit(ctx, configuration, slog.New(slog.NewTextHandler(io.Discard, nil)))
		})
}

func TestStartImportStoresTheStagedBytes(t *testing.T) {
	directory := t.TempDir()
	databasePath := filepath.Join(directory, "audit.db")
	importAndReadRawBack(t, directory, 1,
		func(ctx context.Context) (seedStore, error) { return sqlite.Open(ctx, databasePath) },
		func(configuration *config.Config) { configuration.DBPath = databasePath },
		func(ctx context.Context, configuration config.Config) auditRuntime {
			return assembleSQLiteTest(ctx, configuration, slog.New(slog.NewTextHandler(io.Discard, nil)))
		})
}

func importAndReadRawBack(t *testing.T, directory string, version int, open func(context.Context) (seedStore, error),
	database func(*config.Config), assemble func(context.Context, config.Config) auditRuntime) {
	t.Helper()
	ctx := context.Background()
	keyPath := filepath.Join(directory, "key", "audit.key")
	stagingDir := filepath.Join(directory, "staging")
	key, err := security.LoadOrCreateKey(keyPath, true)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := security.NewAESGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	store, err := open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnableIntegrity(ctx, key); err != nil {
		t.Fatal(err)
	}
	const id = "apx_staged_bytes_restarted"
	started := time.Now().Add(-time.Minute).UnixNano()
	if err := store.BeginAudit(ctx, storage.AuditRecord{AuditID: id, StartedAtNS: started, RouteID: "chat", Protocol: "openai",
		ParserName: "openai.chat_completions", Method: http.MethodPost, Path: "/v1/chat/completions", RequestURIEnc: []byte{1},
		Mode: audit.ModeAvailable, CaptureVersion: version}); err != nil {
		t.Fatal(err)
	}
	stages := []string{storage.StageRequestReceived, storage.StageResponseReceived}
	checkpoint := storage.AuditCheckpoint{AuditID: id, CaptureVersion: version}
	var blockStages []headerblock.Stage
	for _, stage := range stages {
		checkpoint.Stages = append(checkpoint.Stages, storage.HTTPStage{AuditID: id, Stage: stage, State: storage.StageStateStreaming,
			Proto: "HTTP/1.1", Method: http.MethodPost, Host: "proxy.example.com", StartedAtNS: started + 1})
		checkpoint.Bodies = append(checkpoint.Bodies, storage.BodyStream{AuditID: id, Stage: stage, SourceStage: stage,
			State: storage.StageStateStreaming, RetentionState: storage.RetentionPending})
		blockStages = append(blockStages, headerblock.Stage{Name: stage,
			Headers: []headerblock.Field{{Name: "Content-Type", Values: [][]byte{[]byte("application/octet-stream")}}}})
	}
	if version == 2 {
		plaintext, err := headerblock.Encode(blockStages)
		if err != nil {
			t.Fatal(err)
		}
		compression, length, sealed, err := headerblock.Seal(cipher, id, plaintext)
		if err != nil {
			t.Fatal(err)
		}
		checkpoint.HeaderBlock = &storage.HeaderBlock{Compression: compression, PlaintextLength: length, DataEnc: sealed}
	}
	if err := store.Checkpoint(ctx, checkpoint); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	// Random bytes do not compress, so equal plaintext sizes give equal
	// record sizes. The request has two equal chunks, a smaller one and a
	// larger one; the response two equal chunks.
	sizes := map[string][]int{
		storage.StageRequestReceived:  {40_000, 40_000, 10_000, 70_000},
		storage.StageResponseReceived: {40_000, 40_000},
	}
	stager, err := staging.Open(stagingDir, cipher, staging.Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]byte{}
	for _, stage := range stages {
		var offset int64
		for seq, size := range sizes[stage] {
			piece := make([]byte, size)
			if _, err := rand.Read(piece); err != nil {
				t.Fatal(err)
			}
			if _, err := stager.Stage(sealStageChunk(t, cipher, id, stage, int64(seq), offset, piece)); err != nil {
				t.Fatal(err)
			}
			want[stage] = append(want[stage], piece...)
			offset += int64(size)
		}
	}
	stager.Keep(id)
	if err := stager.Close(); err != nil {
		t.Fatal(err)
	}

	configuration := testConfig(t)
	database(&configuration)
	configuration.KeyPath = keyPath
	configuration.Audit.Staging.Dir = stagingDir
	runtime := assemble(ctx, configuration)
	if runtime.store == nil || runtime.stager == nil || !runtime.manager.Healthy() {
		t.Fatalf("start: store %v, stager %v", runtime.store != nil, runtime.stager != nil)
	}
	defer runtime.store.Close()
	defer runtime.stager.Close()
	if entries, _ := os.ReadDir(stagingDir); len(entries) != 0 {
		t.Fatalf("staging left %v", entries)
	}
	reader, ok := runtime.store.(query.Store)
	if !ok {
		t.Fatal("the store does not serve queries")
	}
	service, err := query.New(reader, cipher)
	if err != nil {
		t.Fatal(err)
	}
	for side, stage := range map[query.Side]string{query.SideRequest: storage.StageRequestReceived, query.SideResponse: storage.StageResponseReceived} {
		var got bytes.Buffer
		if err := service.StreamRaw(ctx, id, side, &got); err != nil {
			t.Fatalf("raw %s: %v", stage, err)
		}
		if !bytes.Equal(got.Bytes(), want[stage]) {
			t.Fatalf("raw %s: %d bytes read back differ from the %d staged", stage, got.Len(), len(want[stage]))
		}
	}
	if err := runtime.store.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatalf("integrity: %v", err)
	}
}

func sealStageChunk(t *testing.T, cipher security.Cipher, auditID, stage string, seq, offset int64, plaintext []byte) storage.BodyChunk {
	t.Helper()
	compression, encoded, err := (&bodycodec.Encoder{}).Encode(plaintext, "application/octet-stream")
	if err != nil {
		t.Fatal(err)
	}
	aad, err := security.AAD(auditID, "body_chunk_v2", stage, strconv.FormatInt(seq, 10), compression)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := cipher.Encrypt(aad, encoded)
	if err != nil {
		t.Fatal(err)
	}
	return storage.BodyChunk{AuditID: auditID, Stage: stage, Seq: seq, Offset: offset, PlaintextLength: len(plaintext),
		EncodedLength: len(encoded), ObservedAtNS: time.Now().UnixNano(), Compression: compression, DataEnc: encrypted}
}
