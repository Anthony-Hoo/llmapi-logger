package app

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/audit/staging"
	"llmapi-logger/internal/bodycodec"
	"llmapi-logger/internal/config"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/sqlite"
)

// K item 10: a staging directory that cannot be used makes available mode
// fall back to the legacy write path with a warning that says why, and
// strict mode refuse to audit.
func TestUnusableStagingDirectory(t *testing.T) {
	for _, mode := range []string{audit.ModeAvailable, audit.ModeStrict} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			notADirectory := filepath.Join(directory, "staging")
			if err := os.WriteFile(notADirectory, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			configuration := config.Default()
			configuration.Mode = mode
			configuration.DBPath = filepath.Join(directory, "audit.db")
			configuration.KeyPath = filepath.Join(directory, "key", "audit.key")
			configuration.Audit.WritePath = config.AuditWritePathUnified
			configuration.Audit.Staging.Dir = notADirectory
			var logs bytes.Buffer
			runtime := assembleSQLiteTest(context.Background(), configuration, slog.New(slog.NewJSONHandler(&logs, nil)))
			if runtime.store != nil {
				defer runtime.store.Close()
			}
			switch mode {
			case audit.ModeAvailable:
				if !runtime.manager.Healthy() || runtime.manager.WritePath() != audit.WritePathLegacy || runtime.stager != nil {
					t.Fatalf("healthy %v, write path %s", runtime.manager.Healthy(), runtime.manager.WritePath())
				}
				if !strings.Contains(logs.String(), `"msg":"audit staging unavailable, using the legacy write path"`) ||
					!strings.Contains(logs.String(), `"reason":"not_directory"`) {
					t.Fatalf("no warning with the reason: %s", logs.String())
				}
			default:
				if runtime.store != nil || runtime.manager.Healthy() {
					t.Fatal("strict mode audits without staging")
				}
				if !strings.Contains(logs.String(), `"reason":"not_directory"`) {
					t.Fatalf("no reason logged: %s", logs.String())
				}
			}
		})
	}
}

// A run on unified left staged chunks; the next start, on legacy, imports
// them before recovery, and recovery finalizes the audit with them.
func TestLegacyStartImportsWhatUnifiedStaged(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	databasePath := filepath.Join(directory, "audit.db")
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
	store, err := sqlite.Open(ctx, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnableIntegrity(ctx, key); err != nil {
		t.Fatal(err)
	}
	const id = "apx_staged_then_legacy"
	started := time.Now().Add(-time.Minute).UnixNano()
	if err := store.BeginAudit(ctx, sqlite.AuditRecord{AuditID: id, StartedAtNS: started, RouteID: "chat", Protocol: "openai",
		ParserName: "openai.chat_completions", Method: http.MethodPost, Path: "/v1/chat/completions", RequestURIEnc: []byte{1}, Mode: audit.ModeAvailable}); err != nil {
		t.Fatal(err)
	}
	// The spill checkpoint: the stage row and the body row the chunks belong to.
	if err := store.Checkpoint(ctx, storage.AuditCheckpoint{AuditID: id, CaptureVersion: 1,
		Stages: []storage.HTTPStage{{AuditID: id, Stage: storage.StageRequestReceived, State: storage.StageStateStreaming, Proto: "HTTP/1.1", Method: http.MethodPost, Host: "proxy.example.com", StartedAtNS: started + 1}},
		Bodies: []storage.BodyStream{{AuditID: id, Stage: storage.StageRequestReceived, SourceStage: storage.StageRequestReceived, State: storage.StageStateStreaming, RetentionState: storage.RetentionPending}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	stager, err := staging.Open(stagingDir, cipher, staging.Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	plaintext := bytes.Repeat([]byte(`{"content":"staged"}`), 1<<16)
	for seq := range 2 {
		piece := plaintext[seq*len(plaintext)/2 : (seq+1)*len(plaintext)/2]
		if _, err := stager.Stage(sealTestChunk(t, cipher, id, int64(seq), int64(seq*len(piece)), piece)); err != nil {
			t.Fatal(err)
		}
	}
	stager.Keep(id)
	if err := stager.Close(); err != nil {
		t.Fatal(err)
	}

	configuration := config.Default()
	configuration.DBPath = databasePath
	configuration.KeyPath = keyPath
	configuration.Audit.Staging.Dir = stagingDir
	runtime := assembleSQLiteTest(ctx, configuration, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if runtime.store == nil || runtime.manager.WritePath() != audit.WritePathLegacy || runtime.stager != nil {
		t.Fatalf("legacy start: store %v, write path %s", runtime.store != nil, runtime.manager.WritePath())
	}
	defer runtime.store.Close()
	if entries, _ := os.ReadDir(stagingDir); len(entries) != 0 {
		t.Fatalf("staging left %v", entries)
	}
	snapshot, err := runtime.store.(*sqlite.Store).Snapshot(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	body := snapshot.Bodies[0]
	if snapshot.Audit.ForwardStatus != storage.ForwardInterrupted || snapshot.Audit.CaptureStatus != storage.CapturePartial ||
		len(snapshot.Chunks) != 2 || body.StoredLength != int64(len(plaintext)) || body.ChunkCount != 2 ||
		body.State != storage.StageStatePartial || body.RetentionState != storage.RetentionFull {
		t.Fatalf("recovered audit %+v, body %+v, %d chunks", snapshot.Audit, body, len(snapshot.Chunks))
	}
	if err := runtime.store.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatalf("integrity: %v", err)
	}
}

func sealTestChunk(t *testing.T, cipher security.Cipher, auditID string, seq, offset int64, plaintext []byte) storage.BodyChunk {
	t.Helper()
	compression, encoded, err := (&bodycodec.Encoder{}).Encode(plaintext, "application/json")
	if err != nil {
		t.Fatal(err)
	}
	aad, err := security.AAD(auditID, "body_chunk_v2", storage.StageRequestReceived, strconv.FormatInt(seq, 10), compression)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := cipher.Encrypt(aad, encoded)
	if err != nil {
		t.Fatal(err)
	}
	return storage.BodyChunk{AuditID: auditID, Stage: storage.StageRequestReceived, Seq: seq, Offset: offset, PlaintextLength: len(plaintext),
		EncodedLength: len(encoded), ObservedAtNS: time.Now().UnixNano(), Compression: compression, DataEnc: encrypted}
}
