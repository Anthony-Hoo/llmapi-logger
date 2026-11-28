package app

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/audit/staging"
	"llmapi-logger/internal/bodycodec"
	"llmapi-logger/internal/config"
	"llmapi-logger/internal/headerblock"
	"llmapi-logger/internal/routing"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/postgres"
	"llmapi-logger/internal/storage/sqlite"
)

// A staging directory that cannot be used at start-up makes the audit
// unavailable in both modes: there is no other write path to fall back to
// (the legacy fallback no longer exists). The store is closed, one warning
// says why with a stable reason and no path or error text, and nothing is
// captured: strict mode refuses the request, available mode forwards it
// without an audit.
func TestUnusableStagingDirectoryMakesTheAuditUnavailable(t *testing.T) {
	for _, test := range []struct {
		name string
		// reasons are the stable codes the platform may give.
		reasons []string
		unix    bool
		setup   func(t *testing.T, directory string) string
	}{
		{"not configured", []string{"staging_unavailable"}, false, func(*testing.T, string) string { return "" }},
		{"not a directory", []string{"not_directory"}, false, func(t *testing.T, directory string) string {
			path := filepath.Join(directory, "staging")
			if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		{"below a file", []string{"create_failed", "inspect_failed"}, false, func(t *testing.T, directory string) string {
			parent := filepath.Join(directory, "file")
			if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(parent, "staging")
		}},
		{"open to others", []string{"open_permissions"}, true, func(t *testing.T, directory string) string {
			path := filepath.Join(directory, "staging")
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o755); err != nil {
				t.Fatal(err)
			}
			return path
		}},
	} {
		for _, mode := range []string{audit.ModeAvailable, audit.ModeStrict} {
			t.Run(test.name+"/"+mode, func(t *testing.T) {
				if test.unix && runtime.GOOS == "windows" {
					t.Skip("directory permission bits are not checked on Windows")
				}
				directory := t.TempDir()
				configuration := testConfig(t)
				configuration.Mode = mode
				configuration.DBPath = filepath.Join(directory, "audit.db")
				configuration.KeyPath = filepath.Join(directory, "key", "audit.key")
				configuration.Audit.Staging.Dir = test.setup(t, directory)
				var logs bytes.Buffer
				assembled := assembleSQLiteTest(context.Background(), configuration, slog.New(slog.NewJSONHandler(&logs, nil)))
				if assembled.store != nil || assembled.stager != nil || assembled.manager.Healthy() {
					t.Fatal("the audit runs without a usable staging directory")
				}
				text := logs.String()
				reasoned := false
				for _, reason := range test.reasons {
					reasoned = reasoned || strings.Contains(text, `"reason":"`+reason+`"`)
				}
				if !strings.Contains(text, `"msg":"audit staging unavailable"`) || !strings.Contains(text, `"error_category":"staging_unavailable"`) ||
					!reasoned || strings.Contains(text, "legacy") ||
					strings.Contains(text, directory) || strings.Contains(text, strings.ReplaceAll(directory, `\`, `\\`)) {
					t.Fatalf("log %s", text)
				}
				request := httptest.NewRequest(http.MethodPost, "http://proxy.example.com/v1/chat/completions", strings.NewReader(`{}`))
				session, err := assembled.sink.Begin(context.Background(), request, routing.Match{RouteID: "chat", Parser: "openai.chat_completions"})
				if session != nil || !errors.Is(err, audit.ErrUnavailable) || assembled.sink.Mode() != mode {
					t.Fatalf("Begin = %v, %v (mode %s)", session, err, assembled.sink.Mode())
				}
				// Nothing reached the database either.
				store, err := sqlite.Open(context.Background(), configuration.DBPath)
				if err != nil {
					t.Fatal(err)
				}
				defer store.Close()
				if has, err := store.HasAudits(context.Background()); err != nil || has {
					t.Fatalf("audits stored: %v, %v", has, err)
				}
			})
		}
	}
}

// A run left staged chunks; the next start imports them before recovery, and
// recovery finalizes the audit with them.
func TestStartImportsWhatThePreviousRunStaged(t *testing.T) {
	startImportsOnSQLite(t, false)
}

// A start whose staging directory is unusable recovers nothing: the audit
// stays open with its chunks staged, and the next start with the directory
// back imports them and finalizes it (stage 3 design R.8, as R.3 item 2 for a
// file the import cannot read).
func TestUnusableStagingLeavesInterruptedAuditsOpen(t *testing.T) {
	startImportsOnSQLite(t, true)
}

func TestUnusableStagingLeavesInterruptedAuditsOpenOnPostgreSQL(t *testing.T) {
	startImportsOnPostgreSQL(t, true)
}

func startImportsOnSQLite(t *testing.T, unusableFirst bool) {
	t.Helper()
	directory := t.TempDir()
	databasePath := filepath.Join(directory, "audit.db")
	runImportAfterUnified(t, directory, 1, unusableFirst,
		func(ctx context.Context) (seedStore, error) { return sqlite.Open(ctx, databasePath) },
		func(configuration *config.Config) { configuration.DBPath = databasePath },
		func(ctx context.Context, configuration config.Config) auditRuntime {
			return assembleSQLiteTest(ctx, configuration, slog.New(slog.NewTextHandler(io.Discard, nil)))
		},
		func(ctx context.Context, store runtimeStore, id string) (storage.Snapshot, error) {
			return store.(*sqlite.Store).Snapshot(ctx, id)
		})
}

// The same on PostgreSQL with a capture version 2 start row: the recovered
// audit is signed over the version 2 payload and verifies.
func TestStartImportsWhatThePreviousRunStagedOnPostgreSQL(t *testing.T) {
	startImportsOnPostgreSQL(t, false)
}

func startImportsOnPostgreSQL(t *testing.T, unusableFirst bool) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required for PostgreSQL")
	}
	schemaURL := newStagingSchema(t, dsn)
	runImportAfterUnified(t, t.TempDir(), 2, unusableFirst,
		func(ctx context.Context) (seedStore, error) { return postgres.Open(ctx, schemaURL) },
		func(configuration *config.Config) { configuration.DatabaseURL = schemaURL },
		func(ctx context.Context, configuration config.Config) auditRuntime {
			return assembleAudit(ctx, configuration, slog.New(slog.NewTextHandler(io.Discard, nil)))
		},
		func(ctx context.Context, store runtimeStore, id string) (storage.Snapshot, error) {
			return store.(*postgres.Store).Snapshot(ctx, id)
		})
}

func newStagingSchema(t *testing.T, dsn string) string {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	schema := fmt.Sprintf("app_staging_%d_%d", time.Now().UnixNano(), testSchemas.Add(1))
	if _, err := db.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec("DROP SCHEMA " + schema + " CASCADE") })
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("invalid test DSN")
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

type seedStore interface {
	EnableIntegrity(context.Context, []byte) error
	BeginAudit(context.Context, storage.AuditRecord) error
	Checkpoint(context.Context, storage.AuditCheckpoint) error
	Close() error
}

// staleSnapshotter reads an audit back from a seed store.
type staleSnapshotter interface {
	Snapshot(context.Context, string) (storage.Snapshot, error)
}

// runImportAfterUnified seeds an audit left open with staged chunks, then
// starts the application. With unusableFirst a first start sees a regular
// file where the staging directory is (the files set aside): it must leave
// everything as it was.
func runImportAfterUnified(t *testing.T, directory string, version int, unusableFirst bool, open func(context.Context) (seedStore, error),
	database func(*config.Config), assemble func(context.Context, config.Config) auditRuntime,
	snapshotOf func(context.Context, runtimeStore, string) (storage.Snapshot, error)) {
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
	const id = "apx_staged_then_restarted"
	started := time.Now().Add(-time.Minute).UnixNano()
	if err := store.BeginAudit(ctx, storage.AuditRecord{AuditID: id, StartedAtNS: started, RouteID: "chat", Protocol: "openai",
		ParserName: "openai.chat_completions", Method: http.MethodPost, Path: "/v1/chat/completions", RequestURIEnc: []byte{1},
		Mode: audit.ModeAvailable, CaptureVersion: version}); err != nil {
		t.Fatal(err)
	}
	// The spill checkpoint: the stage row and the body row the chunks belong to.
	checkpoint := storage.AuditCheckpoint{AuditID: id, CaptureVersion: version,
		Stages: []storage.HTTPStage{{AuditID: id, Stage: storage.StageRequestReceived, State: storage.StageStateStreaming, Proto: "HTTP/1.1", Method: http.MethodPost, Host: "proxy.example.com", StartedAtNS: started + 1}},
		Bodies: []storage.BodyStream{{AuditID: id, Stage: storage.StageRequestReceived, SourceStage: storage.StageRequestReceived, State: storage.StageStateStreaming, RetentionState: storage.RetentionPending}},
	}
	if version == 2 {
		// Version 2 writes the header block of the stages written so far.
		plaintext, err := headerblock.Encode([]headerblock.Stage{{Name: storage.StageRequestReceived,
			Headers: []headerblock.Field{{Name: "Content-Type", Values: [][]byte{[]byte("application/json")}}}}})
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

	configuration := testConfig(t)
	database(&configuration)
	configuration.KeyPath = keyPath
	configuration.Audit.Staging.Dir = stagingDir
	if unusableFirst {
		startWithUnusableStaging(t, ctx, configuration, open, assemble, id)
	}
	runtime := assemble(ctx, configuration)
	if runtime.store == nil || runtime.stager == nil || !runtime.manager.Healthy() {
		t.Fatalf("start: store %v, stager %v", runtime.store != nil, runtime.stager != nil)
	}
	defer runtime.store.Close()
	defer runtime.stager.Close()
	if entries, _ := os.ReadDir(stagingDir); len(entries) != 0 {
		t.Fatalf("staging left %v", entries)
	}
	snapshot, err := snapshotOf(ctx, runtime.store, id)
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

// startWithUnusableStaging starts once with a regular file in place of the
// staging directory: the audit is unavailable, nothing is recovered or
// finalized, no chunk is added, and the staging files are untouched; then
// the directory is put back.
func startWithUnusableStaging(t *testing.T, ctx context.Context, configuration config.Config, open func(context.Context) (seedStore, error),
	assemble func(context.Context, config.Config) auditRuntime, id string) {
	t.Helper()
	stagingDir := configuration.Audit.Staging.Dir
	aside := stagingDir + "-aside"
	before := stagingEntries(t, stagingDir)
	if err := os.Rename(stagingDir, aside); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stagingDir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	unusable := assemble(ctx, configuration)
	if unusable.store != nil || unusable.stager != nil || unusable.manager.Healthy() {
		t.Fatal("the audit started without a usable staging directory")
	}
	store, err := open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.(staleSnapshotter).Snapshot(ctx, id)
	_ = store.Close()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Audit.EndedAtNS != nil || len(snapshot.Chunks) != 0 || snapshot.Audit.ForwardStatus != storage.ForwardInProgress {
		t.Fatalf("the unusable start changed the audit: %+v, %d chunks", snapshot.Audit, len(snapshot.Chunks))
	}
	if err := os.Remove(stagingDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(aside, stagingDir); err != nil {
		t.Fatal(err)
	}
	if after := stagingEntries(t, stagingDir); !reflect.DeepEqual(before, after) {
		t.Fatalf("staging files %v became %v", before, after)
	}
}

func stagingEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, fmt.Sprintf("%s %d", entry.Name(), info.Size()))
	}
	return names
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

type noUnifiedStore struct{ *sqlite.Store }

func (noUnifiedStore) SupportsUnifiedWrite() bool { return false }

// A manager that refuses the store is logged with a stable reason, never the
// error text (AGENTS.md, module 13).
func TestManagerRefusalLogsAStableReason(t *testing.T) {
	directory := t.TempDir()
	configuration := testConfig(t)
	configuration.DBPath = filepath.Join(directory, "audit.db")
	configuration.KeyPath = filepath.Join(directory, "key", "audit.key")
	configuration.Audit.Staging.Dir = filepath.Join(directory, "staging")
	var logs bytes.Buffer
	runtime := assembleAuditWithStore(context.Background(), configuration, slog.New(slog.NewJSONHandler(&logs, nil)),
		func(ctx context.Context, _ string, logger *slog.Logger) (runtimeStore, error) {
			store, err := sqlite.OpenWithLogger(ctx, configuration.DBPath, logger)
			if err != nil {
				return nil, err
			}
			return noUnifiedStore{store}, nil
		})
	if runtime.store != nil || runtime.manager.Healthy() {
		t.Fatal("a refused manager audits")
	}
	text := logs.String()
	if !strings.Contains(text, `"msg":"audit manager unavailable"`) || !strings.Contains(text, `"reason":"unified_unsupported"`) ||
		strings.Contains(text, "cannot serve") {
		t.Fatalf("log %s", text)
	}
}
