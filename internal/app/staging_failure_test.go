package app

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/config"
	"llmapi-logger/internal/routing"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/postgres"
	"llmapi-logger/internal/storage/sqlite"
)

// failureBackend is one store under test: where its database is, how to
// make finalization fail as a storage error (a failed batch, not an isolated
// operation), and how to read an audit back.
type failureBackend struct {
	name     string
	database func(t *testing.T, cfg *config.Config, directory string)
	assemble func(context.Context, config.Config) auditRuntime
	block    string
	// isolated makes the same UPDATE fail as one operation (a constraint
	// class error): the commit fails on its own and is not retried.
	isolated string
	unblock  string
	snapshot func(context.Context, runtimeStore, string) (storage.Snapshot, error)
}

func failureBackends() []failureBackend {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	backends := []failureBackend{{
		name: "sqlite",
		database: func(_ *testing.T, cfg *config.Config, directory string) {
			cfg.DBPath = filepath.Join(directory, "audit.db")
		},
		assemble: func(ctx context.Context, cfg config.Config) auditRuntime { return assembleSQLiteTest(ctx, cfg, quiet) },
		// A trigger calling a function that does not exist fails the UPDATE
		// with SQLITE_ERROR: the whole batch rolls back.
		block: `CREATE TRIGGER block_finalization BEFORE UPDATE OF ended_at_ns ON audit_records
			WHEN NEW.ended_at_ns IS NOT NULL BEGIN SELECT staging_test_missing_function(); END`,
		isolated: `CREATE TRIGGER block_finalization BEFORE UPDATE OF ended_at_ns ON audit_records
			WHEN NEW.ended_at_ns IS NOT NULL BEGIN SELECT RAISE(ABORT, 'blocked by test'); END`,
		unblock: `DROP TRIGGER block_finalization`,
		snapshot: func(ctx context.Context, store runtimeStore, id string) (storage.Snapshot, error) {
			return store.(*sqlite.Store).Snapshot(ctx, id)
		},
	}}
	if dsn := os.Getenv("TEST_DATABASE_URL"); dsn != "" {
		backends = append(backends, failureBackend{
			name:     "postgres",
			database: func(t *testing.T, cfg *config.Config, _ string) { cfg.DatabaseURL = newStagingSchema(t, dsn) },
			assemble: func(ctx context.Context, cfg config.Config) auditRuntime { return assembleAudit(ctx, cfg, quiet) },
			// RAISE EXCEPTION is SQLSTATE P0001: not isolatable, the batch fails.
			block: `CREATE FUNCTION block_finalization_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'blocked by test'; END $$;
				CREATE TRIGGER block_finalization BEFORE UPDATE OF ended_at_ns ON audit_records FOR EACH ROW
				WHEN (NEW.ended_at_ns IS NOT NULL) EXECUTE FUNCTION block_finalization_fn()`,
			isolated: `CREATE FUNCTION block_finalization_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'blocked by test' USING ERRCODE = '23514'; END $$;
				CREATE TRIGGER block_finalization BEFORE UPDATE OF ended_at_ns ON audit_records FOR EACH ROW
				WHEN (NEW.ended_at_ns IS NOT NULL) EXECUTE FUNCTION block_finalization_fn()`,
			unblock: `DROP TRIGGER block_finalization ON audit_records; DROP FUNCTION block_finalization_fn()`,
			snapshot: func(ctx context.Context, store runtimeStore, id string) (storage.Snapshot, error) {
				return store.(*postgres.Store).Snapshot(ctx, id)
			},
		})
	}
	return backends
}

func execRaw(t *testing.T, backend failureBackend, cfg config.Config, statement string) {
	t.Helper()
	driver, source := "pgx", cfg.DatabaseURL
	if backend.name == "sqlite" {
		driver, source = "sqlite", "file:"+filepath.ToSlash(cfg.DBPath)
	}
	db, err := sql.Open(driver, source)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(statement); err != nil {
		t.Fatal(err)
	}
}

// driveOverBudget runs one exchange whose response is over the stage budget
// through the manager and finishes it.
func driveOverBudget(t *testing.T, manager *audit.Manager, response []byte) (*audit.Session, error) {
	t.Helper()
	ctx := context.Background()
	request := []byte(`{"model":"model-example","stream":true,"messages":[{"role":"user","content":"hello"}]}`)
	inbound := httptest.NewRequest(http.MethodPost, "http://proxy.example.com/v1/chat/completions", bytes.NewReader(request))
	inbound.Header.Set("Content-Type", "application/json")
	session, err := manager.Begin(ctx, inbound, routing.Match{RouteID: "chat", Parser: "openai.chat_completions"})
	if err != nil {
		t.Fatal(err)
	}
	outbound := inbound.Clone(ctx)
	outbound.Body = inbound.Body
	outbound.Host = "newapi.example.com"
	session.WrapRequestSent(outbound)
	_, _ = io.Copy(io.Discard, outbound.Body)
	_ = outbound.Body.Close()
	upstream := &http.Response{StatusCode: 200, Proto: "HTTP/1.1", ContentLength: -1, Request: outbound,
		Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(bytes.NewReader(response))}
	session.WrapResponseReceived(upstream)
	writer := session.WrapResponseWriter(httptest.NewRecorder(), inbound)
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.WriteHeader(200)
	buffer := make([]byte, 32<<10)
	for {
		count, err := upstream.Body.Read(buffer)
		if count > 0 {
			_, _ = writer.Write(buffer[:count])
		}
		if err != nil {
			break
		}
	}
	writer.CaptureTrailers()
	return session, session.Finish()
}

func overBudgetResponse() []byte {
	var builder strings.Builder
	for index := 0; builder.Len() < 3<<20+12345; index++ {
		fmt.Fprintf(&builder, "data: {\"choices\":[{\"delta\":{\"content\":\"token %d of a long answer\"}}]}\n\n", index)
	}
	builder.WriteString("data: [DONE]\n\n")
	return []byte(builder.String())
}

type failedCommitOutcome struct {
	audit    storage.AuditRecord
	chunks   map[string]int
	stored   map[string]int64
	bodies   int
	staged   int64
	leftover int
}

// runFailedCommit drives one over-budget exchange on writePath with
// finalization blocked, so the final commit (or FinishAudit) fails on every
// attempt. Then either the store recovers while the process lives
// (restart=false), or the process stops while the store still fails and
// starts again once it works.
func runFailedCommit(t *testing.T, backend failureBackend, restart, isolated bool) failedCommitOutcome {
	t.Helper()
	ctx := context.Background()
	directory := t.TempDir()
	cfg := testConfig(t)
	cfg.KeyPath = filepath.Join(directory, "key", "audit.key")
	backend.database(t, &cfg, directory)
	cfg.Mode = audit.ModeAvailable
	cfg.Audit.CommitRetries = 1
	cfg.Audit.Memory.StageBytes = 1 << 20
	cfg.Audit.Staging.Dir = filepath.Join(directory, "staging")
	runtime := backend.assemble(ctx, cfg)
	if runtime.store == nil {
		t.Fatal("audit store did not open")
	}
	block := backend.block
	if isolated {
		block = backend.isolated
	}
	execRaw(t, backend, cfg, block)
	session, err := driveOverBudget(t, runtime.manager, overBudgetResponse())
	if err == nil {
		t.Fatal("finalization was not blocked")
	}
	id := session.ID()
	var staged int64
	if runtime.stager != nil {
		runtime.stager.Flush()
		staged = runtime.stager.Stats().Records
	}
	if restart {
		// The process stops while the store still fails: its last recovery
		// attempt at close fails too, and the file stays.
		if runtime.stager != nil {
			_ = runtime.stager.Close()
		}
		_ = runtime.store.Close()
		execRaw(t, backend, cfg, backend.unblock)
		runtime = backend.assemble(ctx, cfg)
		if runtime.store == nil {
			t.Fatal("restart did not open the store")
		}
	} else {
		execRaw(t, backend, cfg, backend.unblock)
	}
	defer runtime.store.Close()
	if runtime.stager != nil {
		defer runtime.stager.Close()
	}
	var snapshot storage.Snapshot
	for deadline := time.Now().Add(pipelineWait); ; {
		snapshot, err = backend.snapshot(ctx, runtime.store, id)
		if err != nil {
			t.Fatal(err)
		}
		if snapshot.Audit.EndedAtNS != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the audit was never finalized")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := runtime.store.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatalf("integrity: %v", err)
	}
	outcome := failedCommitOutcome{audit: snapshot.Audit, chunks: map[string]int{}, stored: map[string]int64{}, bodies: len(snapshot.Bodies), staged: staged}
	for _, chunk := range snapshot.Chunks {
		outcome.chunks[chunk.Stage]++
	}
	for _, body := range snapshot.Bodies {
		outcome.stored[body.Stage] = body.StoredLength
		if body.RetentionState != storage.RetentionFull {
			t.Fatalf("raw not kept in full: %+v", body)
		}
		if int64(outcome.chunks[body.SourceStage]) != body.ChunkCount && body.SourceStage == body.Stage {
			t.Fatalf("body %s counts %d chunks, %d stored", body.Stage, body.ChunkCount, outcome.chunks[body.Stage])
		}
	}
	entries, _ := os.ReadDir(cfg.Audit.Staging.Dir)
	outcome.leftover = len(entries)
	return outcome
}

// The final commit of an audit with staged chunks fails on every attempt.
// Once the store can write again its staged chunks are stored under their
// body rows before the audit is finalized as failed, raw is kept in full,
// integrity verifies and the staging file is gone: while the process lives,
// and after a stop while the store still failed (the start-up import). The
// final states are the ones the legacy path reached under the same failure
// (failed while the process lives, interrupted after a restart); the test log
// shows the chunks kept.
func TestFailedFinalCommitKeepsStagedChunks(t *testing.T) {
	for _, backend := range failureBackends() {
		for _, variant := range []struct {
			name              string
			restart, isolated bool
		}{{"process alive", false, false}, {"stopped while failing", true, false}, {"operation failure, process alive", false, true}} {
			restart := variant.restart
			t.Run(backend.name+"/"+variant.name, func(t *testing.T) {
				unified := runFailedCommit(t, backend, restart, variant.isolated)
				t.Logf("%s/%s chunks %v stored %v, %d staged",
					unified.audit.ForwardStatus, unified.audit.CaptureStatus, unified.chunks, unified.stored, unified.staged)
				if unified.staged == 0 {
					t.Fatal("nothing was staged")
				}
				if unified.leftover != 0 {
					t.Fatalf("staging directory holds %d entries", unified.leftover)
				}
				wantForward := storage.ForwardCompleted
				wantCapture := storage.CaptureFailed
				if restart {
					wantForward, wantCapture = storage.ForwardInterrupted, storage.CapturePartial
				}
				// The legacy path ended the same way under the same failure.
				if unified.audit.ForwardStatus != wantForward || unified.audit.CaptureStatus != wantCapture {
					t.Fatalf("audit %s/%s, want %s/%s", unified.audit.ForwardStatus, unified.audit.CaptureStatus, wantForward, wantCapture)
				}
				response := storage.StageResponseReceived
				if int64(unified.chunks[response]) != unified.staged {
					t.Fatalf("%d of %d staged response chunks stored", unified.chunks[response], unified.staged)
				}
				// Every staged chunk is a whole 1 MiB chunk; the tail the session
				// still held in memory is lost (R.6 item 2).
				if unified.stored[response] != int64(unified.chunks[response])<<20 {
					t.Fatalf("response stored %d of %d whole chunks", unified.stored[response], unified.chunks[response])
				}
			})
		}
	}
}
