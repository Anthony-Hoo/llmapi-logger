package parser_test

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/builtin"
	"llmapi-logger/internal/protofixture"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/sqlite"
)

// faultStore is a SQLite store whose parse save can be made to fail once,
// and which counts the body pages the parser reads back.
type faultStore struct {
	*sqlite.Store
	path       string
	direct     *sql.DB
	chunkReads atomic.Int64
	// save, when set, replaces the next SaveParsedAudit; real saves.
	save func(ctx context.Context, real func() error) error
}

func (store *faultStore) SaveParsedAudit(ctx context.Context, value storage.ParsedAudit) error {
	real := func() error { return store.Store.SaveParsedAudit(ctx, value) }
	if save := store.save; save != nil {
		store.save = nil
		return save(ctx, real)
	}
	return real()
}

func (store *faultStore) ReadParserChunks(ctx context.Context, auditID, stage string, afterSeq int64, limit int) ([]storage.BodyChunk, error) {
	store.chunkReads.Add(1)
	return store.Store.ReadParserChunks(ctx, auditID, stage, afterSeq, limit)
}

// parseState reads the parse columns of an audit from the database file.
func (store *faultStore) parseState(t *testing.T, auditID string) (status string, failures int, backoff bool) {
	t.Helper()
	database := store.database(t)
	var next sql.NullInt64
	if err := database.QueryRow(`SELECT parse_status, parse_save_failures, parse_next_at_ns FROM audit_records WHERE audit_id = ?`, auditID).
		Scan(&status, &failures, &next); err != nil {
		t.Fatal(err)
	}
	return status, failures, next.Valid
}

// endBackoff makes a released audit claimable now instead of after its
// backoff, as if the backoff had elapsed.
func (store *faultStore) endBackoff(t *testing.T, auditID string) {
	t.Helper()
	database := store.database(t)
	if _, err := database.Exec(`UPDATE audit_records SET parse_next_at_ns = NULL WHERE audit_id = ?`, auditID); err != nil {
		t.Fatal(err)
	}
}

// database is one connection of the test's own, kept open: closing the last
// connection of a WAL database checkpoints it, which can make a write of the
// store's writer fail as busy.
func (store *faultStore) database(t *testing.T) *sql.DB {
	t.Helper()
	if store.direct == nil {
		database, err := sql.Open("sqlite", "file:"+filepath.ToSlash(store.path)+"?_pragma=busy_timeout(5000)")
		if err != nil {
			t.Fatal(err)
		}
		database.SetMaxOpenConns(1)
		store.direct = database
		t.Cleanup(func() { _ = database.Close() })
	}
	return store.direct
}

func newFaultStore(t *testing.T) *faultStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := sqlite.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.EnableIntegrity(context.Background(), finalizeKey); err != nil {
		t.Fatal(err)
	}
	return &faultStore{Store: store, path: path}
}

// waitReparsed waits for the parse from the database that follows a released
// attempt, and fails with what the audit and the worker looked like when the
// wait expired: a second release puts the audit into a 60-second backoff that
// only a later pending scan ends.
func (store *faultStore) waitReparsed(t *testing.T, worker *parser.Worker, auditID string) {
	t.Helper()
	deadline := time.Now().Add(parser.PipelineWait)
	for {
		database := store.database(t)
		var status string
		var failures int
		var next sql.NullInt64
		if err := database.QueryRow(`SELECT parse_status, parse_save_failures, parse_next_at_ns FROM audit_records WHERE audit_id = ?`, auditID).
			Scan(&status, &failures, &next); err != nil {
			t.Fatal(err)
		}
		if status != storage.ParsePending && status != storage.ParseProcessing {
			return
		}
		if time.Now().After(deadline) {
			backoff := "NULL"
			if next.Valid {
				backoff = time.Until(time.Unix(0, next.Int64)).Round(time.Second).String() + " from now"
			}
			t.Fatalf("audit %s was not parsed again within %v: parse_status=%s parse_save_failures=%d parse_next_at_ns=%s, %d jobs queued",
				auditID, parser.PipelineWait, status, failures, backoff, worker.QueueLength())
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// faultyParser wraps a built-in parser: its normalizer panics, or its parse
// stalls, the next times asked.
type faultyParser struct {
	parser.Parser
	normalizer parser.AuditNormalizer
	panics     atomic.Int64
	stalls     atomic.Int64
	stall      time.Duration
}

func (wrapped *faultyParser) Parse(ctx context.Context, input parser.Input) parser.Result {
	if wrapped.stalls.Add(-1) >= 0 {
		time.Sleep(wrapped.stall)
	}
	return wrapped.Parser.Parse(ctx, input)
}

func (wrapped *faultyParser) NormalizeAudit(ctx context.Context, input parser.Input, result parser.Result) (auditmodel.Turn, error) {
	if wrapped.panics.Add(-1) >= 0 {
		panic("synthetic normalizer panic")
	}
	return wrapped.normalizer.NormalizeAudit(ctx, input, result)
}

func faultyParsers(t *testing.T, name string) ([]parser.Parser, *faultyParser) {
	t.Helper()
	var parsers []parser.Parser
	var faulty *faultyParser
	for _, implementation := range builtin.All() {
		if implementation.Name() == name {
			normalizer, ok := implementation.(parser.AuditNormalizer)
			if !ok {
				t.Fatalf("%s has no normalizer", name)
			}
			faulty = &faultyParser{Parser: implementation, normalizer: normalizer}
			implementation = faulty
		}
		parsers = append(parsers, implementation)
	}
	if faulty == nil {
		t.Fatalf("no parser %s", name)
	}
	return parsers, faulty
}

// Design G.2 and K items 14 and 19: when the finalizer cannot finish a job,
// the process survives, the claim is released (or, when the save committed
// and only its acknowledgement was lost, the audit keeps its saved parse),
// the audit stays pending with today's failure counter and backoff, and the
// existing path parses it later from the database.
func TestFinalizerFailuresLeaveTheAuditToTheDatabasePath(t *testing.T) {
	exchanges, err := protofixture.Build(protofixture.Case{Protocol: protofixture.OpenAIChat, Scenario: protofixture.ScenarioBasic},
		protofixture.Options{Seed: 12})
	if err != nil {
		t.Fatal(err)
	}
	// deadline is the job deadline of the cases whose first attempt must
	// run into it. The parse from the database that follows runs under the
	// same deadline, so it must fit too: if it overran, it would be released
	// a second time and wait out a 60-second backoff, past every wait here.
	// That parse of this small exchange takes well under 0.3 s on a tenth of
	// a CPU; 5 s keeps it clear under -race on a slow runner. The other cases
	// keep the worker's own deadline.
	const deadline = 5 * time.Second
	for _, test := range []struct {
		name string
		// arrange breaks the first attempt.
		arrange func(store *faultStore, faulty *faultyParser)
		// released: the first attempt released the claim, counting one
		// failure; otherwise the saved parse stands.
		released bool
		// expires: the first attempt runs into the job deadline.
		expires bool
	}{
		{name: "normalizer panics", released: true, arrange: func(_ *faultStore, faulty *faultyParser) { faulty.panics.Store(1) }},
		{name: "deadline passes before the save", released: true, expires: true, arrange: func(_ *faultStore, faulty *faultyParser) {
			faulty.stall = 2 * deadline
			faulty.stalls.Store(1)
		}},
		{name: "deadline passes during the save", released: true, expires: true, arrange: func(store *faultStore, _ *faultyParser) {
			store.save = func(ctx context.Context, _ func() error) error { <-ctx.Done(); return ctx.Err() }
		}},
		{name: "save fails", released: true, arrange: func(store *faultStore, _ *faultyParser) {
			store.save = func(context.Context, func() error) error { return fmt.Errorf("save: %w", storage.ErrQueueFull) }
		}},
		{name: "save acknowledgement lost", released: false, expires: true, arrange: func(store *faultStore, _ *faultyParser) {
			store.save = func(ctx context.Context, real func() error) error {
				if err := real(); err != nil {
					return err
				}
				<-ctx.Done()
				return ctx.Err()
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := newFaultStore(t)
			parsers, faulty := faultyParsers(t, "openai.chat_completions")
			harness := newFinalizeHarness(t, store, audit.Options{}, parsers)
			if test.expires {
				harness.worker.SetJobDeadlineForTest(deadline)
			}
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			if err := harness.worker.Start(ctx); err != nil {
				t.Fatal(err)
			}
			harness.send(harness.handler, exchanges[0])
			job := harness.next()
			if job.Evidence == nil {
				t.Fatal("id-only job")
			}
			id := job.Audit.AuditID
			test.arrange(store, faulty)
			submitAll(t, harness.worker, job)
			if !test.released {
				waitParsed(t, store, id)
				waitFor(t, func() bool { return harness.manager.MemoryInUse() == 0 })
				if status, failures, _ := store.parseState(t, id); status != storage.ParseOK || failures != 0 || store.chunkReads.Load() != 0 {
					t.Fatalf("status %s, %d failures, %d chunk pages read", status, failures, store.chunkReads.Load())
				}
				return
			}
			waitFor(t, func() bool {
				status, failures, _ := store.parseState(t, id)
				return status == storage.ParsePending && failures == 1
			})
			if _, _, backoff := store.parseState(t, id); !backoff {
				t.Fatal("a released audit has no backoff")
			}
			// K item 19: the retention state is not touched; the raw stays
			// pending for the parse from the database.
			var touched int
			if err := store.database(t).QueryRow(`SELECT COUNT(*) FROM body_streams WHERE audit_id = ? AND retention_state <> 'pending'`, id).Scan(&touched); err != nil || touched != 0 {
				t.Fatalf("%d body rows had their retention changed (%v)", touched, err)
			}
			// The process is alive and the pending path picks the audit up
			// once its backoff has elapsed, reading it from the database.
			store.endBackoff(t, id)
			harness.worker.ScanForTest(ctx)
			store.waitReparsed(t, harness.worker, id)
			if status, failures, _ := store.parseState(t, id); status != storage.ParseOK || failures != 1 || store.chunkReads.Load() == 0 {
				t.Fatalf("later parse: status %s, %d failures, %d chunk pages read", status, failures, store.chunkReads.Load())
			}
			if used := harness.manager.MemoryInUse(); used != 0 {
				t.Fatalf("budget holds %d bytes", used)
			}
		})
	}
}

// A normalizer that panics every time ends, after the fifth release, with the
// terminal error a save failing five times gets.
func TestNormalizerPanickingEveryTimeEndsAsASaveFailure(t *testing.T) {
	exchanges, err := protofixture.Build(protofixture.Case{Protocol: protofixture.OpenAIChat, Scenario: protofixture.ScenarioBasic},
		protofixture.Options{Seed: 13})
	if err != nil {
		t.Fatal(err)
	}
	store := newFaultStore(t)
	parsers, faulty := faultyParsers(t, "openai.chat_completions")
	faulty.panics.Store(1 << 30)
	harness := newFinalizeHarness(t, store, audit.Options{}, parsers)
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	if err := harness.worker.Start(ctx); err != nil {
		t.Fatal(err)
	}
	harness.send(harness.handler, exchanges[0])
	job := harness.next()
	id := job.Audit.AuditID
	submitAll(t, harness.worker, job)
	for attempt := 1; attempt <= 5; attempt++ {
		waitFor(t, func() bool {
			status, failures, _ := store.parseState(t, id)
			return failures == attempt && status != storage.ParseProcessing
		})
		if attempt < 5 {
			store.endBackoff(t, id)
			harness.worker.ScanForTest(ctx)
		}
	}
	if status, _, _ := store.parseState(t, id); status != storage.ParseError {
		t.Fatalf("status %s after five panics", status)
	}
}
