// Package postgres stores encrypted evidence in PostgreSQL with one fenced writer.
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgconn/ctxwatch"
	"github.com/jackc/pgx/v5/stdlib"
	"llmapi-logger/internal/security"
)

var ErrWriterOwned = errors.New("postgres: database already has an active writer")
var ErrWriterFenced = errors.New("postgres: writer connection lost; restart required")

const writerBatchDelay = 5 * time.Millisecond

// Store owns separate writer and read-only database pools plus the ordered
// writer queue.
type Store struct {
	writerDB   *sql.DB
	writerConn *sql.Conn
	fenced     atomic.Bool
	readerDB   *sql.DB
	queue      chan writeRequest
	done       chan struct{}
	logger     *slog.Logger

	submitMu  sync.RWMutex
	closed    bool
	healthy   atomic.Bool
	integrity atomic.Pointer[security.IntegritySigner]

	// Background and writer-detected integrity outcome. Kept apart from healthy
	// because the writer rewrites that flag after every committed batch,
	// which would erase a detected mismatch on the next audit write.
	payloadState atomic.Int32

	// Failed writes retain only bounded capture metadata, never ciphertext.
	recoveryMu        sync.Mutex
	recoveries        map[string]captureRecovery
	recoveryPending   atomic.Int32
	recoveryOverflow  atomic.Bool
	recoveryWake      chan struct{}
	submittedSequence uint64 // protected by submitMu
	processedSequence uint64 // writer goroutine only
	recoveryCursor    string // writer goroutine only; round-robin recovery

	closeOnce sync.Once
	closeErr  error
}

// Open acquires an exclusive session lock before migration or recovery. All
// writes use this exact pinned backend; a lost session can never reconnect and
// continue writing without its lock. This is intentionally a single-writer app.
func Open(ctx context.Context, dsn string) (*Store, error) { return OpenWithLogger(ctx, dsn, nil) }

func OpenWithLogger(ctx context.Context, dsn string, logger *slog.Logger) (*Store, error) {
	if ctx == nil || dsn == "" {
		return nil, errors.New("postgres: context and connection string required")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("postgres: invalid connection configuration")
	}
	// Cancel statements without throwing away the session lock. A five-second
	// network fallback still fences the writer if the server cannot respond.
	config.BuildContextWatcherHandler = func(conn *pgconn.PgConn) ctxwatch.Handler {
		return &pgconn.CancelRequestContextWatcherHandler{Conn: conn, CancelRequestDelay: 10 * time.Millisecond, DeadlineDelay: 5 * time.Second}
	}
	config.RuntimeParams["application_name"] = "llmapi-logger"
	config.RuntimeParams["statement_timeout"] = "30000"
	config.RuntimeParams["lock_timeout"] = "5000"
	config.RuntimeParams["synchronous_commit"] = "on"
	writerDB := stdlib.OpenDB(*config)
	writerDB.SetMaxOpenConns(1)
	conn, err := writerDB.Conn(ctx)
	if err != nil {
		_ = writerDB.Close()
		return nil, errors.New("postgres: connect writer failed")
	}
	cleanup := func() { _ = conn.Close(); _ = writerDB.Close() }
	if err := AcquireWriterLock(ctx, conn); err != nil {
		cleanup()
		return nil, err
	}
	if err := migrate(ctx, conn); err != nil {
		cleanup()
		return nil, err
	}
	readerConfig := config.Copy()
	readerConfig.RuntimeParams["default_transaction_read_only"] = "on"
	readerDB := stdlib.OpenDB(*readerConfig)
	readerDB.SetMaxOpenConns(4)
	readerDB.SetMaxIdleConns(2)
	if err := readerDB.PingContext(ctx); err != nil {
		_ = readerDB.Close()
		cleanup()
		return nil, errors.New("postgres: connect reader failed")
	}
	store := &Store{writerDB: writerDB, writerConn: conn, readerDB: readerDB,
		queue: make(chan writeRequest, writerQueueCapacity), done: make(chan struct{}),
		recoveryWake: make(chan struct{}, 1), logger: logger}
	store.healthy.Store(true)
	go store.runWriter()
	return store, nil
}

// Close drains accepted writes then closes the pinned backend, releasing ownership.
func (store *Store) Close() error {
	if store == nil {
		return nil
	}
	store.closeOnce.Do(func() {
		store.submitMu.Lock()
		store.closed = true
		store.healthy.Store(false)
		close(store.queue)
		store.submitMu.Unlock()
		<-store.done
		// Explicitly release the session lock before returning a healthy connection
		// to database/sql's pool; closing the pool then closes the backend itself.
		_, _ = store.writerConn.ExecContext(context.Background(), `SELECT pg_advisory_unlock_all()`)
		store.closeErr = errors.Join(store.readerDB.Close(), store.writerConn.Close(), store.writerDB.Close())
	})
	return store.closeErr
}

func (store *Store) beginWrite(ctx context.Context) (*countingTx, error) {
	if store.fenced.Load() {
		return nil, ErrWriterFenced
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// database/sql stores BeginTx's context for the driver's eventual Rollback.
	// Keep it live: rolling back with an already canceled policy context would
	// make pgx discard the pinned session (and its ownership lock). Individual
	// statements use ctx, and commitBatch checks it before committing.
	tx, err := store.writerConn.BeginTx(context.Background(), nil)
	if err != nil {
		// A transaction-level cancellation need not fence a live session. A failed
		// ping, however, permanently fences this Store. No new connection is opened.
		pingCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if store.writerConn.PingContext(pingCtx) != nil {
			store.fenced.Store(true)
		}
		return nil, err
	}
	return &countingTx{Tx: tx, ctx: ctx}, nil
}

// Healthy reports whether the store is open, the latest writer batch committed
// successfully, and background payload verification has not found a mismatch.
// A still-running verification does not count as unhealthy: the chain check
// already passed, and the pass only ever downgrades from there.
func (store *Store) Healthy() bool {
	if store == nil {
		return false
	}
	if store.payloadState.Load() == integrityPayloadsFailed || store.recoveryOverflow.Load() || store.recoveryPending.Load() != 0 {
		return false
	}
	store.submitMu.RLock()
	defer store.submitMu.RUnlock()
	return !store.closed && !store.fenced.Load() && store.healthy.Load()
}

// Background payload verification states, reported by IntegrityPayloadState.
const (
	integrityPayloadsPending int32 = iota
	integrityPayloadsVerified
	integrityPayloadsFailed
)

// IntegrityPayloadState reports how far background payload verification got:
// "pending" while it runs or was never started, "verified" once every event
// re-derived to its stored digest, "failed" once verification or a writer-side
// stored-object identity check detected corruption. Failure is sticky.
func (store *Store) IntegrityPayloadState() string {
	if store == nil {
		return "pending"
	}
	switch store.payloadState.Load() {
	case integrityPayloadsVerified:
		return "verified"
	case integrityPayloadsFailed:
		return "failed"
	default:
		return "pending"
	}
}

func (store *Store) isClosed() bool {
	if store == nil {
		return true
	}
	store.submitMu.RLock()
	defer store.submitMu.RUnlock()
	return store.closed
}
