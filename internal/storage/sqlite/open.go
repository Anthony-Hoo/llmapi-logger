package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

const writerBatchDelay = 5 * time.Millisecond

// Store owns separate writer and read-only database pools plus the ordered
// writer queue.
type Store struct {
	writerDB *sql.DB
	readerDB *sql.DB
	queue    chan writeRequest
	done     chan struct{}

	submitMu sync.RWMutex
	closed   bool
	healthy  atomic.Bool

	closeOnce sync.Once
	closeErr  error
}

// Open creates the database parent directory, applies embedded migrations,
// configures WAL durability, and starts the single writer goroutine.
func Open(ctx context.Context, path string) (*Store, error) {
	if ctx == nil {
		return nil, errors.New("sqlite: nil context")
	}
	if path == "" {
		return nil, errors.New("sqlite: empty database path")
	}

	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("sqlite: resolve database path: %w", err)
	}
	if err := ensureParent(absolutePath); err != nil {
		return nil, err
	}

	writerDB, err := sql.Open("sqlite", sqliteDSN(absolutePath, false))
	if err != nil {
		return nil, fmt.Errorf("sqlite: open writer: %w", err)
	}
	writerDB.SetMaxOpenConns(1)
	writerDB.SetMaxIdleConns(1)
	if err := initializeWriter(ctx, writerDB); err != nil {
		_ = writerDB.Close()
		return nil, err
	}
	if err := migrate(ctx, writerDB); err != nil {
		_ = writerDB.Close()
		return nil, err
	}

	readerDB, err := sql.Open("sqlite", sqliteDSN(absolutePath, true))
	if err != nil {
		_ = writerDB.Close()
		return nil, fmt.Errorf("sqlite: open reader: %w", err)
	}
	readerDB.SetMaxOpenConns(4)
	readerDB.SetMaxIdleConns(2)
	if err := readerDB.PingContext(ctx); err != nil {
		_ = readerDB.Close()
		_ = writerDB.Close()
		return nil, fmt.Errorf("sqlite: ping reader: %w", err)
	}

	store := &Store{
		writerDB: writerDB,
		readerDB: readerDB,
		queue:    make(chan writeRequest, writerQueueCapacity),
		done:     make(chan struct{}),
	}
	store.healthy.Store(true)
	go store.runWriter()
	return store, nil
}

// Close drains accepted writes, performs a best-effort passive checkpoint,
// and closes both pools. It is safe to call more than once.
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
		_, _ = store.writerDB.Exec("PRAGMA wal_checkpoint(PASSIVE)")
		readerErr := store.readerDB.Close()
		writerErr := store.writerDB.Close()
		store.closeErr = errors.Join(readerErr, writerErr)
	})
	return store.closeErr
}

// Healthy reports whether the store is open and the latest writer batch
// committed successfully.
func (store *Store) Healthy() bool {
	if store == nil {
		return false
	}
	store.submitMu.RLock()
	defer store.submitMu.RUnlock()
	return !store.closed && store.healthy.Load()
}

func (store *Store) isClosed() bool {
	if store == nil {
		return true
	}
	store.submitMu.RLock()
	defer store.submitMu.RUnlock()
	return store.closed
}

func initializeWriter(ctx context.Context, database *sql.DB) error {
	if err := database.PingContext(ctx); err != nil {
		return fmt.Errorf("sqlite: ping writer: %w", err)
	}
	statements := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=FULL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
	}
	for _, statement := range statements {
		if _, err := database.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("sqlite: apply %s: %w", statement, err)
		}
	}
	return nil
}

func sqliteDSN(path string, readOnly bool) string {
	slashPath := filepath.ToSlash(path)
	if filepath.VolumeName(path) != "" && slashPath[0] != '/' {
		slashPath = "/" + slashPath
	}
	fileURL := (&url.URL{Scheme: "file", Path: slashPath}).String()
	parameters := url.Values{}
	parameters.Add("_pragma", "busy_timeout(5000)")
	parameters.Add("_pragma", "foreign_keys(1)")
	parameters.Add("_pragma", "synchronous(FULL)")
	if readOnly {
		parameters.Add("_pragma", "query_only(1)")
	}
	return fileURL + "?" + parameters.Encode()
}

func ensureParent(path string) error {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("sqlite: create database directory: %w", err)
	}
	return nil
}
