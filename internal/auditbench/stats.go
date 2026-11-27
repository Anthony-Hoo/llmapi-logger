package auditbench

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// statsConn is the tool's own PostgreSQL session. Every statement it runs is
// one transaction, counted so the tool's commits can be subtracted from the
// database totals and its queries listed as overhead.
type statsConn struct {
	mu   sync.Mutex
	conn *pgx.Conn
	// transactions counts every transaction started on conn.
	transactions int64
	// polls counts the latency and drain queries on audit_records.
	latencyPolls int64
	drainPolls   int64
}

func (stats *statsConn) close() {
	stats.mu.Lock()
	defer stats.mu.Unlock()
	if stats.conn != nil {
		_ = stats.conn.Close(context.Background())
		stats.conn = nil
	}
}

// query runs fn in one transaction under the connection lock.
func (stats *statsConn) inTx(ctx context.Context, readOnly bool, fn func(pgx.Tx) error) error {
	stats.mu.Lock()
	defer stats.mu.Unlock()
	if stats.conn == nil {
		return errors.New("statistics connection closed")
	}
	stats.transactions++
	options := pgx.TxOptions{}
	if readOnly {
		options.AccessMode = pgx.ReadOnly
	}
	tx, err := stats.conn.BeginTx(ctx, options)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback(context.Background())
		return err
	}
	return tx.Commit(ctx)
}

// TableStats are the per-table counters and sizes of one snapshot.
type TableStats struct {
	HeapBytes  int64 `json:"heap_bytes"`
	ToastBytes int64 `json:"toast_bytes"`
	IndexBytes int64 `json:"index_bytes"`
	LiveTuples int64 `json:"live_tuples"`
	DeadTuples int64 `json:"dead_tuples"`

	Inserted    int64 `json:"tuples_inserted"`
	Updated     int64 `json:"tuples_updated"`
	HOTUpdated  int64 `json:"tuples_hot_updated"`
	Deleted     int64 `json:"tuples_deleted"`
	SeqScans    int64 `json:"seq_scans"`
	SeqTupRead  int64 `json:"seq_tuples_read"`
	IndexScans  int64 `json:"index_scans"`
	IdxTupFetch int64 `json:"index_tuples_fetched"`

	HeapBlocksRead       int64 `json:"heap_blocks_read"`
	HeapBlocksHit        int64 `json:"heap_blocks_hit"`
	IndexBlocksRead      int64 `json:"index_blocks_read"`
	IndexBlocksHit       int64 `json:"index_blocks_hit"`
	ToastBlocksRead      int64 `json:"toast_blocks_read"`
	ToastBlocksHit       int64 `json:"toast_blocks_hit"`
	ToastIndexBlocksRead int64 `json:"toast_index_blocks_read"`
	ToastIndexBlocksHit  int64 `json:"toast_index_blocks_hit"`

	Autovacuums  int64 `json:"autovacuums"`
	Autoanalyzes int64 `json:"autoanalyzes"`
}

// WALStats are cluster-wide WAL counters plus the insert position.
type WALStats struct {
	Records  int64 `json:"records"`
	FPI      int64 `json:"full_page_images"`
	Bytes    int64 `json:"bytes"`
	LSNBytes int64 `json:"lsn_bytes"`
}

// BackendStats are the per-backend counters of the application's writer
// session (PostgreSQL 18 pg_stat_get_backend_wal/io), which isolate the
// application's writes from any other session in the cluster.
type BackendStats struct {
	Available     bool  `json:"available"`
	WALRecords    int64 `json:"wal_records"`
	WALFPI        int64 `json:"wal_full_page_images"`
	WALBytes      int64 `json:"wal_bytes"`
	IOReads       int64 `json:"io_reads"`
	IOReadBytes   int64 `json:"io_read_bytes"`
	IOWrites      int64 `json:"io_writes"`
	IOWriteBytes  int64 `json:"io_write_bytes"`
	IOExtends     int64 `json:"io_extends"`
	IOHits        int64 `json:"io_hits"`
	IOUnavailable bool  `json:"io_unavailable,omitempty"`
}

// DatabaseStats come from pg_stat_database for the current database.
type DatabaseStats struct {
	XactCommit   int64  `json:"xact_commit"`
	XactRollback int64  `json:"xact_rollback"`
	BlocksRead   int64  `json:"blocks_read"`
	BlocksHit    int64  `json:"blocks_hit"`
	TupInserted  int64  `json:"tuples_inserted"`
	TupUpdated   int64  `json:"tuples_updated"`
	TupDeleted   int64  `json:"tuples_deleted"`
	TempBytes    int64  `json:"temp_bytes"`
	StatsReset   string `json:"-"`
}

// Activity counts client backends other than the tool's own session.
type Activity struct {
	SameDatabase  int64 `json:"same_database"`
	OtherDatabase int64 `json:"other_databases"`
}

type snapshot struct {
	at           time.Time
	tables       map[string]TableStats
	wal          WALStats
	writer       BackendStats
	database     DatabaseStats
	activity     Activity
	transactions int64
	walReset     string
}

// takeSnapshot reads every statistic in one read-only transaction, so the
// statistics cache of the session is fresh and the snapshot costs exactly one
// counted commit.
func (stats *statsConn) takeSnapshot(ctx context.Context, writerPID int32) (snapshot, error) {
	result := snapshot{tables: make(map[string]TableStats)}
	err := stats.inTx(ctx, true, func(tx pgx.Tx) error {
		result.transactions = stats.transactions
		result.at = time.Now()
		if _, err := tx.Exec(ctx, `SAVEPOINT flush`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_stat_force_next_flush()`); err != nil {
			if _, rollbackErr := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT flush`); rollbackErr != nil {
				return rollbackErr
			}
		}
		rows, err := tx.Query(ctx, `
SELECT c.relname,
       pg_relation_size(c.oid),
       COALESCE(pg_total_relation_size(NULLIF(c.reltoastrelid, 0)), 0),
       pg_indexes_size(c.oid),
       s.n_live_tup, s.n_dead_tup, s.n_tup_ins, s.n_tup_upd, s.n_tup_hot_upd, s.n_tup_del,
       COALESCE(s.seq_scan, 0), COALESCE(s.seq_tup_read, 0), COALESCE(s.idx_scan, 0), COALESCE(s.idx_tup_fetch, 0),
       COALESCE(io.heap_blks_read, 0), COALESCE(io.heap_blks_hit, 0),
       COALESCE(io.idx_blks_read, 0), COALESCE(io.idx_blks_hit, 0),
       COALESCE(io.toast_blks_read, 0), COALESCE(io.toast_blks_hit, 0),
       COALESCE(io.tidx_blks_read, 0), COALESCE(io.tidx_blks_hit, 0),
       s.autovacuum_count, s.autoanalyze_count
FROM pg_class AS c
JOIN pg_namespace AS n ON n.oid = c.relnamespace
JOIN pg_stat_user_tables AS s ON s.relid = c.oid
LEFT JOIN pg_statio_user_tables AS io ON io.relid = c.oid
WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p')`)
		if err != nil {
			return fmt.Errorf("table statistics: %w", err)
		}
		for rows.Next() {
			var name string
			var table TableStats
			if err := rows.Scan(&name, &table.HeapBytes, &table.ToastBytes, &table.IndexBytes,
				&table.LiveTuples, &table.DeadTuples, &table.Inserted, &table.Updated, &table.HOTUpdated, &table.Deleted,
				&table.SeqScans, &table.SeqTupRead, &table.IndexScans, &table.IdxTupFetch,
				&table.HeapBlocksRead, &table.HeapBlocksHit, &table.IndexBlocksRead, &table.IndexBlocksHit,
				&table.ToastBlocksRead, &table.ToastBlocksHit, &table.ToastIndexBlocksRead, &table.ToastIndexBlocksHit,
				&table.Autovacuums, &table.Autoanalyzes); err != nil {
				rows.Close()
				return fmt.Errorf("scan table statistics: %w", err)
			}
			result.tables[name] = table
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return fmt.Errorf("table statistics: %w", err)
		}
		if err := tx.QueryRow(ctx, `
SELECT wal_records, wal_fpi, wal_bytes::bigint, pg_wal_lsn_diff(pg_current_wal_lsn(), '0/0')::bigint,
       COALESCE(stats_reset::text, '')
FROM pg_stat_wal`).Scan(&result.wal.Records, &result.wal.FPI, &result.wal.Bytes, &result.wal.LSNBytes, &result.walReset); err != nil {
			return fmt.Errorf("WAL statistics: %w", err)
		}
		if err := tx.QueryRow(ctx, `
SELECT xact_commit, xact_rollback, blks_read, blks_hit, tup_inserted, tup_updated, tup_deleted, temp_bytes,
       COALESCE(stats_reset::text, '')
FROM pg_stat_database WHERE datname = current_database()`).Scan(&result.database.XactCommit, &result.database.XactRollback,
			&result.database.BlocksRead, &result.database.BlocksHit, &result.database.TupInserted, &result.database.TupUpdated,
			&result.database.TupDeleted, &result.database.TempBytes, &result.database.StatsReset); err != nil {
			return fmt.Errorf("database statistics: %w", err)
		}
		if err := tx.QueryRow(ctx, activityQuery).Scan(&result.activity.SameDatabase, &result.activity.OtherDatabase); err != nil {
			return fmt.Errorf("activity: %w", err)
		}
		if writerPID > 0 {
			result.writer = backendStats(ctx, tx, writerPID)
		}
		return nil
	})
	return result, err
}

const activityQuery = `
SELECT count(*) FILTER (WHERE datname = current_database()),
       count(*) FILTER (WHERE datname IS DISTINCT FROM current_database())
FROM pg_stat_activity
WHERE backend_type = 'client backend' AND pid <> pg_backend_pid()`

// backendStats reads the per-backend counters inside savepoints, because the
// functions exist only from PostgreSQL 18 on.
func backendStats(ctx context.Context, tx pgx.Tx, pid int32) BackendStats {
	var result BackendStats
	if _, err := tx.Exec(ctx, `SAVEPOINT backend_wal`); err != nil {
		return result
	}
	if err := tx.QueryRow(ctx, `SELECT wal_records, wal_fpi, wal_bytes::bigint FROM pg_stat_get_backend_wal($1)`, pid).
		Scan(&result.WALRecords, &result.WALFPI, &result.WALBytes); err != nil {
		_, _ = tx.Exec(ctx, `ROLLBACK TO SAVEPOINT backend_wal`)
		return result
	}
	result.Available = true
	if _, err := tx.Exec(ctx, `SAVEPOINT backend_io`); err != nil {
		result.IOUnavailable = true
		return result
	}
	if err := tx.QueryRow(ctx, `
SELECT COALESCE(sum(reads), 0)::bigint, COALESCE(sum(read_bytes), 0)::bigint,
       COALESCE(sum(writes), 0)::bigint, COALESCE(sum(write_bytes), 0)::bigint,
       COALESCE(sum(extends), 0)::bigint, COALESCE(sum(hits), 0)::bigint
FROM pg_stat_get_backend_io($1)`, pid).Scan(&result.IOReads, &result.IOReadBytes, &result.IOWrites, &result.IOWriteBytes,
		&result.IOExtends, &result.IOHits); err != nil {
		_, _ = tx.Exec(ctx, `ROLLBACK TO SAVEPOINT backend_io`)
		result.IOUnavailable = true
	}
	return result
}

// sampleActivity counts foreign client backends between snapshots.
func (stats *statsConn) sampleActivity(ctx context.Context) (Activity, error) {
	var result Activity
	err := stats.inTx(ctx, true, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, activityQuery).Scan(&result.SameDatabase, &result.OtherDatabase)
	})
	return result, err
}

// writerPID finds the application's pinned writer session by the advisory
// lock it holds for the schema (postgres.AcquireWriterLock).
func (stats *statsConn) writerPID(ctx context.Context) (int32, error) {
	var pid int32
	err := stats.inTx(ctx, true, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
WITH key AS (
    SELECT hashtextextended(current_database() || ':' || current_schema() || ':llmapi-writer', 0) AS value
)
SELECT l.pid
FROM pg_locks AS l, key
WHERE l.locktype = 'advisory' AND l.granted AND l.objsubid = 1
  AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database())
  AND l.classid::bigint = ((key.value >> 32) & 4294967295)
  AND l.objid::bigint = (key.value & 4294967295)
LIMIT 1`).Scan(&pid)
	})
	return pid, err
}

// Settings are the server settings needed to read the numbers.
var settingNames = []string{"server_version", "shared_buffers", "fsync", "synchronous_commit", "max_wal_size",
	"checkpoint_timeout", "wal_compression", "full_page_writes", "wal_level", "track_io_timing", "autovacuum"}

func (stats *statsConn) settings(ctx context.Context) (map[string]string, int, error) {
	values := make(map[string]string, len(settingNames))
	versionNumber := 0
	err := stats.inTx(ctx, true, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT name, setting, COALESCE(unit, '') FROM pg_settings WHERE name = ANY($1)`, settingNames)
		if err != nil {
			return err
		}
		for rows.Next() {
			var name, setting, unit string
			if err := rows.Scan(&name, &setting, &unit); err != nil {
				rows.Close()
				return err
			}
			values[name] = humanSetting(setting, unit)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		var number string
		if err := tx.QueryRow(ctx, `SHOW server_version_num`).Scan(&number); err != nil {
			return err
		}
		_, _ = fmt.Sscan(number, &versionNumber)
		return nil
	})
	return values, versionNumber, err
}

// humanSetting renders a pg_settings value with its unit, so 16384 x 8kB
// reads as 128MB the way SHOW prints it.
func humanSetting(setting, unit string) string {
	var value int64
	if _, err := fmt.Sscan(setting, &value); err != nil || unit == "" {
		if unit != "" {
			return setting + " " + unit
		}
		return setting
	}
	multiplier := map[string]int64{"8kB": 8 << 10, "kB": 1 << 10, "MB": 1 << 20, "B": 1, "16MB": 16 << 20}
	if factor, ok := multiplier[unit]; ok {
		bytes := value * factor
		switch {
		case bytes%(1<<30) == 0:
			return fmt.Sprintf("%dGB", bytes>>30)
		case bytes%(1<<20) == 0:
			return fmt.Sprintf("%dMB", bytes>>20)
		case bytes%(1<<10) == 0:
			return fmt.Sprintf("%dkB", bytes>>10)
		default:
			return fmt.Sprintf("%dB", bytes)
		}
	}
	return setting + unit
}
