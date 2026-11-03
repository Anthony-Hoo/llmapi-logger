// Package migrate implements an explicit, offline, non-destructive schema-12 import.
package migrate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"net/url"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/postgres"
	_ "modernc.org/sqlite"
)

// Error intentionally carries no driver error, SQL, file path, DSN or evidence.
type Error string

func (e Error) Error() string { return "audit-import: " + string(e) }

type Options struct {
	SourcePath, DatabaseURL string
	Key                     []byte
	ServiceStopped, DryRun  bool
}
type TableReport struct {
	Table string `json:"table"`
	Rows  int64  `json:"rows"`
}
type Report struct {
	SourceSchema int           `json:"source_schema"`
	DryRun       bool          `json:"dry_run"`
	Tables       []TableReport `json:"tables"`
}

// Run holds one read-only SQLite snapshot (including WAL) and one PostgreSQL
// transaction. The caller must stop both services and preserve a backup first.
func Run(ctx context.Context, opt Options) (Report, error) {
	report := Report{SourceSchema: 12, DryRun: opt.DryRun}
	if !opt.ServiceStopped {
		return report, Error("service_stop_confirmation_required")
	}
	if ctx == nil || opt.SourcePath == "" || opt.DatabaseURL == "" || len(opt.Key) != 32 {
		return report, Error("invalid_options")
	}
	path, err := filepath.Abs(opt.SourcePath)
	if err != nil {
		return report, Error("source_open_failed")
	}
	uri := url.URL{Scheme: "file", Path: path}
	q := uri.Query()
	q.Set("mode", "ro")
	q.Add("_pragma", "query_only(1)")
	uri.RawQuery = q.Encode()
	source, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return report, Error("source_open_failed")
	}
	defer source.Close()
	source.SetMaxOpenConns(1)
	src, err := source.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return report, Error("source_open_failed")
	}
	defer src.Rollback()
	var versions, count int
	if err = src.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0),count(*) FROM schema_migrations`).Scan(&versions, &count); err != nil || versions != 12 || count != 10 {
		return report, Error("unsupported_source_schema")
	}
	var bad int
	if err = src.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version NOT IN (1,4,5,6,7,8,9,10,11,12)`).Scan(&bad); err != nil || bad != 0 {
		return report, Error("unsupported_source_schema")
	}
	rows, err := src.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return report, Error("source_integrity_failed")
	}
	invalid := rows.Next()
	err = rows.Err()
	rows.Close()
	if invalid || err != nil {
		return report, Error("source_integrity_failed")
	}
	var check string
	if err = src.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&check); err != nil || check != "ok" {
		return report, Error("source_integrity_failed")
	}
	config, err := pgx.ParseConfig(opt.DatabaseURL)
	if err != nil {
		return report, Error("target_open_failed")
	}
	config.RuntimeParams["application_name"] = "llmapi-audit-import"
	config.RuntimeParams["synchronous_commit"] = "on"
	db := stdlib.OpenDB(*config)
	defer db.Close()
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		return report, Error("target_open_failed")
	}
	defer conn.Close()
	if err = postgres.AcquireWriterLock(ctx, conn); err != nil {
		return report, Error("target_writer_locked")
	}
	defer conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock_all()`)
	dst, err := conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return report, Error("target_transaction_failed")
	}
	defer dst.Rollback()
	if err = postgres.InitializeImportSchema(ctx, dst); err != nil {
		return report, Error("target_schema_failed")
	}
	// Refuse unrecognized target tables rather than silently mixing repositories.
	targetTables, err := dst.QueryContext(ctx, `SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname=current_schema()`)
	if err != nil {
		return report, Error("target_schema_failed")
	}
	known := map[string]bool{"schema_migrations": true, "offline_import_history": true, "analysis_detail_objects": true}
	for _, t := range tables {
		known[t.name] = true
	}
	hasDetailObjects := false
	for targetTables.Next() {
		var name string
		if err = targetTables.Scan(&name); err != nil {
			targetTables.Close()
			return report, Error("target_schema_failed")
		}
		if !known[name] {
			targetTables.Close()
			return report, Error("target_not_empty")
		}
		if name == "analysis_detail_objects" {
			hasDetailObjects = true
		}
	}
	err = targetTables.Err()
	targetTables.Close()
	if err != nil {
		return report, Error("target_schema_failed")
	}
	if hasDetailObjects {
		var count int64
		if err = dst.QueryRowContext(ctx, `SELECT count(*) FROM analysis_detail_objects`).Scan(&count); err != nil || count != 0 {
			return report, Error("target_not_empty")
		}
	}
	// A durable marker prevents importing an empty source repeatedly as well.
	if _, err = dst.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS offline_import_history (singleton BIGINT PRIMARY KEY CHECK(singleton=1), source_schema BIGINT NOT NULL)`); err != nil {
		return report, Error("target_schema_failed")
	}
	if err = dst.QueryRowContext(ctx, `SELECT count(*) FROM offline_import_history`).Scan(&bad); err != nil || bad != 0 {
		return report, Error("target_not_empty")
	}
	for _, table := range tables {
		var n int64
		if err = dst.QueryRowContext(ctx, `SELECT count(*) FROM `+quote(table.name)).Scan(&n); err != nil {
			return report, Error("target_schema_failed")
		}
		if n != 0 {
			if table.name != "user_agent_rules" || n != 1 {
				return report, Error("target_not_empty")
			}
			var seed int
			err = dst.QueryRowContext(ctx, `SELECT count(*) FROM user_agent_rules WHERE id=1 AND name='GPT models require Codex clients' AND enabled=1 AND model_pattern='^gpt' AND user_agent_pattern='^(codex-tui|Codex Desktop)' AND created_at_ns>0 AND updated_at_ns=created_at_ns`).Scan(&seed)
			if err != nil || seed != 1 {
				return report, Error("target_not_empty")
			}
			if _, err = dst.ExecContext(ctx, `DELETE FROM user_agent_rules WHERE id=1`); err != nil {
				return report, Error("target_not_empty")
			}
		}
	}
	for _, table := range tables {
		n, digest, err := copyTable(ctx, src, dst, table, opt.Key)
		if err != nil {
			return report, err
		}
		actual, got, err := digestTable(ctx, dst, table)
		if err != nil || actual != n || !bytes.Equal(digest, got) {
			return report, Error("target_verification_failed")
		}
		report.Tables = append(report.Tables, TableReport{table.name, n})
	}
	if err = restoreSequences(ctx, src, dst); err != nil {
		return report, err
	}
	signer, _ := security.NewIntegritySigner(opt.Key)
	if err = postgres.VerifyImportIntegrity(ctx, dst, signer); err != nil {
		return report, Error("evidence_integrity_failed")
	}
	if err = verifyGraphs(ctx, dst, opt.Key); err != nil {
		return report, Error("graph_integrity_failed")
	}
	if _, err = dst.ExecContext(ctx, `INSERT INTO offline_import_history(singleton,source_schema) VALUES(1,12)`); err != nil {
		return report, Error("target_write_failed")
	}
	if opt.DryRun {
		return report, nil
	}
	if err = dst.Commit(); err != nil {
		return report, Error("target_commit_outcome_unknown")
	}
	return report, nil
}
func quote(s string) string { return `"` + s + `"` }
func columns(t tableSpec) string {
	out := make([]string, len(t.columns))
	for i, s := range t.columns {
		out[i] = quote(s)
	}
	return strings.Join(out, ",")
}
func selectSQL(t tableSpec) string {
	return `SELECT ` + columns(t) + ` FROM ` + quote(t.name) + ` ORDER BY ` + t.order
}
func scanRow(rows *sql.Rows, t tableSpec) ([]any, error) {
	v := make([]any, len(t.columns))
	p := make([]any, len(v))
	for i := range v {
		p[i] = &v[i]
	}
	if err := rows.Scan(p...); err != nil {
		return nil, Error("source_read_failed")
	}
	for i, x := range v {
		if x == nil {
			continue
		}
		switch t.types[i] {
		case "TEXT":
			s, ok := x.(string)
			if !ok || !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
				return nil, Error("invalid_source_text")
			}
		case "INTEGER":
			if _, ok := x.(int64); !ok {
				return nil, Error("invalid_source_integer")
			}
		case "BLOB":
			blob, ok := x.([]byte)
			if !ok {
				return nil, Error("invalid_source_blob")
			}
			// modernc may represent SQL X'' as a typed nil []byte. pgx binds
			// that representation as NULL, so preserve the non-NULL SQL value
			// with a nonnil empty slice before passing it to PostgreSQL.
			if blob == nil {
				v[i] = []byte{}
			}
		}
	}
	return v, nil
}
func hashRow(h hash.Hash, v []any) {
	var b [8]byte
	for _, x := range v {
		switch y := x.(type) {
		case nil:
			h.Write([]byte{0})
		case int64:
			h.Write([]byte{1})
			binary.BigEndian.PutUint64(b[:], uint64(y))
			h.Write(b[:])
		case float64:
			h.Write([]byte{2})
			binary.BigEndian.PutUint64(b[:], math.Float64bits(y))
			h.Write(b[:])
		case string:
			h.Write([]byte{3})
			binary.BigEndian.PutUint64(b[:], uint64(len(y)))
			h.Write(b[:])
			h.Write([]byte(y))
		case []byte:
			h.Write([]byte{4})
			binary.BigEndian.PutUint64(b[:], uint64(len(y)))
			h.Write(b[:])
			h.Write(y)
		}
	}
}
func copyTable(ctx context.Context, src, dst *sql.Tx, t tableSpec, key []byte) (int64, []byte, error) {
	// Table copying is ordered by primary key for stable verification. Defer only
	// the self-reference temporarily, restoring its immediate semantics below.
	if t.name == "turns" {
		if _, err := dst.ExecContext(ctx, `ALTER TABLE turns ALTER CONSTRAINT turns_parent_turn_id_fkey DEFERRABLE INITIALLY DEFERRED`); err != nil {
			return 0, nil, Error("target_schema_failed")
		}
	}
	rows, err := src.QueryContext(ctx, selectSQL(t))
	if err != nil {
		return 0, nil, Error("source_schema_failed")
	}
	defer rows.Close()
	placeholders := make([]string, len(t.columns))
	for i := range placeholders {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
	}
	stmt, err := dst.PrepareContext(ctx, `INSERT INTO `+quote(t.name)+` (`+columns(t)+`) VALUES (`+strings.Join(placeholders, ",")+`)`)
	if err != nil {
		return 0, nil, Error("target_schema_failed")
	}
	defer stmt.Close()
	h := sha256.New()
	var n int64
	for rows.Next() {
		v, err := scanRow(rows, t)
		if err != nil {
			return 0, nil, err
		}
		if err = verifyEncrypted(t, v, key); err != nil {
			return 0, nil, Error("source_decryption_failed")
		}
		hashRow(h, v)
		if _, err = stmt.ExecContext(ctx, v...); err != nil {
			return 0, nil, Error("target_write_failed")
		}
		n++
	}
	if rows.Err() != nil {
		return 0, nil, Error("source_read_failed")
	}
	if t.name == "turns" {
		if _, err := dst.ExecContext(ctx, `SET CONSTRAINTS turns_parent_turn_id_fkey IMMEDIATE; ALTER TABLE turns ALTER CONSTRAINT turns_parent_turn_id_fkey NOT DEFERRABLE`); err != nil {
			return 0, nil, Error("source_integrity_failed")
		}
	}
	return n, h.Sum(nil), nil
}
func digestTable(ctx context.Context, tx *sql.Tx, t tableSpec) (int64, []byte, error) {
	rows, err := tx.QueryContext(ctx, selectSQL(t))
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	h := sha256.New()
	var n int64
	for rows.Next() {
		v, err := scanRow(rows, t)
		if err != nil {
			return 0, nil, err
		}
		hashRow(h, v)
		n++
	}
	return n, h.Sum(nil), rows.Err()
}
func restoreSequences(ctx context.Context, src, dst *sql.Tx) error {
	for _, item := range []struct{ table, col, seq string }{{"content_policy_rules", "id", "content_policy_rules_id_seq"}, {"integrity_events", "sequence", "integrity_events_sequence_seq"}, {"audit_gaps", "id", "audit_gaps_id_seq"}} {
		var max, high int64
		if err := src.QueryRowContext(ctx, `SELECT COALESCE(MAX(`+quote(item.col)+`),0) FROM `+quote(item.table)).Scan(&max); err != nil {
			return Error("source_sequence_failed")
		}
		var sequenceRows int
		err := src.QueryRowContext(ctx, `SELECT count(*),COALESCE(MAX(seq),0) FROM sqlite_sequence WHERE name=?`, item.table).Scan(&sequenceRows, &high)
		if err != nil || sequenceRows > 1 {
			return Error("source_sequence_failed")
		}
		if high < 0 || max < 0 {
			return Error("source_sequence_failed")
		}
		if max > high {
			high = max
		}
		if high == math.MaxInt64 {
			return Error("source_sequence_exhausted")
		}
		if _, err = dst.ExecContext(ctx, `ALTER SEQUENCE `+quote(item.seq)+` RESTART WITH `+fmt.Sprint(high+1)); err != nil {
			return Error("target_sequence_failed")
		}
	}
	return nil
}
