package migrate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/postgres"
	"llmapi-logger/internal/storage/sqlite"
)

func pgTarget(t *testing.T) (string, *sql.DB) {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL required for real PostgreSQL integration")
	}
	db, e := sql.Open("pgx", dsn)
	if e != nil {
		t.Fatal(e)
	}
	schema := fmt.Sprintf("import_%d", time.Now().UnixNano())
	if _, e = db.Exec(`CREATE SCHEMA ` + quote(schema)); e != nil {
		t.Fatal("create test schema:", e)
	}
	t.Cleanup(func() { db.Exec(`DROP SCHEMA ` + quote(schema) + ` CASCADE`); db.Close() })
	u, e := url.Parse(dsn)
	if e != nil {
		t.Fatal(e)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	scoped, e := sql.Open("pgx", u.String())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { scoped.Close() })
	return u.String(), scoped
}
func sourceFixture(t *testing.T) (string, []byte) {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "source.db")
	key := bytes.Repeat([]byte{0x51}, 32)
	cipher, _ := security.NewAESGCM(key)
	store, e := sqlite.Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	if e = store.EnableIntegrity(ctx, key); e != nil {
		t.Fatal(e)
	}
	for _, id := range []string{"audit-retained", "audit-deleted"} {
		uri, _ := cipher.Encrypt([]byte(id+"\x00request_uri"), []byte("/v1/chat/completions"))
		if e = store.BeginAudit(ctx, sqlite.AuditRecord{AuditID: id, StartedAtNS: 1, RouteID: "example", Protocol: "openai", ParserName: "openai.chat_completions", Method: "POST", Path: "/v1/chat/completions", RequestURIEnc: uri, Mode: "available"}); e != nil {
			t.Fatal(e)
		}
		status := 200
		if e = store.FinishAudit(ctx, sqlite.AuditFinish{AuditID: id, EndedAtNS: 2, StatusCode: &status, ForwardStatus: sqlite.ForwardCompleted, CaptureStatus: sqlite.CaptureComplete, ParseStatus: sqlite.ParsePending}); e != nil {
			t.Fatal(e)
		}
		if id == "audit-deleted" {
			continue
		}
		if _, e = store.ClaimPendingParse(ctx, id); e != nil {
			t.Fatal(e)
		}
		message := map[string]any{"role": "user", "content": []any{
			map[string]any{"type": "text", "text": "synthetic migration evidence"},
			map[string]any{"type": "image_url", "image_url": map[string]any{"url": "data:image/png;base64,AQIDBA=="}},
			map[string]any{"type": "image_url", "image_url": map[string]any{"url": "https://example.com/synthetic.png"}},
		}}
		prepared, e := auditmodel.Prepare(auditmodel.Turn{AuditID: id, Protocol: "openai", ParserName: "openai.chat_completions", RequestLayout: auditmodel.LayoutOpenAIChatRequest, ResponseLayout: auditmodel.LayoutNone, RequestEnvelope: map[string]any{"model": "model-example"}, RequestItems: []auditmodel.Item{{Slot: auditmodel.SlotMessages, Kind: "user_message", Value: message}}, RequestOriginal: map[string]any{"model": "model-example", "messages": []any{message}}, CreatedAtNS: 3}, cipher)
		if e != nil {
			t.Fatal(e)
		}
		if e = store.SaveParsedAudit(ctx, sqlite.ParsedAudit{Result: sqlite.ParsedResult{AuditID: id, ParserName: "openai.chat_completions", ParserVersion: "2", Status: sqlite.ParseOK, ParsedAtNS: 4}, Turn: &prepared}); e != nil {
			t.Fatal(e)
		}
	}
	if e = store.Close(); e != nil {
		t.Fatal(e)
	}
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	for _, q := range []string{`PRAGMA foreign_keys=ON`, `DELETE FROM audit_records WHERE audit_id='audit-deleted'`, `INSERT INTO content_policy_rules(id,name,enabled,action,model_pattern,scan_scopes,keywords,created_at_ns,updated_at_ns) VALUES(800,'synthetic',0,'block','','[]','[]',1,1)`, `DELETE FROM content_policy_rules WHERE id=800`, `UPDATE sqlite_sequence SET seq=900 WHERE name='integrity_events'`} {
		if _, e = db.Exec(q); e != nil {
			t.Fatal(e)
		}
	}
	return path, key
}
func assertEmpty(t *testing.T, db *sql.DB) {
	t.Helper()
	var n int
	if e := db.QueryRow(`SELECT count(*) FROM information_schema.tables WHERE table_schema=current_schema()`).Scan(&n); e != nil || n != 0 {
		t.Fatalf("rollback schema count %d: %v", n, e)
	}
}
func TestImportAtomicGraphAndSequences(t *testing.T) {
	path, key := sourceFixture(t)
	dsn, db := pgTarget(t)
	before, _ := os.ReadFile(path)
	opts := Options{SourcePath: path, DatabaseURL: dsn, Key: key, ServiceStopped: true, DryRun: true}
	report, e := Run(context.Background(), opts)
	if e != nil {
		t.Fatal(e)
	}
	if len(report.Tables) != len(tables) {
		t.Fatal("missing table report")
	}
	assertEmpty(t, db)
	opts.DryRun = false
	if _, e = Run(context.Background(), opts); e != nil {
		t.Fatal(e)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("source changed")
	}
	var n int
	if e = db.QueryRow(`SELECT count(*) FROM integrity_events`).Scan(&n); e != nil || n != 3 {
		t.Fatalf("chain: %d %v", n, e)
	}
	for seq, want := range map[string]int64{"content_policy_rules_id_seq": 801, "integrity_events_sequence_seq": 901} {
		var id int64
		if e = db.QueryRow(`SELECT nextval('` + seq + `')`).Scan(&id); e != nil || id != want {
			t.Fatalf("sequence %s: %d %v", seq, id, e)
		}
	}
	if _, e = Run(context.Background(), opts); e != Error("target_not_empty") {
		t.Fatalf("repeat: %v", e)
	}
}
func TestImportRejectsCorruptionAndRollsBack(t *testing.T) {
	for _, mode := range []string{"key", "nul", "utf8", "reference", "schema", "chain", "sequence"} {
		t.Run(mode, func(t *testing.T) {
			path, key := sourceFixture(t)
			dsn, db := pgTarget(t)
			source, _ := sql.Open("sqlite", path)
			switch mode {
			case "key":
				key = bytes.Repeat([]byte{0x52}, 32)
			case "nul":
				source.Exec(`UPDATE audit_records SET route_id=?`, "invalid\x00text")
			case "utf8":
				source.Exec(`UPDATE audit_records SET route_id=?`, string([]byte{0xff}))
			case "reference":
				source.Exec(`UPDATE turns SET parent_turn_id='missing'`)
			case "schema":
				source.Exec(`DELETE FROM schema_migrations WHERE version=12`)
			case "chain":
				source.Exec(`UPDATE integrity_events SET event_mac=zeroblob(32) WHERE sequence=1`)
			case "sequence":
				source.Exec(`UPDATE sqlite_sequence SET seq=9223372036854775807 WHERE name='content_policy_rules'`)
			}
			source.Close()
			_, e := Run(context.Background(), Options{SourcePath: path, DatabaseURL: dsn, Key: key, ServiceStopped: true})
			expected := map[string]Error{"key": "source_decryption_failed", "nul": "invalid_source_text", "utf8": "invalid_source_text", "reference": "source_integrity_failed", "schema": "unsupported_source_schema", "chain": "evidence_integrity_failed", "sequence": "source_sequence_exhausted"}
			if e != expected[mode] {
				t.Fatalf("got %v want %v", e, expected[mode])
			}
			assertEmpty(t, db)
		})
	}
}
func TestImportRequiresStoppedService(t *testing.T) {
	_, e := Run(context.Background(), Options{})
	if e != Error("service_stop_confirmation_required") {
		t.Fatal(e)
	}
}
func TestImportReadsWAL(t *testing.T) {
	path, key := sourceFixture(t)
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if _, e = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; INSERT INTO audit_gaps(started_at_ns,ended_at_ns,reason,request_count,detail,created_at_ns) VALUES(1,2,'process_exit',1,'synthetic',2)`); e != nil {
		t.Fatal(e)
	}
	wal, e := os.ReadFile(path + "-wal")
	if e != nil || len(wal) == 0 {
		t.Fatal("fixture has no WAL")
	}
	dsn, target := pgTarget(t)
	if _, e = Run(context.Background(), Options{SourcePath: path, DatabaseURL: dsn, Key: key, ServiceStopped: true}); e != nil {
		t.Fatal(e)
	}
	var n int
	if e = target.QueryRow(`SELECT count(*) FROM audit_gaps`).Scan(&n); e != nil || n != 1 {
		t.Fatal("missed WAL row", e)
	}
	after, _ := os.ReadFile(path + "-wal")
	if !bytes.Equal(wal, after) {
		t.Fatal("WAL changed")
	}
}

func TestImportTargetRulesAndRollbackSequence(t *testing.T) {
	for _, mode := range []string{"seed", "custom", "sequence_rollback", "writer_lock", "unrelated_table"} {
		t.Run(mode, func(t *testing.T) {
			path, key := sourceFixture(t)
			dsn, db := pgTarget(t)
			ctx := context.Background()
			conn, e := db.Conn(ctx)
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			tx, e := conn.BeginTx(ctx, nil)
			if e != nil {
				t.Fatal(e)
			}
			if e = postgres.InitializeImportSchema(ctx, tx); e != nil {
				t.Fatal(e)
			}
			if e = tx.Commit(); e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "seed":
				_, e = db.Exec(`INSERT INTO user_agent_rules VALUES(1,'GPT models require Codex clients',1,'^gpt','^(codex-tui|Codex Desktop)',1,1)`)
			case "unrelated_table":
				_, e = db.Exec(`CREATE TABLE unrelated (id BIGINT)`)
			case "custom":
				_, e = db.Exec(`INSERT INTO user_agent_rules VALUES(2,'custom',1,'^model','^client',1,1)`)
			case "sequence_rollback":
				_, e = db.Exec(`ALTER SEQUENCE content_policy_rules_id_seq RESTART WITH 17`)
				src, _ := sql.Open("sqlite", path)
				src.Exec(`UPDATE integrity_events SET event_mac=zeroblob(32) WHERE sequence=1`)
				src.Close()
			case "writer_lock":
				e = postgres.AcquireWriterLock(ctx, conn)
				defer conn.ExecContext(ctx, `SELECT pg_advisory_unlock_all()`)
			}
			if e != nil {
				t.Fatal(e)
			}
			_, e = Run(ctx, Options{SourcePath: path, DatabaseURL: dsn, Key: key, ServiceStopped: true})
			if mode == "seed" {
				if e != nil {
					t.Fatal(e)
				}
				return
			}
			want := Error("target_not_empty")
			if mode == "sequence_rollback" {
				want = Error("evidence_integrity_failed")
			}
			if mode == "writer_lock" {
				want = Error("target_writer_locked")
			}
			if e != want {
				t.Fatalf("got %v want %v", e, want)
			}
			if mode == "sequence_rollback" {
				var id int64
				if e = db.QueryRow(`SELECT nextval('content_policy_rules_id_seq')`).Scan(&id); e != nil || id != 17 {
					t.Fatalf("sequence rollback got %d %v", id, e)
				}
				var n int
				if e = db.QueryRow(`SELECT count(*) FROM audit_records`).Scan(&n); e != nil || n != 0 {
					t.Fatal("partial import")
				}
			}
		})
	}
}

func TestTypedDigestDistinguishesNullEmptyAndValues(t *testing.T) {
	values := [][]any{{nil}, {[]byte{}}, {""}, {int64(0)}, {float64(0)}}
	seen := map[string]bool{}
	for _, row := range values {
		h := sha256.New()
		hashRow(h, row)
		sum := string(h.Sum(nil))
		if seen[sum] {
			t.Fatal("typed digest collision")
		}
		seen[sum] = true
	}
}
