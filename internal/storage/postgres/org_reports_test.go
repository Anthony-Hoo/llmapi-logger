package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"testing"

	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// These tests need a real PostgreSQL (TEST_DATABASE_URL) and skip otherwise.

func finishedTestAudit(t *testing.T, store *Store, auditID string, startedAtNS int64) {
	t.Helper()
	ctx := context.Background()
	record := testAudit(auditID)
	record.StartedAtNS = startedAtNS
	if err := store.BeginAudit(ctx, record); err != nil {
		t.Fatal(err)
	}
	status := 200
	if err := store.FinishAudit(ctx, AuditFinish{
		AuditID: auditID, EndedAtNS: startedAtNS + 1, StatusCode: &status,
		ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParsePending,
	}); err != nil {
		t.Fatal(err)
	}
}

func identityTestRow(auditID string) storage.ProjectIdentityRow {
	return storage.ProjectIdentityRow{
		AuditID: auditID, Version: 1, ExtractedAtNS: 10, Source: "codex_turn_metadata", BodyScanned: true,
		IdentityFPR: bytes.Repeat([]byte{1}, 32), RemoteFPR: bytes.Repeat([]byte{2}, 32),
		RootFPR: bytes.Repeat([]byte{3}, 32), CwdFPR: bytes.Repeat([]byte{4}, 32), IdentityEnc: []byte{9, 9, 9},
	}
}

func TestMigrationTwoAppliesOnceAndRuntimeOnly(t *testing.T) {
	store, dsn := openTestStore(t)
	var versions []int
	rows, err := store.readerDB.Query(`SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			t.Fatal(err)
		}
		versions = append(versions, version)
	}
	rows.Close()
	if len(versions) != 3 || versions[0] != 1 || versions[1] != 2 || versions[2] != 3 {
		t.Fatalf("versions = %v", versions)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("reopen at version 3: %v", err)
	}
	reopened.Close()

	// The import baseline still builds version 1 only.
	db, err := sql.Open("pgx", newTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := AcquireWriterLock(context.Background(), conn); err != nil {
		t.Fatal(err)
	}
	tx, err := conn.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := InitializeImportSchema(context.Background(), tx); err != nil {
		t.Fatal(err)
	}
	var exists bool
	if err := tx.QueryRow(`SELECT to_regclass('audit_project_identity') IS NOT NULL`).Scan(&exists); err != nil || exists {
		t.Fatalf("import baseline created org tables: %v %v", exists, err)
	}
}

func TestProjectIdentityRoundTripAndCascade(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	finishedTestAudit(t, store, "audit-pi", 100)
	if err := store.SaveProjectIdentity(ctx, identityTestRow("audit-pi")); err != nil {
		t.Fatal(err)
	}
	updated := identityTestRow("audit-pi")
	updated.Version, updated.Source, updated.BodyScanned = 2, "none", false
	updated.IdentityFPR, updated.RemoteFPR, updated.RootFPR, updated.CwdFPR, updated.IdentityEnc = nil, nil, nil, nil, nil
	if err := store.SaveProjectIdentity(ctx, updated); err != nil {
		t.Fatal(err)
	}
	row, err := store.LoadProjectIdentity(ctx, "audit-pi")
	if err != nil || row.Version != 2 || row.Source != "none" || row.IdentityEnc != nil {
		t.Fatalf("row = %+v err = %v", row, err)
	}
	if err := store.SaveProjectIdentity(ctx, identityTestRow("missing")); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unknown audit = %v", err)
	}
	if _, err := store.writerConn.ExecContext(ctx, `DELETE FROM audit_records WHERE audit_id = 'audit-pi'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadProjectIdentity(ctx, "audit-pi"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("identity survived its audit: %v", err)
	}
}

func TestDerivedOrgTablesStayOutsideTheEvidenceChain(t *testing.T) {
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x73}, security.KeySize)
	dsn := newTestDSN(t)
	store, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnableIntegrity(ctx, key); err != nil {
		t.Fatal(err)
	}
	finishedTestAudit(t, store, "audit-org-chain", 100)
	if err := store.SaveProjectIdentity(ctx, identityTestRow("audit-org-chain")); err != nil {
		t.Fatal(err)
	}
	var events int
	if err := store.readerDB.QueryRow(`SELECT COUNT(*) FROM integrity_events`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	// Rewriting or deleting derived rows must leave the chain valid.
	if _, err := store.writerConn.ExecContext(ctx, `UPDATE audit_project_identity SET source = 'cwd', identity_fpr = $1`, bytes.Repeat([]byte{7}, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.writerConn.ExecContext(ctx, `DELETE FROM audit_project_identity`); err != nil {
		t.Fatal(err)
	}
	var after int
	if err := store.readerDB.QueryRow(`SELECT COUNT(*) FROM integrity_events`).Scan(&after); err != nil || after != events {
		t.Fatalf("derived writes added integrity events: %d -> %d (%v)", events, after, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.EnableIntegrity(ctx, key); err != nil {
		t.Fatalf("org tables must not participate in the integrity chain: %v", err)
	}
}

func TestProjectIdentityBackfillCandidatesNewestFirst(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	for index, id := range []string{"c-old", "c-mid", "c-new"} {
		finishedTestAudit(t, store, id, int64(100*(index+1)))
		if _, err := store.writerConn.ExecContext(ctx, `INSERT INTO audit_analysis (audit_id, analysis_version, analyzed_at_ns, protocol, started_at_ns) VALUES ($1, 1, 1, 'openai', $2)`, id, int64(100*(index+1))); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.SaveProjectIdentity(ctx, identityTestRow("c-mid")); err != nil {
		t.Fatal(err)
	}
	candidates, err := store.ListProjectIdentityBackfillCandidates(ctx, 1, nil, 10)
	if err != nil || len(candidates) != 2 || candidates[0].AuditID != "c-new" || candidates[1].AuditID != "c-old" {
		t.Fatalf("candidates = %+v err = %v", candidates, err)
	}
	candidates, err = store.ListProjectIdentityBackfillCandidates(ctx, 2, &storage.ProjectBackfillCursor{StartedAtNS: 300, AuditID: "c-new"}, 10)
	if err != nil || len(candidates) != 2 || candidates[0].AuditID != "c-mid" {
		t.Fatalf("version upgrade candidates = %+v err = %v", candidates, err)
	}
}

func TestOrgCatalogCRUDAndConstraints(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	group, err := store.CreateProjectGroup(ctx, orgreport.Group{Name: "Platform", Enabled: true, CreatedAtNS: 1, UpdatedAtNS: 1})
	if err != nil || group.ID <= 0 {
		t.Fatalf("group = %+v err = %v", group, err)
	}
	if _, err := store.CreateProjectGroup(ctx, orgreport.Group{Name: "platform", CreatedAtNS: 1, UpdatedAtNS: 1}); !errors.Is(err, orgreport.ErrConflict) {
		t.Fatalf("duplicate group = %v", err)
	}
	project, err := store.CreateProject(ctx, orgreport.Project{Name: "Core", GroupID: &group.ID, Enabled: true,
		Rules: []orgreport.Rule{{Kind: orgreport.RuleRepoName, Pattern: "core"}}, CreatedAtNS: 1, UpdatedAtNS: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetGroupMember(ctx, orgreport.Member{UserID: 7, GroupID: group.ID, UpdatedAtNS: 2}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetPrincipalClass(ctx, orgreport.Principal{Kind: "token", ID: 70, Class: "service", UpdatedAtNS: 2}); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteProjectGroup(ctx, group.ID); !errors.Is(err, orgreport.ErrConflict) {
		t.Fatalf("restricted delete = %v", err)
	}
	catalog, err := store.LoadOrgCatalog(ctx)
	if err != nil || len(catalog.Groups) != 1 || len(catalog.Projects) != 1 || catalog.Projects[0].Rules[0].Pattern != "core" ||
		*catalog.Projects[0].GroupID != group.ID || len(catalog.Members) != 1 || len(catalog.Principals) != 1 {
		t.Fatalf("catalog = %+v err = %v", catalog, err)
	}
	project.Enabled = false
	if err := store.UpdateProject(ctx, project); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteProject(ctx, project.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteProject(ctx, project.ID); !errors.Is(err, orgreport.ErrNotFound) {
		t.Fatalf("delete twice = %v", err)
	}
	if err := store.DeleteGroupMember(ctx, 7); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteProjectGroup(ctx, group.ID); err != nil {
		t.Fatal(err)
	}
}

func TestWeeklySnapshotRoundTripSurvivesRetention(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	finishedTestAudit(t, store, "audit-snap", 100)
	snapshot := orgreport.WeeklySnapshot{
		Week: "2026-11-02", FrozenAtNS: 5, GeneratedAtNS: 5, ProjectNames: map[int64]string{10: "Demo"},
		Result: orgreport.WeekResult{
			Users: []orgreport.UserRow{{
				UserID: 7, GroupID: 1, ActiveNS: 600, OtherActiveNS: 5, Roots: 2, SingleRequestRoots: 1, Requests: 4,
				IdentifiedRequests: 3, BilledRequests: 4, Tokens: orgreport.Tokens{Uncached: 1, CacheRead: 2, CacheWrite: 3, Output: 4},
				CostUSD: 1.5, PeakConcurrency: 2, AvgConcurrency: 1.5, Daily: []int64{600, 0, 0, 0, 0, 0, 0},
				Flags:    []orgreport.Flag{{Code: orgreport.FlagConcurrency, Value: 2, Threshold: 1}},
				Projects: []orgreport.ProjectCell{{Project: 10, ActiveNS: 400, Roots: 1, Requests: 2}, {Project: orgreport.ProjectUnattributed, ActiveNS: 200, Roots: 1, Requests: 2}},
			}},
			Service: []orgreport.ServiceRow{{UserID: 9, TokenID: 90, ActiveNS: 50, Requests: 1}},
		},
	}
	if err := store.SaveWeeklySnapshot(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	// Retention deletes the audit; the snapshot has no foreign key to it.
	if _, err := store.writerConn.ExecContext(ctx, `DELETE FROM audit_records`); err != nil {
		t.Fatal(err)
	}
	loaded, ok, err := store.LoadWeeklySnapshot(ctx, "2026-11-02")
	if err != nil || !ok {
		t.Fatalf("load = %v %v", ok, err)
	}
	user := loaded.Result.Users[0]
	if user.ActiveNS != 600 || user.Tokens.CacheWrite != 3 || user.Flags[0].Code != orgreport.FlagConcurrency || len(user.Projects) != 2 ||
		user.Projects[0].Project != 10 || loaded.ProjectNames[10] != "Demo" || len(loaded.Result.Service) != 1 || loaded.Result.Service[0].TokenID != 90 {
		t.Fatalf("loaded = %+v", loaded)
	}
	// Regeneration replaces the whole week.
	snapshot.Result.Users = nil
	snapshot.GeneratedAtNS = 9
	if err := store.SaveWeeklySnapshot(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	loaded, _, _ = store.LoadWeeklySnapshot(ctx, "2026-11-02")
	if len(loaded.Result.Users) != 0 || loaded.GeneratedAtNS != 9 {
		t.Fatalf("regenerated = %+v", loaded)
	}
	if _, ok, err := store.LoadWeeklySnapshot(ctx, "2026-10-26"); ok || err != nil {
		t.Fatalf("missing week = %v %v", ok, err)
	}
}
