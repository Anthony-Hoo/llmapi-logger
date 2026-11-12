package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

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

// The freeze check separates audits still in the pipeline from parsed audits
// that never got an analysis row.
func TestCountOrgPendingAuditsSplitsUnanalysed(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	exec := func(query string, arguments ...any) {
		t.Helper()
		if _, err := store.writerConn.ExecContext(ctx, query, arguments...); err != nil {
			t.Fatal(err)
		}
	}
	for index, id := range []string{"p-parse", "p-unanalysed", "p-no-identity", "p-done", "p-failed"} {
		finishedTestAudit(t, store, id, int64(100+index))
	}
	finishedTestAudit(t, store, "p-outside", 500)
	exec(`UPDATE audit_records SET parse_status = 'ok' WHERE audit_id IN ('p-unanalysed', 'p-no-identity', 'p-done', 'p-outside')`)
	exec(`UPDATE audit_records SET parse_status = 'error' WHERE audit_id = 'p-failed'`)
	for _, id := range []string{"p-no-identity", "p-done"} {
		exec(`INSERT INTO audit_analysis (audit_id, analysis_version, analyzed_at_ns, protocol, started_at_ns) VALUES ($1, 1, 1, 'openai', 100)`, id)
	}
	if err := store.SaveProjectIdentity(ctx, identityTestRow("p-done")); err != nil {
		t.Fatal(err)
	}
	counts, err := store.CountOrgPendingAudits(ctx, 100, 200, 1)
	if err != nil || counts.Pending != 2 || counts.Unanalysed != 1 {
		t.Fatalf("counts = %+v err = %v", counts, err)
	}
	// A newer identity version makes the identified audit pending again.
	if counts, err = store.CountOrgPendingAudits(ctx, 100, 200, 2); err != nil || counts.Pending != 3 {
		t.Fatalf("counts at version 2 = %+v err = %v", counts, err)
	}
}

// Report requests carry their caller scope, so identity inheritance never
// crosses keys.
func TestLoadOrgRequestsCarryTheCallerKey(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	day := seedSharedWorld(t, store)
	requests, err := store.LoadOrgRequests(context.Background(), day.Add(-time.Hour).UnixNano(), day.Add(time.Hour).UnixNano())
	if err != nil || len(requests) == 0 {
		t.Fatalf("requests = %d err = %v", len(requests), err)
	}
	for _, request := range requests {
		want := hex.EncodeToString(keyA)
		if request.AuditID == "b1" || request.AuditID == "d1" {
			want = hex.EncodeToString(keyB)
		}
		if request.CallerKey != want {
			t.Fatalf("%s caller = %s, want %s", request.AuditID, request.CallerKey, want)
		}
	}
}

// One analysis session's attribution input is its own requests only: another
// key's requests under the same root, and rejected requests, stay out.
func TestLoadOrgSessionReadsOneKeysRequests(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	ctx := context.Background()
	day := seedSharedWorld(t, store)
	seedInsights(t, store, insightsSeed{id: "a-rejected", at: day.Add(5 * time.Second), key: keyA, root: rootA, node: node1})
	if _, err := store.writerConn.ExecContext(ctx, `UPDATE audit_records SET forward_status = 'rejected', blocked_by = 'content_policy', block_code = 'content_policy_blocked', parse_status = 'skipped', status_code = 400 WHERE audit_id = 'a-rejected'`); err != nil {
		t.Fatal(err)
	}
	identity := identityTestRow("a1")
	identity.IdentityFPR = fill(0x71)
	empty := identityTestRow("a2")
	empty.Source, empty.IdentityFPR, empty.RemoteFPR, empty.RootFPR, empty.CwdFPR, empty.IdentityEnc = "none", nil, nil, nil, nil, nil
	foreign := identityTestRow("b1")
	foreign.IdentityFPR = fill(0x72)
	rejected := identityTestRow("a-rejected")
	rejected.IdentityFPR = fill(0x73)
	for _, row := range []storage.ProjectIdentityRow{identity, empty, foreign, rejected} {
		if err := store.SaveProjectIdentity(ctx, row); err != nil {
			t.Fatal(err)
		}
	}

	own, err := store.LoadOrgSession(ctx, rootA, keyA)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(own.Requests))
	for _, request := range own.Requests {
		ids = append(ids, request.AuditID)
	}
	if strings.Join(ids, ",") != "a1,a2,c1,c2" || own.Extracted != 2 {
		t.Fatalf("requests = %v, extracted = %d", ids, own.Extracted)
	}
	first := own.Requests[0]
	if first.IdentityKey != hex.EncodeToString(fill(0x71)) || first.TokenID != 1 || first.RootKey != hex.EncodeToString(rootA) ||
		first.NodeKey != hex.EncodeToString(node1) || own.Requests[1].IdentityKey != "" {
		t.Fatalf("request projection = %+v / %+v", first, own.Requests[1])
	}
	if len(own.Identities) != 1 || own.Identities[0].Key != first.IdentityKey || own.Identities[0].AuditID != "a1" || !bytes.Equal(own.Identities[0].Enc, identity.IdentityEnc) {
		t.Fatalf("identities = %+v", own.Identities)
	}

	other, err := store.LoadOrgSession(ctx, rootA, keyB)
	if err != nil || len(other.Requests) != 1 || other.Requests[0].AuditID != "b1" || len(other.Identities) != 1 || other.Identities[0].Key != hex.EncodeToString(fill(0x72)) {
		t.Fatalf("key B = %+v, %v", other, err)
	}
	if keyless, err := store.LoadOrgSession(ctx, rootA, nil); err != nil || len(keyless.Requests) != 0 || len(keyless.Identities) != 0 {
		t.Fatalf("no key = %+v, %v", keyless, err)
	}
	if _, err := store.LoadOrgSession(ctx, []byte{1}, keyA); err == nil {
		t.Fatal("short root accepted")
	}
}
