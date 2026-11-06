package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

func testSignals(key []byte, apiKey []byte, lastAuditID string, lastNS int64) storage.SessionSignals {
	cost := 1.25
	userID, tokenID := int64(8), int64(1)
	return storage.SessionSignals{
		SessionKey: key, Kind: "agent", APIKeyFPR: apiKey, NewAPIUserID: &userID, NewAPITokenID: &tokenID,
		Client: "codex", MainSessionID: "agt_example", MainModel: "model-example",
		FirstNS: lastNS - int64(time.Minute), LastNS: lastNS, LastAuditID: lastAuditID,
		Requests: 3, MainRequests: 2, SubRequests: 1, Subagents: 1, MaxDepth: 1, UserTurns: 2,
		ActiveNS: int64(time.Minute), InputTokens: 1000, OutputTokens: 100, CacheReadTokens: 900, CostUSD: &cost,
		ToolCalls: 5, ToolFailures: 2, MaxFailureStreak: 2, Loops: 1, MaxLoopLength: 3,
		Verified: "no", Corrections: 1, DangerCounts: `{"force_push":1}`, SecretCounts: "{}",
		Eligible: true, SignalVersion: 1, ComputedAtNS: lastNS + 1,
	}
}

func TestSessionAnalysisStorageRoundTrip(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	ctx := context.Background()
	day := seedSharedWorld(t, store)
	// A locally rejected request in root A must never reach the batch.
	seedInsights(t, store, insightsSeed{id: "a-rejected", at: day.Add(5 * time.Second), key: keyA, root: rootA, node: node1})
	if _, err := store.writerConn.ExecContext(ctx, `UPDATE audit_records SET forward_status = 'rejected', blocked_by = 'content_policy', block_code = 'content_policy_blocked', parse_status = 'skipped', status_code = 400 WHERE audit_id = 'a-rejected'`); err != nil {
		t.Fatal(err)
	}

	since, quiet := day.Add(-time.Hour).UnixNano(), day.Add(time.Hour).UnixNano()
	candidates, err := store.ListSessionCandidates(ctx, since, quiet, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	roots := map[string]storage.SessionCandidate{}
	for _, candidate := range candidates {
		roots[string(candidate.SessionKey)] = candidate
	}
	if _, ok := roots[string(rootA)]; !ok {
		t.Fatalf("root A not a candidate: %d candidates", len(candidates))
	}
	// Still-active roots are not due yet.
	if early, err := store.ListSessionCandidates(ctx, since, day.UnixNano(), 1, 10); err != nil || len(early) != 0 {
		t.Fatalf("active roots listed: %d, %v", len(early), err)
	}

	rows, truncated, err := store.LoadSessionAudits(ctx, rootA)
	if err != nil || truncated {
		t.Fatalf("load: %v truncated=%v", err, truncated)
	}
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.AuditID)
	}
	if len(rows) != 5 || ids[0] != "a1" || ids[1] != "a2" || ids[2] != "b1" || ids[4] != "c2" {
		t.Fatalf("rows = %v", ids)
	}
	if rows[0].NewAPITokenID == nil || *rows[0].NewAPITokenID != 1 || !rows[0].TurnStart || rows[2].AgentRole != "subagent" || rows[4].AgentRole != "compaction" {
		t.Fatalf("row projection: %+v", rows[0])
	}

	lastNS := rows[len(rows)-1].StartedAtNS
	signals := testSignals(rootA, keyA, "c2", lastNS)
	fprs := []storage.SessionTextFPR{
		{Source: storage.TextSourceUser, FPR: fill(0x51), APIKeyFPR: keyA, SeenAtNS: lastNS},
		{Source: storage.TextSourceInjectedRules, FPR: fill(0x52), APIKeyFPR: keyA, SeenAtNS: 1},
	}
	if err := store.SaveSessionSignals(ctx, signals, fprs); err != nil {
		t.Fatal(err)
	}
	// Saving twice replaces, never duplicates.
	if err := store.SaveSessionSignals(ctx, signals, fprs); err != nil {
		t.Fatal(err)
	}
	if again, err := store.ListSessionCandidates(ctx, since, quiet, 1, 10); err != nil {
		t.Fatal(err)
	} else {
		for _, candidate := range again {
			if bytes.Equal(candidate.SessionKey, rootA) {
				t.Fatal("analysed root listed again")
			}
		}
	}
	if stale, err := store.ListSessionCandidates(ctx, since, quiet, 2, 10); err != nil || len(stale) == 0 {
		t.Fatalf("older signal version not recomputed: %d %v", len(stale), err)
	}

	window := storage.SessionSignalFilter{FromNS: day.Add(-time.Hour).UnixNano(), ToNS: day.Add(time.Hour).UnixNano()}
	page, err := store.ListSessionSignals(ctx, window, storage.SessionSignalCursor{}, 10)
	if err != nil || len(page.Rows) != 1 {
		t.Fatalf("admin list = %d, %v", len(page.Rows), err)
	}
	got := page.Rows[0]
	if got.Loops != 1 || got.Verified != "no" || got.CostUSD == nil || *got.CostUSD != 1.25 || got.DangerCounts != `{"force_push":1}` {
		t.Fatalf("round trip: %+v", got)
	}
	owner := window
	owner.Scope = &storage.AuditScope{Fingerprint: keyA}
	if page, err := store.ListSessionSignals(ctx, owner, storage.SessionSignalCursor{}, 10); err != nil || len(page.Rows) != 1 {
		t.Fatalf("owner list = %d, %v", len(page.Rows), err)
	}
	stranger := window
	stranger.Scope = &storage.AuditScope{Fingerprint: keyB}
	if page, err := store.ListSessionSignals(ctx, stranger, storage.SessionSignalCursor{}, 10); err != nil || len(page.Rows) != 0 {
		t.Fatalf("stranger list = %d, %v", len(page.Rows), err)
	}
	tokenID := int64(1)
	byToken := window
	byToken.Scope = &storage.AuditScope{Fingerprint: keyB, TokenID: &tokenID}
	if page, err := store.ListSessionSignals(ctx, byToken, storage.SessionSignalCursor{}, 10); err != nil || len(page.Rows) != 1 {
		t.Fatalf("token-scoped list = %d, %v", len(page.Rows), err)
	}
	flagged := window
	flagged.Flags = []string{"loop", "unverified", "danger"}
	if page, err := store.ListSessionSignals(ctx, flagged, storage.SessionSignalCursor{}, 10); err != nil || len(page.Rows) != 1 {
		t.Fatalf("flag filter = %d, %v", len(page.Rows), err)
	}
	flagged.Flags = []string{"secret"}
	if page, err := store.ListSessionSignals(ctx, flagged, storage.SessionSignalCursor{}, 10); err != nil || len(page.Rows) != 0 {
		t.Fatalf("secret filter = %d, %v", len(page.Rows), err)
	}
	flagged.Flags = []string{"nonsense"}
	if _, err := store.ListSessionSignals(ctx, flagged, storage.SessionSignalCursor{}, 10); err == nil {
		t.Fatal("unknown flag accepted")
	}

	totals, err := store.SessionSignalTotals(ctx, window)
	if err != nil {
		t.Fatal(err)
	}
	if totals.Sessions != 1 || totals.LoopSessions != 1 || totals.Unverified != 1 || totals.WithWrites != 1 ||
		totals.DangerSessions != 1 || totals.SecretSessions != 0 || totals.CostUSD != 1.25 || totals.BilledSessions != 1 {
		t.Fatalf("totals = %+v", totals)
	}

	if err := store.RecordSessionAnalysisRun(ctx, storage.SessionAnalysisRun{StartedAtNS: 10, FinishedAtNS: 20, Trigger: "manual", Candidates: 2, Analyzed: 1}); err != nil {
		t.Fatal(err)
	}
	run, err := store.LatestSessionAnalysisRun(ctx)
	if err != nil || run.Trigger != "manual" || run.Analyzed != 1 || run.SkipReasons != "{}" {
		t.Fatalf("run = %+v, %v", run, err)
	}

	// Retention removed the session's newest audit: the next prune drops the
	// row; fingerprints older than the cutoff go too.
	removed, err := store.PruneSessionAnalysis(ctx, 2)
	if err != nil || removed != 0 {
		t.Fatalf("prune with live audit = %d, %v", removed, err)
	}
	var fprCount int
	if err := store.readerDB.QueryRow(`SELECT count(*) FROM session_text_fprs`).Scan(&fprCount); err != nil || fprCount != 1 {
		t.Fatalf("fingerprints after cutoff = %d, %v", fprCount, err)
	}
	if _, err := store.writerConn.ExecContext(ctx, `UPDATE session_signals SET last_audit_id = 'expired-audit'`); err != nil {
		t.Fatal(err)
	}
	if removed, err := store.PruneSessionAnalysis(ctx, 2); err != nil || removed != 1 {
		t.Fatalf("prune = %d, %v", removed, err)
	}
}

func TestSessionAnalysisRunsWithoutRunsReturnNoRows(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	if _, err := store.LatestSessionAnalysisRun(context.Background()); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("err = %v", err)
	}
}

func TestSessionSignalsStayOutsideTheEvidenceChain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x74}, security.KeySize)
	path := newTestDSN(t)
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnableIntegrity(ctx, key); err != nil {
		t.Fatal(err)
	}
	const auditID = "audit-session-chain"
	user := graphItem("user_message", map[string]any{"role": "user", "content": "question"})
	assistant := graphItem("assistant_message", map[string]any{"role": "assistant", "content": "answer"})
	saveIntegrityChainTurn(t, store, graphTestCipher(t), auditID, "", "response-session", 100,
		[]graphTestItem{user}, []graphTestItem{assistant})
	before := readEvidenceDigests(t, store, auditID)
	signals := testSignals(fill(0x61), scopeFingerprint(0x07), auditID, 100)
	if err := store.SaveSessionSignals(ctx, signals, []storage.SessionTextFPR{{Source: storage.TextSourceUser, FPR: fill(0x62), SeenAtNS: 100}}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordSessionAnalysisRun(ctx, storage.SessionAnalysisRun{StartedAtNS: 1, FinishedAtNS: 2, Trigger: "schedule"}); err != nil {
		t.Fatal(err)
	}
	after := readEvidenceDigests(t, store, auditID)
	if !bytes.Equal(before.capture, after.capture) || !bytes.Equal(before.parsed, after.parsed) || !bytes.Equal(before.semantic, after.semantic) {
		t.Fatal("session signals changed an evidence digest")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.EnableIntegrity(ctx, key); err != nil {
		t.Fatalf("integrity chain rejected after session analysis writes: %v", err)
	}
	if err := reopened.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatalf("payload verification failed: %v", err)
	}
}

func TestDerivedMigrationsApplyOnceAndToleratePriorVersions(t *testing.T) {
	t.Parallel()
	store, path := openTestStore(t)
	var versions []int64
	rows, err := store.readerDB.Query(`SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var version int64
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
	// Reopening is idempotent.
	reopened, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	reopened.Close()
}

func TestSessionPacksStorageAndViewLog(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	ctx := context.Background()
	day := seedSharedWorld(t, store)
	tokenID := int64(1)
	pack := storage.SessionPack{
		SessionKey: rootA, Kind: storage.PackKindSession, APIKeyFPR: keyA, NewAPITokenID: &tokenID, Client: "codex",
		PackHash: strings.Repeat("ab", 32), PackEnc: []byte{1, 2, 3}, RefMap: `{"U1":"a1"}`, TokenEstimate: 120,
		FirstNS: day.UnixNano(), LastNS: day.UnixNano(), LastAuditID: "a2", BuiltAtNS: 5, Members: 1,
	}
	if err := store.SaveSessionPack(ctx, pack, nil); err != nil {
		t.Fatal(err)
	}
	digestKey := fill(0x71)
	digest := pack
	digest.SessionKey, digest.Kind, digest.LastAuditID, digest.Members = digestKey, storage.PackKindChatDigest, "expired-audit", 2
	member1, member2 := fill(0x72), fill(0x73)
	if err := store.SaveSessionPack(ctx, digest, [][]byte{member1, member2}); err != nil {
		t.Fatal(err)
	}
	// A rebuilt digest replaces its members.
	if err := store.SaveSessionPack(ctx, digest, [][]byte{member2}); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadSessionPack(ctx, rootA)
	if err != nil || loaded.Kind != storage.PackKindSession || loaded.RefMap != `{"U1":"a1"}` || *loaded.NewAPITokenID != 1 || !bytes.Equal(loaded.PackEnc, []byte{1, 2, 3}) {
		t.Fatalf("own pack = %+v, %v", loaded, err)
	}
	if viaMember, err := store.LoadSessionPack(ctx, member2); err != nil || !bytes.Equal(viaMember.SessionKey, digestKey) {
		t.Fatalf("member lookup = %v", err)
	}
	if _, err := store.LoadSessionPack(ctx, member1); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("dropped member still resolves: %v", err)
	}
	if err := store.RecordAnalysisView(ctx, storage.AnalysisView{AtNS: 9, ViewerRole: "admin", Resource: "pack", SessionKey: rootA}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAnalysisView(ctx, storage.AnalysisView{AtNS: 9, ViewerRole: "root", Resource: "pack", SessionKey: rootA}); err == nil {
		t.Fatal("invalid viewer role accepted")
	}
	// An ineligible recomputation drops the session pack; the digest of a
	// vanished audit goes with the next prune.
	signals := testSignals(rootA, keyA, "a2", day.UnixNano())
	signals.Eligible, signals.SkipReason = false, "below_threshold"
	if err := store.SaveSessionSignals(ctx, signals, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSessionPack(ctx, rootA); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("stale pack kept: %v", err)
	}
	if _, err := store.PruneSessionAnalysis(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSessionPack(ctx, member2); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("digest of a missing audit survived the prune: %v", err)
	}
	var views int
	if err := store.readerDB.QueryRow(`SELECT count(*) FROM analysis_view_log`).Scan(&views); err != nil || views != 1 {
		t.Fatalf("views = %d, %v", views, err)
	}

	// Digest members: single-turn chats of one key and client in a day.
	chat := testSignals(fill(0x74), keyA, "a1", day.UnixNano())
	chat.Kind, chat.Client, chat.SkipReason, chat.Eligible = "chat", "", "single_turn_chat", false
	if err := store.SaveSessionSignals(ctx, chat, nil); err != nil {
		t.Fatal(err)
	}
	members, err := store.ListChatDigestMembers(ctx, keyA, "unknown", day.Add(-time.Hour).UnixNano(), day.Add(time.Hour).UnixNano(), 10)
	if err != nil || len(members) != 1 || !bytes.Equal(members[0].SessionKey, fill(0x74)) {
		t.Fatalf("members = %d, %v", len(members), err)
	}
	if others, err := store.ListChatDigestMembers(ctx, keyB, "unknown", day.Add(-time.Hour).UnixNano(), day.Add(time.Hour).UnixNano(), 10); err != nil || len(others) != 0 {
		t.Fatalf("foreign members = %d, %v", len(others), err)
	}
}

func TestSessionFacetsStorage(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	ctx := context.Background()
	day := seedSharedWorld(t, store)
	if err := store.SaveSessionSignals(ctx, testSignals(rootA, keyA, "a2", day.UnixNano()), nil); err != nil {
		t.Fatal(err)
	}
	pack := storage.SessionPack{
		SessionKey: rootA, Kind: storage.PackKindSession, APIKeyFPR: keyA, PackHash: strings.Repeat("ab", 32),
		PackEnc: []byte{1}, RefMap: "{}", FirstNS: day.UnixNano(), LastNS: day.UnixNano(), LastAuditID: "a2", BuiltAtNS: 1, Members: 1,
	}
	if err := store.SaveSessionPack(ctx, pack, nil); err != nil {
		t.Fatal(err)
	}
	settled := day.Add(time.Hour).UnixNano()
	candidates := func(model string) int {
		t.Helper()
		due, err := store.ListFacetCandidates(ctx, settled, "facet-v1", model, 10)
		if err != nil {
			t.Fatal(err)
		}
		return len(due)
	}
	if candidates("m") != 1 {
		t.Fatal("pack without facet not due")
	}
	if due, err := store.ListFacetCandidates(ctx, day.UnixNano(), "facet-v1", "m", 10); err != nil || len(due) != 0 {
		t.Fatalf("unsettled pack due: %d %v", len(due), err)
	}
	facet := storage.SessionFacet{
		SessionKey: rootA, Kind: storage.PackKindSession, APIKeyFPR: keyA, LastNS: day.UnixNano(), PackHash: pack.PackHash,
		PromptVersion: "facet-v1", Model: "m", Status: "failed", CreatedAtNS: 5,
	}
	if err := store.SaveSessionFacet(ctx, facet, nil); err != nil {
		t.Fatal(err)
	}
	if candidates("m") != 1 {
		t.Fatal("failed facet not retried")
	}
	if err := store.SaveSessionFacet(ctx, facet, nil); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadSessionFacet(ctx, rootA)
	if err != nil || loaded.Attempts != 2 {
		t.Fatalf("attempts = %d, %v", loaded.Attempts, err)
	}
	facet.Status, facet.TaskType, facet.Outcome, facet.Friction, facet.TextEnc = "ok", "refactor", "achieved", `["tool_failed"]`, []byte{9, 9}
	if err := store.SaveSessionFacet(ctx, facet, []storage.SessionTextFPR{{Source: storage.TextSourceFacetInstruction, FPR: fill(0x81), SeenAtNS: 1}}); err != nil {
		t.Fatal(err)
	}
	if candidates("m") != 0 || candidates("other-model") != 1 {
		t.Fatal("facet cache key ignored")
	}
	loaded, err = store.LoadSessionFacet(ctx, rootA)
	if err != nil || loaded.Status != "ok" || loaded.Attempts != 3 || loaded.Friction != `["tool_failed"]` || loaded.Items != "[]" || !bytes.Equal(loaded.TextEnc, []byte{9, 9}) {
		t.Fatalf("facet = %+v, %v", loaded, err)
	}
	page, err := store.ListSessionSignals(ctx, storage.SessionSignalFilter{FromNS: day.Add(-time.Hour).UnixNano(), ToNS: settled}, storage.SessionSignalCursor{}, 10)
	if err != nil || len(page.Rows) != 1 || page.Rows[0].FacetStatus != "ok" || page.Rows[0].FacetTaskType != "refactor" || page.Rows[0].FacetOutcome != "achieved" {
		t.Fatalf("list facet enums = %+v, %v", page.Rows, err)
	}
	// A rebuilt pack with new text is due again.
	pack.PackHash = strings.Repeat("cd", 32)
	if err := store.SaveSessionPack(ctx, pack, nil); err != nil {
		t.Fatal(err)
	}
	if candidates("m") != 1 {
		t.Fatal("changed pack not due")
	}
	if err := store.SaveFacetCalibration(ctx, storage.FacetCalibration{CreatedAtNS: 1, PromptVersion: "facet-v1", Model: "m", Samples: 30, Agreement: `{"agreement":{"outcome":0.5}}`}); err != nil {
		t.Fatal(err)
	}
	if calibration, err := store.LatestFacetCalibration(ctx, "facet-v1", "m"); err != nil || calibration.Samples != 30 {
		t.Fatalf("calibration = %+v, %v", calibration, err)
	}
	if _, err := store.LatestFacetCalibration(ctx, "facet-v1", "other"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("calibration of another model: %v", err)
	}
	// Deleting the pack removes its facet.
	if _, err := store.writerConn.ExecContext(ctx, `DELETE FROM session_packs`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSessionFacet(ctx, rootA); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("facet survived its pack: %v", err)
	}
}

func TestSessionReportsStorage(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	ctx := context.Background()
	day := seedSharedWorld(t, store)
	at := day.UnixNano()
	for index, key := range [][]byte{fill(0x91), fill(0x92), fill(0x93)} {
		signals := testSignals(key, keyA, "a2", at+int64(index))
		if index == 2 {
			signals.APIKeyFPR = keyB
		}
		repeated := fill(0xa1)
		fprs := []storage.SessionTextFPR{{Source: storage.TextSourceUser, FPR: repeated, APIKeyFPR: signals.APIKeyFPR, SeenAtNS: at + int64(index)}}
		if index == 1 {
			fprs = append(fprs, storage.SessionTextFPR{Source: storage.TextSourceInjectedRules, FPR: repeated, APIKeyFPR: keyA, SeenAtNS: at + 10})
		}
		if err := store.SaveSessionSignals(ctx, signals, fprs); err != nil {
			t.Fatal(err)
		}
	}
	keys, err := store.ActiveAnalysisKeys(ctx, at-1, at+100)
	if err != nil || len(keys) != 2 {
		t.Fatalf("active keys = %d, %v", len(keys), err)
	}
	all, err := store.RepeatedFingerprints(ctx, at-1, nil, 10)
	if err != nil || len(all) != 1 || all[0].Sessions != 3 || all[0].Kind != "instruction" || len(all[0].SessionKeys) != 3 || !all[0].Adopted {
		t.Fatalf("repeated (all) = %+v, %v", all, err)
	}
	mine, err := store.RepeatedFingerprints(ctx, at-1, keyA, 10)
	if err != nil || len(mine) != 1 || mine[0].Sessions != 2 {
		t.Fatalf("repeated (key A) = %+v, %v", mine, err)
	}
	if theirs, err := store.RepeatedFingerprints(ctx, at-1, keyB, 10); err != nil || len(theirs) != 0 {
		t.Fatalf("repeated (key B) = %+v, %v", theirs, err)
	}
	suggestion := storage.Suggestion{Scope: storage.ScopeAll, ScopeKey: storage.AllScopeKey, Kind: "instruction", FPR: fill(0xa1),
		Support: 3, FirstSeenNS: at, LastSeenNS: at + 2, Status: "open", TextEnc: []byte{7}, Evidence: `["a2"]`, UpdatedAtNS: 1}
	if err := store.UpsertSuggestion(ctx, suggestion); err != nil {
		t.Fatal(err)
	}
	listed, err := store.ListSuggestions(ctx, storage.ScopeAll, storage.AllScopeKey, nil, 10)
	if err != nil || len(listed) != 1 {
		t.Fatalf("suggestions = %+v, %v", listed, err)
	}
	if err := store.DismissSuggestion(ctx, listed[0].ID, storage.ScopePerson, 2); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("dismiss in the wrong scope: %v", err)
	}
	if err := store.DismissSuggestion(ctx, listed[0].ID, storage.ScopeAll, 2); err != nil {
		t.Fatal(err)
	}
	suggestion.Support = 4
	if err := store.UpsertSuggestion(ctx, suggestion); err != nil {
		t.Fatal(err)
	}
	listed, _ = store.ListSuggestions(ctx, storage.ScopeAll, storage.AllScopeKey, nil, 10)
	if listed[0].Status != "dismissed" || listed[0].Support != 4 {
		t.Fatalf("refreshed suggestion = %+v", listed[0])
	}
	personal := suggestion
	personal.Scope, personal.ScopeKey, personal.Status = storage.ScopePerson, keyA, "adopted_detected"
	tokenID := int64(1)
	personal.NewAPITokenID = &tokenID
	if err := store.UpsertSuggestion(ctx, personal); err != nil {
		t.Fatal(err)
	}
	personal.Status = "open"
	if err := store.UpsertSuggestion(ctx, personal); err != nil {
		t.Fatal(err)
	}
	if mineListed, err := store.ListSuggestions(ctx, storage.ScopePerson, keyB, &tokenID, 10); err != nil || len(mineListed) != 1 || mineListed[0].Status != "adopted_detected" {
		t.Fatalf("personal by token = %+v, %v", mineListed, err)
	}

	stats := storage.PeriodStats{WeekStartNS: 100, Scope: storage.ScopePerson, ScopeKey: keyA, NewAPITokenID: &tokenID, Stats: `{"totals":{}}`,
		NarrativeEnc: []byte{1, 2}, NarrativeSource: "template", InputHash: "h", ComputedAtNS: 5}
	if err := store.SavePeriodStats(ctx, stats); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadPeriodStats(ctx, 100, storage.ScopePerson, keyA, nil)
	if err != nil || loaded.InputHash != "h" || loaded.NarrativeSource != "template" || !bytes.Equal(loaded.NarrativeEnc, []byte{1, 2}) {
		t.Fatalf("stats = %+v, %v", loaded, err)
	}
	if _, err := store.LoadPeriodStats(ctx, 100, storage.ScopePerson, keyB, &tokenID); err != nil {
		t.Fatalf("token fallback: %v", err)
	}
	if _, err := store.LoadPeriodStats(ctx, 100, storage.ScopeAll, storage.AllScopeKey, nil); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing scope: %v", err)
	}
	costly, err := store.TopCostSessions(ctx, storage.SessionSignalFilter{FromNS: at - 1, ToNS: at + 100, Flags: []string{"loop"}}, 2)
	if err != nil || len(costly) != 2 {
		t.Fatalf("costly = %d, %v", len(costly), err)
	}
	if enums, err := store.FacetEnums(ctx, at-1, at+100, keyA); err != nil || len(enums) != 0 {
		t.Fatalf("enums = %+v, %v", enums, err)
	}
}
