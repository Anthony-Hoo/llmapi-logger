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
		SessionKey: key, AgentRootFPR: key, Kind: "agent", APIKeyFPR: apiKey, NewAPIUserID: &userID, NewAPITokenID: &tokenID,
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
	// Key B sent one step into key A's tree: one root, two analysis sessions.
	pairs := map[string]storage.SessionCandidate{}
	for _, candidate := range candidates {
		pairs[string(candidate.AgentRootFPR)+string(candidate.APIKeyFPR)] = candidate
	}
	if len(candidates) != 3 || pairs[string(rootA)+string(keyA)].Requests != 4 || pairs[string(rootA)+string(keyB)].Requests != 1 || pairs[string(rootB)+string(keyB)].Requests != 1 {
		t.Fatalf("candidates = %+v", candidates)
	}
	// Still-active roots are not due yet.
	if early, err := store.ListSessionCandidates(ctx, since, day.UnixNano(), 1, 10); err != nil || len(early) != 0 {
		t.Fatalf("active roots listed: %d, %v", len(early), err)
	}

	rows, truncated, err := store.LoadSessionAudits(ctx, rootA, keyA)
	if err != nil || truncated {
		t.Fatalf("load: %v truncated=%v", err, truncated)
	}
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.AuditID)
	}
	if strings.Join(ids, ",") != "a1,a2,c1,c2" {
		t.Fatalf("rows of key A = %v", ids)
	}
	if rows[0].NewAPITokenID == nil || *rows[0].NewAPITokenID != 1 || !rows[0].TurnStart || rows[2].AgentRole != "subagent" || rows[3].AgentRole != "compaction" {
		t.Fatalf("row projection: %+v", rows[0])
	}
	foreign, _, err := store.LoadSessionAudits(ctx, rootA, keyB)
	if err != nil || len(foreign) != 1 || foreign[0].AuditID != "b1" || !bytes.Equal(foreign[0].APIKeyFPR, keyB) {
		t.Fatalf("rows of key B = %+v, %v", foreign, err)
	}
	if keyless, _, err := store.LoadSessionAudits(ctx, rootA, nil); err != nil || len(keyless) != 0 {
		t.Fatalf("rows without a key = %d, %v", len(keyless), err)
	}

	lastNS := rows[len(rows)-1].StartedAtNS
	signals := testSignals(fill(0xc1), keyA, "c2", lastNS)
	signals.AgentRootFPR = rootA
	fprs := []storage.SessionTextFPR{
		{Source: storage.TextSourceUser, FPR: fill(0x51), APIKeyFPR: keyA, SeenAtNS: lastNS},
		{Source: storage.TextSourceInjectedRules, FPR: fill(0x52), APIKeyFPR: keyA, SeenAtNS: 1},
	}
	if err := store.SaveSessionSignals(ctx, signals, fprs, nil); err != nil {
		t.Fatal(err)
	}
	// Saving twice replaces, never duplicates.
	if err := store.SaveSessionSignals(ctx, signals, fprs, nil); err != nil {
		t.Fatal(err)
	}
	if again, err := store.ListSessionCandidates(ctx, since, quiet, 1, 10); err != nil {
		t.Fatal(err)
	} else {
		for _, candidate := range again {
			if bytes.Equal(candidate.AgentRootFPR, rootA) && bytes.Equal(candidate.APIKeyFPR, keyA) {
				t.Fatal("analysed session listed again")
			}
		}
		if len(again) != 2 {
			t.Fatalf("key B's part of root A must stay due: %+v", again)
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
	if !bytes.Equal(got.AgentRootFPR, rootA) || got.Loops != 1 || got.Verified != "no" || got.CostUSD == nil || *got.CostUSD != 1.25 || got.DangerCounts != `{"force_push":1}` {
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
	removed, err := store.PruneSessionAnalysis(ctx, quiet, 2)
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
	if removed, err := store.PruneSessionAnalysis(ctx, quiet, 2); err != nil || removed != 1 {
		t.Fatalf("prune = %d, %v", removed, err)
	}
}

// Signals mark a session analysed, so they are stored only together with its
// pack: a pack the database rejects leaves no signals behind.
func TestSessionSignalsAndPackAreOneWrite(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	ctx := context.Background()
	day := seedSharedWorld(t, store)
	key := fill(0xc2)
	signals := testSignals(key, keyA, "a2", day.UnixNano())
	signals.AgentRootFPR = rootA
	pack := storage.SessionPack{
		SessionKey: key, Kind: storage.PackKindSession, APIKeyFPR: keyA, PackHash: strings.Repeat("ab", 32),
		PackEnc: []byte{1}, RefMap: "{}", FirstNS: day.UnixNano(), LastNS: day.UnixNano(), LastAuditID: "a2", BuiltAtNS: 1, Members: 1,
		TokenEstimate: -1, // violates the token_estimate check inside the transaction
	}
	if err := store.SaveSessionSignals(ctx, signals, nil, &pack); err == nil {
		t.Fatal("rejected pack accepted")
	}
	var count int
	if err := store.readerDB.QueryRow(`SELECT count(*) FROM session_signals WHERE session_key = $1`, key).Scan(&count); err != nil || count != 0 {
		t.Fatalf("signals stored without their pack: %d, %v", count, err)
	}
	since, quiet := day.Add(-time.Hour).UnixNano(), day.Add(time.Hour).UnixNano()
	if due, err := store.ListSessionCandidates(ctx, since, quiet, 1, 10); err != nil || len(due) != 3 {
		t.Fatalf("session not due after a failed write: %d, %v", len(due), err)
	}
	pack.TokenEstimate = 10
	if err := store.SaveSessionSignals(ctx, signals, nil, &pack); err != nil {
		t.Fatal(err)
	}
	if loaded, err := store.LoadSessionPack(ctx, key); err != nil || loaded.Kind != storage.PackKindSession {
		t.Fatalf("pack = %+v, %v", loaded, err)
	}
	// A recomputation without a pack drops the stale one in the same write.
	if err := store.SaveSessionSignals(ctx, signals, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSessionPack(ctx, key); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("stale pack kept: %v", err)
	}
	digest := pack
	digest.Kind = storage.PackKindChatDigest
	if err := store.SaveSessionSignals(ctx, signals, nil, &digest); err == nil {
		t.Fatal("digest accepted as a session's own pack")
	}
}

// Chat digests follow their members: a chat that leaves its bucket drops the
// digests holding it (and their facets) and queues the other members; a
// rebuild replaces the bucket's chunks, removes surplus ones and clears the
// queue; retention does the same for expiring members.
func TestChatDigestsFollowTheirMembers(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	ctx := context.Background()
	day := seedSharedWorld(t, store)
	bucketKey := fill(0xd1)
	bucket := storage.ChatDigestBucket{APIKeyFPR: keyA, Client: "unknown", FromNS: day.Add(-time.Hour).UnixNano(), ToNS: day.Add(time.Hour).UnixNano()}
	chat := func(key []byte, lastNS int64) storage.SessionSignals {
		signals := testSignals(key, keyA, "a2", lastNS)
		signals.Kind, signals.Client, signals.SkipReason, signals.Eligible, signals.DigestBucket = "chat", "", "single_turn_chat", false, bucketKey
		return signals
	}
	c1, c2, c3 := fill(0xc1), fill(0xc2), fill(0xc3)
	for index, key := range [][]byte{c1, c2, c3} {
		if err := store.SaveSessionSignals(ctx, chat(key, day.UnixNano()+int64(index)), nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	pending := func() map[string]bool {
		t.Helper()
		rows, err := store.ListPendingDigestMembers(ctx, 10)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, row := range rows {
			out[string(row.SessionKey)] = true
		}
		return out
	}
	if got := pending(); len(got) != 3 {
		t.Fatalf("new single-turn chats pending = %d", len(got))
	}
	digest := func(key []byte, members ...[]byte) storage.ChatDigestChunk {
		return storage.ChatDigestChunk{Members: members, Pack: storage.SessionPack{
			SessionKey: key, Kind: storage.PackKindChatDigest, APIKeyFPR: keyA, Client: "unknown", PackHash: strings.Repeat("ef", 32),
			PackEnc: []byte{1}, RefMap: "{}", FirstNS: day.UnixNano(), LastNS: day.UnixNano(), LastAuditID: "a2", BuiltAtNS: 1, Members: int64(len(members)),
		}}
	}
	chunk0, chunk1 := fill(0xe0), fill(0xe1)
	// A surplus chunk from a larger day is removed by the rebuild.
	surplus := digest(chunk1, c3)
	if err := store.SaveSessionPack(ctx, surplus.Pack, surplus.Members); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveChatDigests(ctx, bucket, []storage.ChatDigestChunk{digest(chunk0, c1, c2, c3)}, [][]byte{chunk1}); err != nil {
		t.Fatal(err)
	}
	if got := pending(); len(got) != 0 {
		t.Fatalf("pending after the rebuild = %d", len(got))
	}
	if _, err := store.LoadSessionPack(ctx, chunk1); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("surplus chunk kept: %v", err)
	}
	if err := store.SaveSessionFacet(ctx, storage.SessionFacet{SessionKey: chunk0, Kind: storage.PackKindChatDigest, APIKeyFPR: keyA,
		LastNS: day.UnixNano(), PackHash: strings.Repeat("ef", 32), PromptVersion: "facet-v1", Model: "m", Status: "ok", TaskType: "stale", CreatedAtNS: 1}, nil); err != nil {
		t.Fatal(err)
	}

	// c1 gains a turn and leaves the single-turn category.
	left := testSignals(c1, keyA, "a2", day.UnixNano())
	left.Kind = "chat"
	if err := store.SaveSessionSignals(ctx, left, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSessionPack(ctx, c2); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("digest holding the departed chat kept: %v", err)
	}
	if _, err := store.LoadSessionFacet(ctx, chunk0); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("stale digest facet kept: %v", err)
	}
	if got := pending(); len(got) != 2 || !got[string(c2)] || !got[string(c3)] {
		t.Fatalf("remaining members not queued: %d", len(got))
	}
	// A re-save of a chat that stays in its bucket drops nothing.
	if err := store.SaveChatDigests(ctx, bucket, []storage.ChatDigestChunk{digest(chunk0, c2, c3)}, [][]byte{chunk1}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveSessionSignals(ctx, chat(c2, day.UnixNano()+1), nil, nil); err != nil {
		t.Fatal(err)
	}
	if loaded, err := store.LoadSessionPack(ctx, c3); err != nil || !bytes.Equal(loaded.SessionKey, chunk0) {
		t.Fatalf("digest dropped by a member that stayed: %v", err)
	}
	if err := store.SaveChatDigests(ctx, bucket, []storage.ChatDigestChunk{digest(chunk0, c2, c3)}, nil); err != nil {
		t.Fatal(err)
	}

	// Retention removes c2: its digest goes and c3 is queued.
	if _, err := store.writerConn.ExecContext(ctx, `UPDATE session_signals SET last_audit_id = 'expired-audit' WHERE session_key = $1`, c2); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PruneSessionAnalysis(ctx, day.Add(time.Hour).UnixNano(), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSessionPack(ctx, c3); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("digest holding an expired chat kept: %v", err)
	}
	if got := pending(); len(got) != 1 || !got[string(c3)] {
		t.Fatalf("pending after prune = %d", len(got))
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
	if err := store.SaveSessionSignals(ctx, signals, []storage.SessionTextFPR{{Source: storage.TextSourceUser, FPR: fill(0x62), SeenAtNS: 100}}, nil); err != nil {
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
	if err := store.SaveSessionSignals(ctx, signals, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSessionPack(ctx, rootA); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("stale pack kept: %v", err)
	}
	if _, err := store.PruneSessionAnalysis(ctx, day.Add(time.Hour).UnixNano(), 0); err != nil {
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
	if err := store.SaveSessionSignals(ctx, chat, nil, nil); err != nil {
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

func TestSessionFacetRetryLimit(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	ctx := context.Background()
	day := seedSharedWorld(t, store)
	if err := store.SaveSessionSignals(ctx, testSignals(rootA, keyA, "a2", day.UnixNano()), nil, nil); err != nil {
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
	due := func(model string) int {
		t.Helper()
		packs, err := store.ListFacetCandidates(ctx, settled, "facet-v1", model, 10)
		if err != nil {
			t.Fatal(err)
		}
		return len(packs)
	}
	failed := storage.SessionFacet{
		SessionKey: rootA, Kind: storage.PackKindSession, APIKeyFPR: keyA, LastNS: day.UnixNano(), PackHash: pack.PackHash,
		PromptVersion: "facet-v1", Model: "m", Status: "failed", CreatedAtNS: 5,
	}
	// The first attempt and every retry inside the limit leave the pack due.
	for attempt := 1; attempt <= storage.FacetRetryLimit; attempt++ {
		if err := store.SaveSessionFacet(ctx, failed, nil); err != nil {
			t.Fatal(err)
		}
		if due("m") != 1 {
			t.Fatalf("failed facet not due after attempt %d", attempt)
		}
	}
	// The last retry failed too: the pack is left alone.
	if err := store.SaveSessionFacet(ctx, failed, nil); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadSessionFacet(ctx, rootA)
	if err != nil || loaded.Attempts != storage.FacetRetryLimit+1 || due("m") != 0 {
		t.Fatalf("after the limit: attempts = %d, due = %d, %v", loaded.Attempts, due("m"), err)
	}
	// Another model starts over, and its attempts are counted from one.
	if due("other") != 1 {
		t.Fatal("another model is not due")
	}
	failed.Model = "other"
	if err := store.SaveSessionFacet(ctx, failed, nil); err != nil {
		t.Fatal(err)
	}
	if loaded, err := store.LoadSessionFacet(ctx, rootA); err != nil || loaded.Attempts != 1 || due("other") != 1 {
		t.Fatalf("after a model change: attempts = %d, %v", loaded.Attempts, err)
	}
}

func TestSessionFacetsStorage(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	ctx := context.Background()
	day := seedSharedWorld(t, store)
	if err := store.SaveSessionSignals(ctx, testSignals(rootA, keyA, "a2", day.UnixNano()), nil, nil); err != nil {
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
		if err := store.SaveSessionSignals(ctx, signals, fprs, nil); err != nil {
			t.Fatal(err)
		}
	}
	keys, err := store.ActiveAnalysisKeys(ctx, at-1, at+100)
	if err != nil || len(keys) != 2 {
		t.Fatalf("active keys = %d, %v", len(keys), err)
	}
	// session_keys is a bytea[] column: every key must decode byte for byte.
	sameKeys := func(got [][]byte, want ...[]byte) bool {
		if len(got) != len(want) {
			return false
		}
		remaining := map[string]int{}
		for _, key := range want {
			remaining[string(key)]++
		}
		for _, key := range got {
			if remaining[string(key)] == 0 {
				return false
			}
			remaining[string(key)]--
		}
		return true
	}
	all, err := store.RepeatedFingerprints(ctx, at-1, storage.FacetScope{}, 10)
	if err != nil || len(all) != 1 || all[0].Sessions != 3 || all[0].Kind != "instruction" || !all[0].Adopted ||
		!bytes.Equal(all[0].FPR, fill(0xa1)) || !sameKeys(all[0].SessionKeys, fill(0x91), fill(0x92), fill(0x93)) {
		t.Fatalf("repeated (all) = %+v, %v", all, err)
	}
	mine, err := store.RepeatedFingerprints(ctx, at-1, storage.FacetScope{APIKeyFPR: keyA}, 10)
	if err != nil || len(mine) != 1 || mine[0].Sessions != 2 || !sameKeys(mine[0].SessionKeys, fill(0x91), fill(0x92)) {
		t.Fatalf("repeated (key A) = %+v, %v", mine, err)
	}
	if theirs, err := store.RepeatedFingerprints(ctx, at-1, storage.FacetScope{APIKeyFPR: keyB}, 10); err != nil || len(theirs) != 0 {
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
	if enums, err := store.FacetEnums(ctx, at-1, at+100, storage.FacetScope{APIKeyFPR: keyA}); err != nil || len(enums) != 0 {
		t.Fatalf("enums = %+v, %v", enums, err)
	}
}

// Sessions carry the project and bucket of the organisation reports; report
// filters select by them, and a refresh re-books without re-analysing.
func TestSessionProjectBooking(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	ctx := context.Background()
	day := seedSharedWorld(t, store)
	at := day.UnixNano()
	project := func(id int64) *int64 { return &id }
	user := func(id int64) *int64 { return &id }
	save := func(key []byte, apiKey []byte, userID int64, projectID *int64, bucket string, offset int64) {
		t.Helper()
		signals := testSignals(key, apiKey, "a2", at+offset)
		signals.NewAPIUserID, signals.ProjectID, signals.Bucket = user(userID), projectID, bucket
		fprs := []storage.SessionTextFPR{{Source: storage.TextSourceUser, FPR: fill(0xb0), APIKeyFPR: apiKey, SeenAtNS: at + offset}}
		if err := store.SaveSessionSignals(ctx, signals, fprs, nil); err != nil {
			t.Fatal(err)
		}
	}
	booked, loose, service, plain := fill(0xd1), fill(0xd2), fill(0xd3), fill(0xd4)
	save(booked, keyA, 8, project(10), storage.BucketAttributed, 1)
	save(loose, keyA, 8, nil, storage.BucketUnattributed, 2)
	save(service, keyB, 9, project(10), storage.BucketService, 3)
	save(plain, keyA, 8, nil, "", 4)
	bad := testSignals(fill(0xd5), keyA, "a2", at)
	bad.Bucket = "elsewhere"
	if err := store.SaveSessionSignals(ctx, bad, nil, nil); err == nil {
		t.Fatal("unknown bucket stored")
	}

	window := storage.SessionSignalFilter{FromNS: at, ToNS: at + 100}
	page, err := store.ListSessionSignals(ctx, window, storage.SessionSignalCursor{}, 10)
	if err != nil || len(page.Rows) != 4 {
		t.Fatalf("rows = %d, %v", len(page.Rows), err)
	}
	stored := map[string]storage.SessionSignals{}
	for _, row := range page.Rows {
		stored[string(row.SessionKey)] = row
	}
	if row := stored[string(booked)]; row.ProjectID == nil || *row.ProjectID != 10 || row.Bucket != storage.BucketAttributed {
		t.Fatalf("booked = %v %q", row.ProjectID, row.Bucket)
	}
	if row := stored[string(plain)]; row.ProjectID != nil || row.Bucket != "" {
		t.Fatalf("plain = %v %q", row.ProjectID, row.Bucket)
	}

	count := func(filter storage.SessionSignalFilter) storage.SessionSignalTotals {
		t.Helper()
		filter.FromNS, filter.ToNS = window.FromNS, window.ToNS
		totals, err := store.SessionSignalTotals(ctx, filter)
		if err != nil {
			t.Fatal(err)
		}
		return totals
	}
	if all := count(storage.SessionSignalFilter{}); all.Sessions != 4 || all.Contributors != 2 {
		t.Fatalf("all = %d sessions, %d contributors", all.Sessions, all.Contributors)
	}
	if reported := count(storage.SessionSignalFilter{ExcludeService: true}); reported.Sessions != 3 || reported.Contributors != 1 {
		t.Fatalf("without services = %d sessions, %d contributors", reported.Sessions, reported.Contributors)
	}
	if got := count(storage.SessionSignalFilter{ProjectID: project(10)}).Sessions; got != 2 {
		t.Fatalf("project 10 = %d", got)
	}
	if got := count(storage.SessionSignalFilter{ProjectID: project(10), ExcludeService: true}).Sessions; got != 1 {
		t.Fatalf("project 10 without services = %d", got)
	}
	if got := count(storage.SessionSignalFilter{UserIDs: []int64{9, 77}}).Sessions; got != 1 {
		t.Fatalf("users 9 and 77 = %d", got)
	}
	if got := count(storage.SessionSignalFilter{UserIDs: []int64{}}).Sessions; got != 0 {
		t.Fatalf("empty user set = %d", got)
	}
	// Key B only has a service session: it gets no personal report.
	if keys, err := store.ActiveAnalysisKeys(ctx, at, at+100); err != nil || len(keys) != 1 || !bytes.Equal(keys[0].APIKeyFPR, keyA) {
		t.Fatalf("active keys = %+v, %v", keys, err)
	}

	fprProject := func(key []byte) sql.NullInt64 {
		t.Helper()
		var id sql.NullInt64
		if err := store.readerDB.QueryRow(`SELECT project_id FROM session_text_fprs WHERE session_key = $1`, key).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	if id := fprProject(booked); !id.Valid || id.Int64 != 10 {
		t.Fatalf("fingerprint project = %+v", id)
	}
	if id := fprProject(loose); id.Valid {
		t.Fatalf("unattributed fingerprint has project %d", id.Int64)
	}

	refs, err := store.ListSessionProjects(ctx, at+2, at+1000, 10)
	if err != nil || len(refs) != 3 || !bytes.Equal(refs[0].SessionKey, plain) || !bytes.Equal(refs[2].SessionKey, loose) ||
		!bytes.Equal(refs[1].AgentRootFPR, service) || !bytes.Equal(refs[1].APIKeyFPR, keyB) || refs[1].Bucket != storage.BucketService {
		t.Fatalf("refs = %+v, %v", refs, err)
	}
	if early, err := store.ListSessionProjects(ctx, at, at+3, 10); err != nil || len(early) != 1 || !bytes.Equal(early[0].SessionKey, booked) {
		t.Fatalf("computed before = %+v, %v", early, err)
	}

	if err := store.UpdateSessionProjects(ctx, []storage.SessionProjectRef{
		{SessionKey: loose, ProjectID: project(11), Bucket: storage.BucketAttributed},
		{SessionKey: booked, Bucket: storage.BucketUnattributed},
		{SessionKey: service, ProjectID: project(12), Bucket: storage.BucketAttributed},
	}); err != nil {
		t.Fatal(err)
	}
	if got := count(storage.SessionSignalFilter{ProjectID: project(11)}).Sessions; got != 1 {
		t.Fatalf("re-booked to 11 = %d", got)
	}
	if id := fprProject(loose); !id.Valid || id.Int64 != 11 {
		t.Fatalf("re-booked fingerprint = %+v", id)
	}
	if id := fprProject(booked); id.Valid {
		t.Fatalf("fingerprint kept project %d", id.Int64)
	}
	// A service session is never re-booked by the refresh.
	if got := count(storage.SessionSignalFilter{ProjectID: project(10)}).Sessions; got != 1 {
		t.Fatalf("service session moved: project 10 = %d", got)
	}
	// It stored no fingerprints in the first place.
	var kept int
	if err := store.readerDB.QueryRow(`SELECT COUNT(*) FROM session_text_fprs WHERE session_key = $1`, service).Scan(&kept); err != nil || kept != 0 {
		t.Fatalf("service session kept %d fingerprints, %v", kept, err)
	}
	if err := store.UpdateSessionProjects(ctx, []storage.SessionProjectRef{{SessionKey: loose, Bucket: storage.BucketService}}); err == nil {
		t.Fatal("refresh turned a session into a service")
	}
	if err := store.UpdateSessionProjects(ctx, nil); err != nil {
		t.Fatal(err)
	}
}

// Weekly statistics and suggestions also exist per project and per project
// group; facets and sentence fingerprints are selected through the booking.
func TestSessionReportScopes(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	ctx := context.Background()
	day := seedSharedWorld(t, store)
	at := day.UnixNano()
	id := func(value int64) *int64 { return &value }
	type session struct {
		key     []byte
		apiKey  []byte
		user    int64
		project *int64
		bucket  string
	}
	sessions := []session{
		{fill(0xe1), keyA, 8, id(10), storage.BucketAttributed},
		{fill(0xe2), keyB, 9, id(10), storage.BucketAttributed},
		{fill(0xe3), keyA, 8, id(11), storage.BucketAttributed},
		{fill(0xe4), keyB, 9, id(10), storage.BucketService},
	}
	repeated := fill(0xa7)
	for index, entry := range sessions {
		signals := testSignals(entry.key, entry.apiKey, "a2", at+int64(index))
		signals.NewAPIUserID, signals.ProjectID, signals.Bucket = id(entry.user), entry.project, entry.bucket
		fprs := []storage.SessionTextFPR{{Source: storage.TextSourceUser, FPR: repeated, APIKeyFPR: entry.apiKey, SeenAtNS: at + int64(index)}}
		if index == 2 {
			// Project 11 already injects the sentence as a rule.
			fprs = append(fprs, storage.SessionTextFPR{Source: storage.TextSourceInjectedRules, FPR: repeated, APIKeyFPR: entry.apiKey, SeenAtNS: at + 50})
		}
		pack := storage.SessionPack{
			SessionKey: entry.key, Kind: storage.PackKindSession, APIKeyFPR: entry.apiKey, PackHash: strings.Repeat("cd", 32),
			PackEnc: []byte{1}, RefMap: "{}", FirstNS: at, LastNS: at + int64(index), LastAuditID: "a2", BuiltAtNS: 1, Members: 1,
		}
		if err := store.SaveSessionSignals(ctx, signals, fprs, &pack); err != nil {
			t.Fatal(err)
		}
		facet := storage.SessionFacet{
			SessionKey: entry.key, Kind: storage.PackKindSession, APIKeyFPR: entry.apiKey, LastNS: at + int64(index), PackHash: pack.PackHash,
			PromptVersion: "facet-v1", Model: "m", Status: "ok", TaskType: "bug_fix", Outcome: "achieved", CreatedAtNS: 5,
		}
		if err := store.SaveSessionFacet(ctx, facet, []storage.SessionTextFPR{{Source: storage.TextSourceFacetSkill, FPR: fill(0xa8), APIKeyFPR: entry.apiKey, SeenAtNS: at + int64(index)}}); err != nil {
			t.Fatal(err)
		}
	}

	if projects, err := store.ActiveAnalysisProjects(ctx, at, at+100); err != nil || len(projects) != 2 || projects[0] != 10 || projects[1] != 11 {
		t.Fatalf("active projects = %v, %v", projects, err)
	}
	if none, err := store.ActiveAnalysisProjects(ctx, at+3, at+100); err != nil || len(none) != 0 {
		t.Fatalf("a service session made its project active: %v, %v", none, err)
	}

	enums := func(scope storage.FacetScope) int {
		t.Helper()
		rows, err := store.FacetEnums(ctx, at, at+100, scope)
		if err != nil {
			t.Fatal(err)
		}
		return len(rows)
	}
	if enums(storage.FacetScope{}) != 4 || enums(storage.FacetScope{APIKeyFPR: keyA}) != 2 {
		t.Fatalf("all = %d, key A = %d", enums(storage.FacetScope{}), enums(storage.FacetScope{APIKeyFPR: keyA}))
	}
	// Project and user scopes leave the service session out.
	if got := enums(storage.FacetScope{ProjectID: id(10)}); got != 2 {
		t.Fatalf("project 10 facets = %d", got)
	}
	if got := enums(storage.FacetScope{ProjectID: id(11)}); got != 1 {
		t.Fatalf("project 11 facets = %d", got)
	}
	if got := enums(storage.FacetScope{UserIDs: []int64{9}}); got != 1 {
		t.Fatalf("user 9 facets = %d", got)
	}
	if got := enums(storage.FacetScope{UserIDs: []int64{8, 9}}); got != 3 {
		t.Fatalf("users 8 and 9 facets = %d", got)
	}
	if got := enums(storage.FacetScope{UserIDs: []int64{}}); got != 0 {
		t.Fatalf("empty user set facets = %d", got)
	}

	// Sentences repeat inside a project; the facet stage's fingerprints carry
	// the session's project too.
	inOrders, err := store.RepeatedFingerprints(ctx, at-1, storage.FacetScope{ProjectID: id(10)}, 10)
	if err != nil || len(inOrders) != 2 {
		t.Fatalf("project 10 repeats = %+v, %v", inOrders, err)
	}
	for _, group := range inOrders {
		// Two sessions of project 10 say it; the rule lives in project 11
		// only. A service session keeps no fingerprints: the instruction it
		// was saved with is dropped, and the skill its facet added afterwards
		// goes when it is saved as a service again.
		want := int64(2)
		if group.Kind == "skill" {
			want = 3
		}
		if group.Sessions != want || group.Adopted {
			t.Fatalf("project 10 group = %+v", group)
		}
	}
	serviceSignals := testSignals(sessions[3].key, keyB, "a2", at+3)
	serviceSignals.NewAPIUserID, serviceSignals.ProjectID, serviceSignals.Bucket = id(9), id(10), storage.BucketService
	if err := store.SaveSessionSignals(ctx, serviceSignals, nil, nil); err != nil {
		t.Fatal(err)
	}
	var left int
	if err := store.readerDB.QueryRow(`SELECT COUNT(*) FROM session_text_fprs WHERE session_key = $1`, sessions[3].key).Scan(&left); err != nil || left != 0 {
		t.Fatalf("service session kept %d fingerprints, %v", left, err)
	}
	if inBilling, err := store.RepeatedFingerprints(ctx, at-1, storage.FacetScope{ProjectID: id(11)}, 10); err != nil || len(inBilling) != 0 {
		t.Fatalf("project 11 repeats = %+v, %v", inBilling, err)
	}
	everywhere, err := store.RepeatedFingerprints(ctx, at-1, storage.FacetScope{}, 10)
	if err != nil || len(everywhere) != 2 {
		t.Fatalf("all repeats = %+v, %v", everywhere, err)
	}
	for _, group := range everywhere {
		if group.Sessions != 3 || (group.Kind == "instruction") != group.Adopted {
			t.Fatalf("all group = %+v", group)
		}
	}

	// Project and group scopes are stored under the id-derived key.
	for _, scope := range []string{storage.ScopeProject, storage.ScopeGroup} {
		for _, scopeID := range []int64{11, 10} {
			if err := store.SavePeriodStats(ctx, storage.PeriodStats{WeekStartNS: 700, Scope: scope, ScopeKey: storage.IDScopeKey(scopeID),
				Stats: `{"totals":{}}`, InputHash: "h", ComputedAtNS: 5}); err != nil {
				t.Fatalf("%s stats: %v", scope, err)
			}
		}
		keys, err := store.ListPeriodScopeKeys(ctx, 700, scope)
		if err != nil || len(keys) != 2 {
			t.Fatalf("%s keys = %d, %v", scope, len(keys), err)
		}
		first, okFirst := storage.IDOfScopeKey(keys[0])
		second, okSecond := storage.IDOfScopeKey(keys[1])
		if !okFirst || !okSecond || first != 10 || second != 11 {
			t.Fatalf("%s ids = %d %d", scope, first, second)
		}
		if loaded, err := store.LoadPeriodStats(ctx, 700, scope, storage.IDScopeKey(10), nil); err != nil || loaded.Scope != scope {
			t.Fatalf("%s load = %+v, %v", scope, loaded, err)
		}
	}
	if keys, err := store.ListPeriodScopeKeys(ctx, 701, storage.ScopeProject); err != nil || len(keys) != 0 {
		t.Fatalf("another week = %d, %v", len(keys), err)
	}
	if _, ok := storage.IDOfScopeKey(keyA); ok {
		t.Fatal("an API key fingerprint decoded as an id")
	}
	if err := store.SavePeriodStats(ctx, storage.PeriodStats{WeekStartNS: 700, Scope: "team", ScopeKey: storage.IDScopeKey(1), Stats: "{}", ComputedAtNS: 5}); err == nil {
		t.Fatal("unknown scope stored")
	}

	suggestion := storage.Suggestion{Scope: storage.ScopeProject, ScopeKey: storage.IDScopeKey(10), Kind: "instruction", FPR: repeated,
		Support: 2, FirstSeenNS: at, LastSeenNS: at + 1, Status: "open", TextEnc: []byte{7}, UpdatedAtNS: 1}
	if err := store.UpsertSuggestion(ctx, suggestion); err != nil {
		t.Fatal(err)
	}
	listed, err := store.ListSuggestions(ctx, storage.ScopeProject, storage.IDScopeKey(10), nil, 10)
	if err != nil || len(listed) != 1 {
		t.Fatalf("project suggestions = %+v, %v", listed, err)
	}
	if other, err := store.ListSuggestions(ctx, storage.ScopeProject, storage.IDScopeKey(11), nil, 10); err != nil || len(other) != 0 {
		t.Fatalf("another project's suggestions = %+v, %v", other, err)
	}
	if err := store.DismissSuggestion(ctx, listed[0].ID, storage.ScopeAll, 2); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("dismissed through the all scope: %v", err)
	}
	if err := store.DismissSuggestion(ctx, listed[0].ID, storage.ScopeProject, 2); err != nil {
		t.Fatal(err)
	}
	suggestion.Scope = storage.ScopeGroup
	if err := store.UpsertSuggestion(ctx, suggestion); err == nil {
		t.Fatal("group suggestion stored")
	}
}

// The prune checks only rows older than the retention cutoff, one bounded
// page per writer operation, and leaves everything else alone.
func TestSessionPruneChecksOnlyExpiredCandidatesInPages(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	ctx := context.Background()
	day := seedSharedWorld(t, store)
	at := day.UnixNano()
	cutoff := at + 1000
	pack := func(key []byte, kind, lastAuditID string, lastNS int64) storage.SessionPack {
		return storage.SessionPack{
			SessionKey: key, Kind: kind, APIKeyFPR: keyA, PackHash: strings.Repeat("ef", 32), PackEnc: []byte{1}, RefMap: "{}",
			FirstNS: at - 1, LastNS: lastNS, LastAuditID: lastAuditID, BuiltAtNS: 1, Members: 1,
		}
	}
	save := func(key []byte, lastAuditID string, lastNS, seenNS int64) {
		t.Helper()
		signals := testSignals(key, keyA, lastAuditID, lastNS)
		own := pack(key, storage.PackKindSession, lastAuditID, lastNS)
		fprs := []storage.SessionTextFPR{{Source: storage.TextSourceUser, FPR: key, APIKeyFPR: keyA, SeenAtNS: seenNS}}
		if err := store.SaveSessionSignals(ctx, signals, fprs, &own); err != nil {
			t.Fatal(err)
		}
	}
	// Five sessions older than the cutoff lost their newest audit. Two share a
	// last_ns, so a page boundary falls between rows of the same instant.
	expired := [][]byte{fill(0xf1), fill(0xf2), fill(0xf3), fill(0xf4), fill(0xf5)}
	for index, lastNS := range []int64{at, at + 1, at + 1, at + 3, at + 4} {
		save(expired[index], "gone-"+string(rune('a'+index)), lastNS, int64(index+1))
	}
	// Older than the cutoff, but its audit is still there.
	live := fill(0xf6)
	chat := testSignals(live, keyA, "a2", at+2)
	chat.Kind, chat.Eligible, chat.SkipReason, chat.DigestBucket = "chat", false, "single_turn_chat", fill(0xb7)
	if err := store.SaveSessionSignals(ctx, chat, nil, nil); err != nil {
		t.Fatal(err)
	}
	// Its audit is gone too, but it is not older than the cutoff: outside the
	// range the prune may look at.
	recent := fill(0xf7)
	save(recent, "gone-recent", cutoff, 100)
	// A digest whose own newest audit expired while its member remains.
	digest := fill(0xf8)
	if err := store.SaveSessionPack(ctx, pack(digest, storage.PackKindChatDigest, "gone-digest", at+5), [][]byte{live}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.writerConn.ExecContext(ctx, `UPDATE session_signals SET digest_pending = FALSE`); err != nil {
		t.Fatal(err)
	}

	count := func(query string, arguments ...any) int {
		t.Helper()
		var rows int
		if err := store.readerDB.QueryRow(query, arguments...).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		return rows
	}
	// Retention disabled: nothing is checked, whatever is missing.
	if removed, err := store.pruneSessionAnalysis(ctx, 0, 0, 2, 2); err != nil || removed != 0 || count(`SELECT COUNT(*) FROM session_signals`) != 7 {
		t.Fatalf("prune without a cutoff removed %d, %v", removed, err)
	}

	// Pages of two sessions and chunks of two fingerprints.
	removed, err := store.pruneSessionAnalysis(ctx, cutoff, 4, 2, 2)
	if err != nil || removed != 5 {
		t.Fatalf("removed = %d, %v", removed, err)
	}
	for _, key := range expired {
		if count(`SELECT COUNT(*) FROM session_signals WHERE session_key = $1`, key) != 0 || count(`SELECT COUNT(*) FROM session_packs WHERE session_key = $1`, key) != 0 {
			t.Fatalf("expired session %x kept rows", key[:1])
		}
	}
	if count(`SELECT COUNT(*) FROM session_signals`) != 2 {
		t.Fatalf("sessions left = %d", count(`SELECT COUNT(*) FROM session_signals`))
	}
	if count(`SELECT COUNT(*) FROM session_signals WHERE session_key = $1`, recent) != 1 || count(`SELECT COUNT(*) FROM session_packs WHERE session_key = $1`, recent) != 1 {
		t.Fatal("a session inside the retention period was pruned")
	}
	// The expired digest is gone and its remaining member waits for a rebuild.
	if count(`SELECT COUNT(*) FROM session_packs WHERE session_key = $1`, digest) != 0 || count(`SELECT COUNT(*) FROM session_pack_members WHERE pack_key = $1`, digest) != 0 {
		t.Fatal("expired digest kept")
	}
	if count(`SELECT COUNT(*) FROM session_signals WHERE session_key = $1 AND digest_pending`, live) != 1 {
		t.Fatal("member of the expired digest not queued")
	}
	// Fingerprints older than the cutoff went, in chunks; the others stay
	// although their sessions are gone.
	if count(`SELECT COUNT(*) FROM session_text_fprs WHERE seen_at_ns < 4`) != 0 || count(`SELECT COUNT(*) FROM session_text_fprs`) != 3 {
		t.Fatalf("fingerprints left = %d", count(`SELECT COUNT(*) FROM session_text_fprs`))
	}
	// A second pass finds nothing.
	if removed, err := store.pruneSessionAnalysis(ctx, cutoff, 4, 2, 2); err != nil || removed != 0 {
		t.Fatalf("second pass removed %d, %v", removed, err)
	}
	// Once it is older than the cutoff, the remaining orphan goes as well.
	if removed, err := store.PruneSessionAnalysis(ctx, cutoff+1, 0); err != nil || removed != 1 {
		t.Fatalf("later pass removed %d, %v", removed, err)
	}
	for _, size := range [][2]int{{0, 2}, {gcBatchSize + 1, 2}, {2, 0}} {
		if _, err := store.pruneSessionAnalysis(ctx, cutoff, 0, size[0], size[1]); err == nil {
			t.Fatalf("page sizes %v accepted", size)
		}
	}
}
