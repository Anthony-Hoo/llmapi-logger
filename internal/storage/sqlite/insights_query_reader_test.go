package sqlite

import (
	"bytes"
	"context"
	"strconv"
	"testing"
	"time"
)

type insightsSeed struct {
	id        string
	at        time.Time
	endAfter  time.Duration
	key       []byte
	token     int64 // 0: no token link
	model     string
	session   string
	root      []byte
	node      []byte
	parent    []byte
	role      string
	client    string
	uncached  int64
	cacheRead int64
	output    int64
	noUsage   bool
	turnStart bool
	stop      string
	prev      string
	system    int64
	user      int64
}

func fill(value byte) []byte { return bytes.Repeat([]byte{value}, AnalysisFingerprintSize) }

func seedInsights(t *testing.T, store *Store, seed insightsSeed) {
	t.Helper()
	ctx := context.Background()
	record := testAudit(seed.id)
	record.StartedAtNS = seed.at.UnixNano()
	record.APIKeyFPR = seed.key
	if err := store.BeginAudit(ctx, record); err != nil {
		t.Fatal(err)
	}
	status := 200
	endAfter := seed.endAfter
	if endAfter == 0 {
		endAfter = time.Second
	}
	if err := store.FinishAudit(ctx, AuditFinish{
		AuditID: seed.id, EndedAtNS: record.StartedAtNS + int64(endAfter), StatusCode: &status,
		ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParseOK,
	}); err != nil {
		t.Fatal(err)
	}
	if seed.token != 0 {
		if _, err := store.writerDB.ExecContext(ctx, `
INSERT INTO token_links (audit_id, newapi_user_id, username, newapi_token_id, token_name, linked_at_ns)
VALUES (?, ?, ?, ?, ?, ?)`, seed.id, 7+seed.token, "user-"+strconv.FormatInt(seed.token, 10), seed.token, "token-name", record.StartedAtNS+1); err != nil {
			t.Fatal(err)
		}
	}
	model := seed.model
	if model == "" {
		model = "model-example"
	}
	role := seed.role
	if role == "" {
		role = "main"
	}
	client := seed.client
	if client == "" {
		client = "custom"
	}
	link := "agent"
	row := AnalysisRow{
		AuditID: seed.id, AnalysisVersion: 1, AnalyzedAtNS: record.StartedAtNS + 10, Protocol: "openai",
		Model: &model, StartedAtNS: record.StartedAtNS,
		EstSystem: seed.system, EstUser: seed.user,
		RespKinds: 4, TurnStart: seed.turnStart, EventFlags: 0,
		AgentClient: &client, AgentRole: &role,
		AgentNodeFPR: seed.node, AgentParentFPR: seed.parent, AgentRootFPR: seed.root,
		SessionLink: &link,
	}
	if !seed.noUsage {
		row.UncachedInput, row.CacheRead, row.Output = &seed.uncached, &seed.cacheRead, &seed.output
	}
	if seed.session != "" {
		row.AnalysisSessionID = &seed.session
	}
	if seed.stop != "" {
		row.StopReason = &seed.stop
	}
	if seed.prev != "" {
		row.PrevAuditID = &seed.prev
	}
	if err := store.SaveAnalysis(ctx, row); err != nil {
		t.Fatal(err)
	}
}

const (
	sessionShared = "agt_aaaaaaaaaaaaaaaaaaaaaaaa"
	sessionSub    = "agt_bbbbbbbbbbbbbbbbbbbbbbbb"
	sessionForeig = "agt_cccccccccccccccccccccccc"
)

var (
	keyA  = scopeFingerprint(0x01)
	keyB  = scopeFingerprint(0x02)
	rootA = fill(0xa0)
	rootB = fill(0xb0)
	node1 = fill(0x11)
	node2 = fill(0x12)
	node3 = fill(0x13)
	node4 = fill(0x14)
)

// seedSharedWorld writes a world where key B contributes a step to key A's
// session and agent tree, plus a session and tree owned only by B.
func seedSharedWorld(t *testing.T, store *Store) (day time.Time) {
	t.Helper()
	day = time.Date(2026, 10, 10, 23, 30, 0, 0, time.UTC)
	seedInsights(t, store, insightsSeed{id: "a1", at: day, key: keyA, token: 1, session: sessionShared, root: rootA, node: node1,
		uncached: 100, cacheRead: 900, output: 50, turnStart: true, stop: "tool_use", system: 300, user: 100, model: "model-example"})
	seedInsights(t, store, insightsSeed{id: "a2", at: day.Add(10 * time.Second), key: keyA, token: 1, session: sessionShared, root: rootA, node: node1,
		uncached: 50, cacheRead: 1000, output: 20, prev: "a1", system: 300, user: 150})
	seedInsights(t, store, insightsSeed{id: "b1", at: day.Add(20 * time.Second), key: keyB, token: 2, session: sessionShared, root: rootA, node: node2, parent: node1,
		role: "subagent", uncached: 7000, cacheRead: 0, output: 700, system: 5000, user: 2000})
	seedInsights(t, store, insightsSeed{id: "c1", at: day.Add(30 * time.Second), key: keyA, token: 1, session: sessionSub, root: rootA, node: node3, parent: node1,
		role: "subagent", uncached: 10, cacheRead: 20, output: 5, turnStart: true, system: 10})
	seedInsights(t, store, insightsSeed{id: "c2", at: day.Add(40 * time.Second), key: keyA, token: 1, session: sessionSub, root: rootA, node: node3, parent: node1,
		role: "compaction", uncached: 1, cacheRead: 2, output: 3, system: 1})
	seedInsights(t, store, insightsSeed{id: "d1", at: day.Add(50 * time.Second), key: keyB, token: 2, session: sessionForeig, root: rootB, node: node4,
		uncached: 4000, output: 400, system: 4000})
	// A step without a session (never grouped into cards) and without usage.
	seedInsights(t, store, insightsSeed{id: "e1", at: day.Add(60 * time.Second), key: keyA, token: 1, noUsage: true, system: 40, user: 60})
	return day
}

func windowFilter(day time.Time, scope *AuditScope) InsightsFilter {
	return InsightsFilter{FromNS: day.Add(-time.Hour).UnixNano(), ToNS: day.Add(time.Hour).UnixNano(), Scope: scope}
}

func TestInsightsUsageAggregatesAndAppliesScope(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	day := seedSharedWorld(t, store)
	ctx := context.Background()
	scopeA := &AuditScope{Fingerprint: keyA}

	rows, err := store.InsightsUsage(ctx, windowFilter(day, nil), InsightsUsageSpec{Dimension: InsightsDimTotal})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Requests != 7 || rows[0].UncachedInput != 100+50+7000+10+1+4000 || rows[0].Output != 50+20+700+5+3+400 {
		t.Fatalf("unscoped total = %+v", rows)
	}
	rows, err = store.InsightsUsage(ctx, windowFilter(day, scopeA), InsightsUsageSpec{Dimension: InsightsDimTotal})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Requests != 5 || rows[0].UncachedInput != 100+50+10+1 || rows[0].CacheRead != 900+1000+20+2 {
		t.Fatalf("scoped total = %+v", rows)
	}
	// Anchored mix: a1 prompt 1000 over estimate 400 scales system 300 -> 750.
	if rows[0].Mix.System <= 0 || rows[0].Mix.User <= 0 {
		t.Fatalf("mix = %+v", rows[0].Mix)
	}

	distinctSessions, trees, err := store.InsightsDistinct(ctx, windowFilter(day, scopeA))
	if err != nil || distinctSessions != 2 || trees != 1 {
		t.Fatalf("scoped distinct = %d %d %v", distinctSessions, trees, err)
	}
	distinctSessions, trees, err = store.InsightsDistinct(ctx, windowFilter(day, nil))
	if err != nil || distinctSessions != 3 || trees != 2 {
		t.Fatalf("unscoped distinct = %d %d %v", distinctSessions, trees, err)
	}

	// The time range is half open and bounds the aggregate.
	rows, err = store.InsightsUsage(ctx, InsightsFilter{FromNS: day.UnixNano(), ToNS: day.Add(10 * time.Second).UnixNano()}, InsightsUsageSpec{Dimension: InsightsDimTotal})
	if err != nil || len(rows) != 1 || rows[0].Requests != 1 {
		t.Fatalf("half-open range = %+v %v", rows, err)
	}
}

func TestInsightsUsageGroupings(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	day := seedSharedWorld(t, store)
	ctx := context.Background()

	// 23:30 UTC is already the next local day at UTC+1 but not at UTC.
	for offset, want := range map[int][]string{0: {"2026-10-10"}, 60: {"2026-10-11"}} {
		rows, err := store.InsightsUsage(ctx, windowFilter(day, nil), InsightsUsageSpec{Dimension: InsightsDimDay, TZOffsetMin: offset})
		if err != nil || len(rows) != 1 || rows[0].Key != want[0] {
			t.Fatalf("day offset %d = %+v %v", offset, rows, err)
		}
	}
	counts, err := store.InsightsDayCounts(ctx, windowFilter(day, &AuditScope{Fingerprint: keyA}), 0)
	if err != nil || len(counts) != 1 || counts[0].Requests != 5 || counts[0].Sessions != 2 {
		t.Fatalf("day counts = %+v %v", counts, err)
	}

	rows, err := store.InsightsUsage(ctx, windowFilter(day, nil), InsightsUsageSpec{Dimension: InsightsDimToken})
	if err != nil || len(rows) != 2 || rows[0].Key != "1" || rows[0].Requests != 5 || rows[0].Label != "token-name" || rows[1].Key != "2" || rows[1].Requests != 2 {
		t.Fatalf("token groups = %+v %v", rows, err)
	}
	rows, err = store.InsightsUsage(ctx, windowFilter(day, nil), InsightsUsageSpec{Dimension: InsightsDimCaller})
	if err != nil || len(rows) != 2 || rows[0].Key != "8" || rows[0].Label != "user-1" {
		t.Fatalf("caller groups = %+v %v", rows, err)
	}
	for _, dimension := range []string{InsightsDimModel, InsightsDimProtocol, InsightsDimClient, InsightsDimSession, InsightsDimNode} {
		if _, err := store.InsightsUsage(ctx, windowFilter(day, nil), InsightsUsageSpec{Dimension: dimension, SlotNS: int64(30 * time.Minute)}); err != nil {
			t.Fatalf("dimension %s: %v", dimension, err)
		}
	}
	if _, err := store.InsightsUsage(ctx, windowFilter(day, nil), InsightsUsageSpec{Dimension: "bogus"}); err == nil {
		t.Fatal("unknown dimension accepted")
	}
}

func TestInsightsSessionsKeysetScopeAndLastStep(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	day := seedSharedWorld(t, store)
	ctx := context.Background()
	scopeA := &AuditScope{Fingerprint: keyA}

	page, err := store.InsightsSessions(ctx, windowFilter(day, scopeA), InsightsSortRecent, nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 2 || page.HasMore {
		t.Fatalf("scoped sessions = %+v", page)
	}
	// Most recent first: the subagent session ends after the shared one.
	sub, shared := page.Rows[0], page.Rows[1]
	if sub.SessionID != sessionSub || sub.Steps != 2 || sub.Turns != 1 || sub.Role != "compaction" {
		t.Fatalf("sub session = %+v", sub)
	}
	if shared.SessionID != sessionShared || shared.Steps != 2 || shared.Turns != 1 || shared.Tokens != 1050+1070 {
		t.Fatalf("shared session must only count key A steps: %+v", shared)
	}
	if shared.LastPrompt == nil || *shared.LastPrompt != 1050 || shared.Estimate.System != 300 || shared.Estimate.User != 150 {
		t.Fatalf("shared last step = %+v", shared)
	}
	if shared.Username != "user-1" || len(shared.Root) != AnalysisFingerprintSize {
		t.Fatalf("shared caller/root = %+v", shared)
	}

	unscoped, err := store.InsightsSessions(ctx, windowFilter(day, nil), InsightsSortTokens, nil, 10)
	if err != nil || len(unscoped.Rows) != 3 {
		t.Fatalf("unscoped sessions = %+v %v", unscoped, err)
	}
	if unscoped.Rows[0].SessionID != sessionShared || unscoped.Rows[0].Steps != 3 {
		t.Fatalf("tokens order = %+v", unscoped.Rows[0])
	}

	// Walk every ordering one card at a time; the keyset must visit each once.
	for _, sortKey := range []string{InsightsSortRecent, InsightsSortTokens, InsightsSortContext} {
		var seen []string
		var cursor *InsightsSessionCursor
		for range 5 {
			page, err := store.InsightsSessions(ctx, windowFilter(day, nil), sortKey, cursor, 1)
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range page.Rows {
				seen = append(seen, row.SessionID)
				cursor = &InsightsSessionCursor{Value: row.SortValue, SessionID: row.SessionID}
			}
			if !page.HasMore {
				break
			}
		}
		if len(seen) != 3 || seen[0] == seen[1] || seen[1] == seen[2] || seen[0] == seen[2] {
			t.Fatalf("sort %s visited %v", sortKey, seen)
		}
	}

	models, err := store.InsightsSessionModels(ctx, InsightsFilter{FromNS: windowFilter(day, nil).FromNS, ToNS: windowFilter(day, nil).ToNS, SessionIDs: []string{sessionShared}, Scope: scopeA})
	if err != nil || len(models[sessionShared]) != 1 || models[sessionShared][0] != "model-example" {
		t.Fatalf("models = %v %v", models, err)
	}
	counts, err := store.InsightsSubagentCounts(ctx, InsightsFilter{FromNS: windowFilter(day, nil).FromNS, ToNS: windowFilter(day, nil).ToNS, RootFPRs: [][]byte{rootA}, Scope: scopeA})
	if err != nil || counts[string(rootA)] != 1 {
		t.Fatalf("scoped subagents = %v %v", counts, err)
	}
	counts, err = store.InsightsSubagentCounts(ctx, InsightsFilter{FromNS: windowFilter(day, nil).FromNS, ToNS: windowFilter(day, nil).ToNS, RootFPRs: [][]byte{rootA}})
	if err != nil || counts[string(rootA)] != 2 {
		t.Fatalf("unscoped subagents = %v %v", counts, err)
	}
	if _, err := store.InsightsSessions(ctx, windowFilter(day, nil), "bogus", nil, 1); err == nil {
		t.Fatal("unknown sort accepted")
	}
}

func TestInsightsTrendOrdersLimitsAndHonoursScope(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	day := seedSharedWorld(t, store)
	ctx := context.Background()
	scopeA := &AuditScope{Fingerprint: keyA}
	filter := InsightsFilter{Scope: scopeA, SessionIDs: []string{sessionShared}}

	rows, truncated, err := store.InsightsTrend(ctx, filter, 10)
	if err != nil || truncated || len(rows) != 2 || rows[0].AuditID != "a1" || rows[1].AuditID != "a2" {
		t.Fatalf("trend = %+v truncated=%v err=%v", rows, truncated, err)
	}
	if !rows[0].TurnStart || rows[0].StopReason != "tool_use" || rows[0].EndedAtNS == nil ||
		*rows[0].EndedAtNS != day.UnixNano()+int64(time.Second) || rows[1].PrevAuditID != "a1" {
		t.Fatalf("trend fields = %+v", rows)
	}
	rows, truncated, err = store.InsightsTrend(ctx, filter, 1)
	if err != nil || !truncated || len(rows) != 1 || rows[0].AuditID != "a2" {
		t.Fatalf("limited trend = %+v truncated=%v err=%v", rows, truncated, err)
	}
	rows, _, err = store.InsightsTrend(ctx, InsightsFilter{Scope: scopeA, SessionIDs: []string{sessionForeig}}, 10)
	if err != nil || len(rows) != 0 {
		t.Fatalf("foreign session trend = %+v %v", rows, err)
	}
	rows, _, err = store.InsightsTrend(ctx, InsightsFilter{SessionIDs: []string{sessionShared}}, 10)
	if err != nil || len(rows) != 3 {
		t.Fatalf("unscoped trend = %d rows %v", len(rows), err)
	}
	if _, _, err := store.InsightsTrend(ctx, InsightsFilter{}, 10); err == nil {
		t.Fatal("trend without session accepted")
	}
}

func TestInsightsTreeNodesScopeAndTruncation(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	seedSharedWorld(t, store)
	ctx := context.Background()
	scopeA := &AuditScope{Fingerprint: keyA}
	prefix := rootA[:12]

	nodes, truncated, err := store.InsightsTree(ctx, InsightsFilter{Scope: scopeA, RootPrefix: prefix}, 40)
	if err != nil || truncated || len(nodes) != 2 {
		t.Fatalf("scoped nodes = %+v truncated=%v err=%v", nodes, truncated, err)
	}
	main, child := nodes[0], nodes[1]
	if !bytes.Equal(main.NodeFPR, node1) || main.Steps != 2 || main.AuxRequests != 0 || main.Role != "main" {
		t.Fatalf("main node = %+v", main)
	}
	// The compaction request belongs to node3 and counts as auxiliary only; the
	// last composition comes from its non-auxiliary step.
	if !bytes.Equal(child.NodeFPR, node3) || child.Steps != 1 || child.AuxRequests != 1 || child.Role != "subagent" ||
		!bytes.Equal(child.ParentFPR, node1) || child.Estimate.System != 10 {
		t.Fatalf("child node = %+v", child)
	}
	all, _, err := store.InsightsTree(ctx, InsightsFilter{RootPrefix: prefix}, 40)
	if err != nil || len(all) != 3 {
		t.Fatalf("unscoped nodes = %d %v", len(all), err)
	}
	limited, truncated, err := store.InsightsTree(ctx, InsightsFilter{RootPrefix: prefix}, 2)
	if err != nil || !truncated || len(limited) != 2 {
		t.Fatalf("limited nodes = %d truncated=%v %v", len(limited), truncated, err)
	}
	foreign, _, err := store.InsightsTree(ctx, InsightsFilter{Scope: scopeA, RootPrefix: rootB[:12]}, 40)
	if err != nil || len(foreign) != 0 {
		t.Fatalf("foreign tree = %d %v", len(foreign), err)
	}
	// Prefix boundaries: a prefix ending in 0xff must still bound correctly.
	if upper := prefixUpperBound([]byte{0x01, 0xff}); !bytes.Equal(upper, []byte{0x02}) {
		t.Fatalf("upper bound = %x", upper)
	}
	if prefixUpperBound([]byte{0xff, 0xff}) != nil {
		t.Fatal("all-ff prefix must be unbounded")
	}
}

func TestInsightsScopeAdmitsTokenLinkedRowsAndRejectsMalformedScope(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	day := seedSharedWorld(t, store)
	ctx := context.Background()
	// Key C has no rows of its own but owns token 2, which B's rows are linked to.
	token := int64(2)
	scope := &AuditScope{Fingerprint: scopeFingerprint(0x03), TokenID: &token}
	rows, err := store.InsightsUsage(ctx, windowFilter(day, scope), InsightsUsageSpec{Dimension: InsightsDimTotal})
	if err != nil || len(rows) != 1 || rows[0].Requests != 2 {
		t.Fatalf("token scope total = %+v %v", rows, err)
	}
	if _, err := store.InsightsUsage(ctx, windowFilter(day, &AuditScope{}), InsightsUsageSpec{Dimension: InsightsDimTotal}); err == nil {
		t.Fatal("malformed scope accepted")
	}
	if _, err := store.InsightsUsage(ctx, InsightsFilter{FromNS: 5, ToNS: 5}, InsightsUsageSpec{Dimension: InsightsDimTotal}); err == nil {
		t.Fatal("empty range accepted")
	}
}
