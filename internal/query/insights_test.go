package query

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/insights/pricing"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

var _ InsightsStore = (*sqlite.Store)(nil)

const (
	testSessionShared  = "agt_aaaaaaaaaaaaaaaaaaaaaaaa"
	testSessionForeign = "agt_cccccccccccccccccccccccc"
)

func fingerprint(value byte) []byte {
	return bytes.Repeat([]byte{value}, sqlite.AnalysisFingerprintSize)
}

type insightsFixture struct {
	t       *testing.T
	store   *sqlite.Store
	cipher  security.Cipher
	service *Insights
	base    time.Time
}

func newInsightsFixture(t *testing.T, prices *pricing.Table) *insightsFixture {
	t.Helper()
	store, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{0x5a}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	if prices == nil {
		if prices, err = pricing.Load(""); err != nil {
			t.Fatal(err)
		}
	}
	service, err := NewInsights(store, cipher, prices)
	if err != nil {
		t.Fatal(err)
	}
	return &insightsFixture{t: t, store: store, cipher: cipher, service: service, base: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)}
}

type stepSeed struct {
	id        string
	offset    time.Duration
	length    time.Duration
	key       []byte
	session   string
	root      []byte
	node      []byte
	parent    []byte
	role      string
	model     string
	uncached  *int64
	cacheRead *int64
	output    *int64
	turnStart bool
	stop      string
	prev      string
	events    int
	system    int64
	user      int64
	detail    *insights.Detail
	version   int
}

func i64(value int64) *int64 { return &value }

func (fixture *insightsFixture) seed(seed stepSeed) {
	fixture.t.Helper()
	ctx := context.Background()
	startedAt := fixture.base.Add(seed.offset).UnixNano()
	record := sqlite.AuditRecord{
		AuditID: seed.id, StartedAtNS: startedAt, RouteID: "openai-chat", Protocol: "openai", ParserName: "openai.chat_completions",
		Method: "POST", Path: "/v1/chat/completions", RequestURIEnc: []byte{1}, Mode: "available", APIKeyFPR: seed.key,
	}
	if err := fixture.store.BeginAudit(ctx, record); err != nil {
		fixture.t.Fatal(err)
	}
	status := 200
	length := seed.length
	if length == 0 {
		length = 2 * time.Second
	}
	if err := fixture.store.FinishAudit(ctx, sqlite.AuditFinish{
		AuditID: seed.id, EndedAtNS: startedAt + int64(length), StatusCode: &status,
		ForwardStatus: sqlite.ForwardCompleted, CaptureStatus: sqlite.CaptureComplete, ParseStatus: sqlite.ParseOK,
	}); err != nil {
		fixture.t.Fatal(err)
	}
	model := seed.model
	if model == "" {
		model = "gpt-4.1"
	}
	role := seed.role
	if role == "" {
		role = "main"
	}
	client := "custom"
	version := seed.version
	if version == 0 {
		version = 1
	}
	row := sqlite.AnalysisRow{
		AuditID: seed.id, AnalysisVersion: version, AnalyzedAtNS: startedAt + 1, Protocol: "openai", Model: &model, StartedAtNS: startedAt,
		UncachedInput: seed.uncached, CacheRead: seed.cacheRead, Output: seed.output,
		EstSystem: seed.system, EstUser: seed.user, RespKinds: insights.KindText | insights.KindToolCall,
		TurnStart: seed.turnStart, EventFlags: seed.events, AgentClient: &client, AgentRole: &role,
		AgentNodeFPR: seed.node, AgentParentFPR: seed.parent, AgentRootFPR: seed.root,
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
	if seed.detail != nil {
		plaintext, err := json.Marshal(seed.detail)
		if err != nil {
			fixture.t.Fatal(err)
		}
		aad, err := security.AAD(seed.id, "analysis_detail", strconv.Itoa(version))
		if err != nil {
			fixture.t.Fatal(err)
		}
		if row.DetailEnc, err = fixture.cipher.Encrypt(aad, plaintext); err != nil {
			fixture.t.Fatal(err)
		}
	}
	if err := fixture.store.SaveAnalysis(ctx, row); err != nil {
		fixture.t.Fatal(err)
	}
}

func (fixture *insightsFixture) rangeNS() (*int64, *int64) {
	from, to := fixture.base.Add(-time.Hour).UnixNano(), fixture.base.Add(time.Hour).UnixNano()
	return &from, &to
}

func scopeFor(key []byte) *Scope { return &Scope{Fingerprint: key} }

var (
	keyOwn   = fingerprint(0x01)
	keyOther = fingerprint(0x02)
)

// seedWorld mirrors a shared agent session: the other key contributes a step to
// the caller's session and tree and owns one session and tree outright.
func (fixture *insightsFixture) seedWorld() {
	rootOwn, rootOther := fingerprint(0xa0), fingerprint(0xb0)
	fixture.seed(stepSeed{id: "own-1", offset: 0, key: keyOwn, session: testSessionShared, root: rootOwn, node: fingerprint(0x11),
		uncached: i64(100), cacheRead: i64(900), output: i64(50), turnStart: true, stop: "tool_use", system: 300, user: 100, length: 4 * time.Second})
	fixture.seed(stepSeed{id: "own-2", offset: 10 * time.Second, key: keyOwn, session: testSessionShared, root: rootOwn, node: fingerprint(0x11),
		uncached: i64(50), cacheRead: i64(1000), output: i64(20), prev: "own-1", events: insights.EventModelSwitch | insights.EventCompaction,
		system: 300, user: 150, model: "mystery-model"})
	fixture.seed(stepSeed{id: "other-1", offset: 20 * time.Second, key: keyOther, session: testSessionShared, root: rootOwn, node: fingerprint(0x12),
		parent: fingerprint(0x11), role: "subagent", uncached: i64(7000), output: i64(700), system: 5000})
	fixture.seed(stepSeed{id: "own-sub", offset: 30 * time.Second, key: keyOwn, session: "agt_bbbbbbbbbbbbbbbbbbbbbbbb", root: rootOwn, node: fingerprint(0x13),
		parent: fingerprint(0x99), role: "subagent", turnStart: true, uncached: i64(10), cacheRead: i64(20), output: i64(5), system: 10})
	fixture.seed(stepSeed{id: "other-2", offset: 40 * time.Second, key: keyOther, session: testSessionForeign, root: rootOther, node: fingerprint(0x14),
		uncached: i64(4000), output: i64(400), system: 4000})
}

func TestInsightsOverviewTotalsCostAndDays(t *testing.T) {
	t.Parallel()
	fixture := newInsightsFixture(t, nil)
	fixture.seedWorld()
	from, to := fixture.rangeNS()

	response, err := fixture.service.Overview(context.Background(), OverviewQuery{FromNS: from, ToNS: to, GroupBy: "model", Scope: scopeFor(keyOwn)})
	if err != nil {
		t.Fatal(err)
	}
	totals := response.Totals
	if totals.Requests != 3 || totals.UncachedInput != 160 || totals.CacheRead != 1920 || totals.Output != 75 || totals.PromptTotal != 2080 {
		t.Fatalf("totals = %+v", totals)
	}
	if totals.CacheHitRate == nil || *totals.CacheHitRate != 1920.0/2080.0 {
		t.Fatalf("cache hit rate = %v", totals.CacheHitRate)
	}
	// own-2 uses a model without a price; the other two are gpt-4.1.
	if totals.UnpricedRequests != 1 || totals.EstimatedCostUSD == nil {
		t.Fatalf("pricing = %+v", totals)
	}
	want := (100*2.0 + 900*0.5 + 50*8.0 + 10*2.0 + 20*0.5 + 5*8.0) / 1e6
	if diff := *totals.EstimatedCostUSD - want; diff > 1e-12 || diff < -1e-12 {
		t.Fatalf("cost = %v, want %v", *totals.EstimatedCostUSD, want)
	}
	if response.Sessions != 2 || response.Trees != 1 {
		t.Fatalf("sessions/trees = %d %d", response.Sessions, response.Trees)
	}
	if len(response.Groups) != 2 || response.Groups[0].Key != "gpt-4.1" && response.Groups[0].Key != "mystery-model" {
		t.Fatalf("groups = %+v", response.Groups)
	}
	if len(response.Daily) != 1 || response.Daily[0].Day != "2026-10-10" || response.Daily[0].Usage.Requests != 3 {
		t.Fatalf("daily = %+v", response.Daily)
	}
	if len(response.Heatmap) != HeatmapDays || response.Heatmap[HeatmapDays-1].Day != "2026-10-10" || response.Heatmap[HeatmapDays-1].Requests != 3 ||
		response.Heatmap[0].Day != "2026-08-16" {
		t.Fatalf("heatmap = first %+v last %+v", response.Heatmap[0], response.Heatmap[HeatmapDays-1])
	}
	if response.Mix.Sum() == 0 {
		t.Fatalf("mix = %+v", response.Mix)
	}

	// An administrator sees every key, and may group by caller.
	admin, err := fixture.service.Overview(context.Background(), OverviewQuery{FromNS: from, ToNS: to, GroupBy: "caller"})
	if err != nil || admin.Totals.Requests != 5 || admin.Sessions != 3 || admin.Trees != 1 {
		t.Fatalf("admin overview = %+v %v", admin, err)
	}
}

func TestInsightsOverviewValidation(t *testing.T) {
	t.Parallel()
	fixture := newInsightsFixture(t, nil)
	from, to := fixture.rangeNS()
	tooEarly := *to - int64(401*24*time.Hour)
	negative := int64(-5)
	for name, query := range map[string]OverviewQuery{
		"range too long":            {FromNS: &tooEarly, ToNS: to},
		"reversed":                  {FromNS: to, ToNS: from},
		"negative":                  {FromNS: &negative, ToNS: to},
		"tz low":                    {TZOffsetMin: -841},
		"tz high":                   {TZOffsetMin: 841},
		"unknown group":             {GroupBy: "user_agent"},
		"developer group by caller": {GroupBy: "caller", Scope: scopeFor(keyOwn)},
		"developer group by token":  {GroupBy: "token", Scope: scopeFor(keyOwn)},
		"malformed scope":           {Scope: &Scope{Fingerprint: []byte{1}}},
	} {
		if _, err := fixture.service.Overview(context.Background(), query); !errors.Is(err, ErrInvalidQuery) {
			t.Errorf("%s: err = %v, want ErrInvalidQuery", name, err)
		}
	}
	maximum := *to - int64(MaxInsightsRange)
	for _, offset := range []int{-840, 0, 840} {
		if _, err := fixture.service.Overview(context.Background(), OverviewQuery{FromNS: &maximum, ToNS: to, TZOffsetMin: offset}); err != nil {
			t.Errorf("offset %d with the maximum range: %v", offset, err)
		}
	}
	// Default range is the trailing seven days.
	response, err := fixture.service.Overview(context.Background(), OverviewQuery{})
	if err != nil || response.ToNS-response.FromNS != int64(DefaultInsightsRange) {
		t.Fatalf("default range = %d %v", response.ToNS-response.FromNS, err)
	}
	if response.GroupBy != "model" {
		t.Fatalf("default group_by = %q", response.GroupBy)
	}
}

func TestInsightsSessionsAreScopedPagedAndHideCallerFromDevelopers(t *testing.T) {
	t.Parallel()
	fixture := newInsightsFixture(t, nil)
	fixture.seedWorld()
	from, to := fixture.rangeNS()

	page, err := fixture.service.Sessions(context.Background(), SessionsQuery{FromNS: from, ToNS: to, Limit: 1, Scope: scopeFor(keyOwn)})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.NextCursor == "" || page.Items[0].SessionID != "agt_bbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Fatalf("first page = %+v", page)
	}
	if page.Items[0].Caller != nil {
		t.Fatal("developer card exposes the caller")
	}
	second, err := fixture.service.Sessions(context.Background(), SessionsQuery{FromNS: from, ToNS: to, Limit: 1, Cursor: page.NextCursor, Scope: scopeFor(keyOwn)})
	if err != nil || len(second.Items) != 1 || second.NextCursor != "" {
		t.Fatalf("second page = %+v %v", second, err)
	}
	card := second.Items[0]
	if card.SessionID != testSessionShared || card.Steps != 2 || card.Turns != 1 || card.Usage.Requests != 2 || card.Usage.PromptTotal != 2050 {
		t.Fatalf("shared card counts the other key's step: %+v", card)
	}
	if card.TreeID == "" || card.Subagents != 1 || card.LastPrompt == nil || *card.LastPrompt != 1050 || card.LastEstimate.Sum() != 1050 {
		t.Fatalf("shared card details = %+v", card)
	}
	if card.ContextWindow != nil && len(card.Models) == 0 {
		t.Fatalf("models = %+v", card)
	}

	for name, query := range map[string]SessionsQuery{
		"bad sort":   {Sort: "newest"},
		"bad limit":  {Limit: 101},
		"neg limit":  {Limit: -1},
		"bad cursor": {Cursor: "not-a-cursor"},
	} {
		if _, err := fixture.service.Sessions(context.Background(), query); !errors.Is(err, ErrInvalidQuery) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// A cursor minted for one ordering must not be accepted by another.
	if _, err := fixture.service.Sessions(context.Background(), SessionsQuery{Sort: "tokens", Cursor: page.NextCursor, FromNS: from, ToNS: to}); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("cross-sort cursor accepted: %v", err)
	}

	admin, err := fixture.service.Sessions(context.Background(), SessionsQuery{FromNS: from, ToNS: to, Sort: "tokens"})
	if err != nil || len(admin.Items) != 3 || admin.Items[0].SessionID != testSessionShared || admin.Items[0].Steps != 3 {
		t.Fatalf("admin sessions = %+v %v", admin, err)
	}
}

func TestInsightsTrendTurnsEventsGapsAndScope(t *testing.T) {
	t.Parallel()
	fixture := newInsightsFixture(t, nil)
	fixture.seedWorld()
	ctx := context.Background()

	trend, err := fixture.service.Trend(ctx, testSessionShared, scopeFor(keyOwn))
	if err != nil {
		t.Fatal(err)
	}
	if len(trend.Steps) != 2 || trend.Truncated || trend.TreeID == "" {
		t.Fatalf("trend = %+v", trend)
	}
	first, second := trend.Steps[0], trend.Steps[1]
	if first.AuditID != "own-1" || first.Turn != 1 || !first.TurnStart || second.AuditID != "own-2" || second.Turn != 1 {
		t.Fatalf("turn numbering = %+v / %+v", first, second)
	}
	if first.ClientGapMS != nil {
		t.Fatalf("first step gap = %v", *first.ClientGapMS)
	}
	// own-1 ends 4s after it starts and ended with tool_use; own-2 starts at 10s.
	if second.ClientGapMS == nil || *second.ClientGapMS != 6000 {
		t.Fatalf("client gap = %v", second.ClientGapMS)
	}
	if len(second.Events) != 2 || second.Events[0] != "model_switch" || second.Events[1] != "compaction" {
		t.Fatalf("events = %v", second.Events)
	}
	if len(first.ResponseKinds) != 2 || first.ResponseKinds[0] != "tool_call" || first.ResponseKinds[1] != "text" {
		t.Fatalf("kinds = %v", first.ResponseKinds)
	}
	if first.PromptTotal == nil || *first.PromptTotal != 1000 || first.CostUSD == nil || second.CostUSD != nil {
		t.Fatalf("usage/cost = %+v / %+v", first, second)
	}
	if trend.ContextWindow != nil {
		t.Fatalf("unpriced last model must have no window: %v", *trend.ContextWindow)
	}

	// The other key's session is not found for the caller, and the shared one
	// contains only the caller's steps; an administrator sees all three.
	if _, err := fixture.service.Trend(ctx, testSessionForeign, scopeFor(keyOwn)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign session err = %v", err)
	}
	if _, err := fixture.service.Trend(ctx, "agt_dddddddddddddddddddddddd", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing session err = %v", err)
	}
	admin, err := fixture.service.Trend(ctx, testSessionShared, nil)
	if err != nil || len(admin.Steps) != 3 {
		t.Fatalf("admin trend = %+v %v", admin, err)
	}
	for _, bad := range []string{"", "agt_short", "ses_ZZZZZZZZZZZZZZZZZZZZZZZZ", "conv_a/b", "x"} {
		if _, err := fixture.service.Trend(ctx, bad, nil); !errors.Is(err, ErrInvalidQuery) {
			t.Errorf("session id %q: %v", bad, err)
		}
	}
	if _, err := fixture.service.Trend(ctx, "conv_0123abcd", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("conv id format rejected: %v", err)
	}
}

func TestInsightsTreeScopePlaceholdersAndAuxRequests(t *testing.T) {
	t.Parallel()
	fixture := newInsightsFixture(t, nil)
	fixture.seedWorld()
	fixture.seed(stepSeed{id: "own-compact", offset: 35 * time.Second, key: keyOwn, session: "agt_bbbbbbbbbbbbbbbbbbbbbbbb", root: fingerprint(0xa0),
		node: fingerprint(0x13), parent: fingerprint(0x99), role: "compaction", uncached: i64(1)})
	ctx := context.Background()
	treeID := "a0a0a0a0a0a0a0a0a0a0a0a0"

	tree, err := fixture.service.Tree(ctx, treeID, scopeFor(keyOwn))
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]insights.TreeNode{}
	for _, node := range tree.Nodes {
		byID[node.NodeID] = node
	}
	// Visible: own main + own subagent. The other key's node is absent and the
	// subagent's parent (never observed) is a placeholder.
	if len(tree.Nodes) != 3 || tree.Truncated {
		t.Fatalf("nodes = %+v", tree.Nodes)
	}
	main, sub, placeholder := byID["111111111111111111111111"], byID["131313131313131313131313"], byID["999999999999999999999999"]
	if !main.Visible || main.Steps != 2 || main.Usage.Requests != 2 || main.ParentNodeID != "" {
		t.Fatalf("main node = %+v", main)
	}
	if !sub.Visible || sub.Steps != 1 || sub.AuxRequests != 1 || sub.ParentNodeID != "999999999999999999999999" || sub.Role != "subagent" {
		t.Fatalf("sub node = %+v", sub)
	}
	if placeholder.Visible || placeholder.NodeID == "" {
		t.Fatalf("placeholder = %+v", placeholder)
	}
	if _, ok := byID["121212121212121212121212"]; ok {
		t.Fatal("other key's node leaked into the developer tree")
	}
	if _, err := fixture.service.Tree(ctx, "b0b0b0b0b0b0b0b0b0b0b0b0", scopeFor(keyOwn)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign tree err = %v", err)
	}
	admin, err := fixture.service.Tree(ctx, treeID, nil)
	if err != nil || len(admin.Nodes) < 4 {
		t.Fatalf("admin tree = %+v %v", admin, err)
	}
	for _, bad := range []string{"", "xyz", "A0A0A0A0A0A0A0A0A0A0A0A0", "a0a0"} {
		if _, err := fixture.service.Tree(ctx, bad, nil); !errors.Is(err, ErrInvalidQuery) {
			t.Errorf("tree id %q: %v", bad, err)
		}
	}
}

func TestInsightsCompositionRoundTripDiffAndScope(t *testing.T) {
	t.Parallel()
	fixture := newInsightsFixture(t, nil)
	ctx := context.Background()
	root := fingerprint(0xa0)
	previous := &insights.Detail{
		Items: []insights.Item{
			{Index: 0, Category: insights.CategorySystem, Kind: "system", Tokens: 300, Summary: "system prompt"},
			{Index: 1, Category: insights.CategoryUser, Kind: "text", Tokens: 100, Summary: "first question"},
			{Index: 2, Category: insights.CategoryAssistant, Kind: "tool_call", Tokens: 50, Label: "tool-name"},
		},
		Tools:    []insights.ToolDef{{Name: "tool-name", Tokens: 20, Source: "builtin"}},
		ItemFPRs: []string{"f1", "f2", "f3"},
	}
	current := &insights.Detail{
		Items: []insights.Item{
			{Index: 0, Category: insights.CategorySystem, Kind: "system", Tokens: 300},
			{Index: 1, Category: insights.CategoryUser, Kind: "text", Tokens: 100},
			{Index: 2, Category: insights.CategoryToolResult, Kind: "tool_result", Tokens: 400},
			{Index: 3, Category: insights.CategoryUser, Kind: "text", Tokens: 60},
		},
		Tools:    []insights.ToolDef{},
		FileOps:  []insights.FileOp{{Tool: "Read", Op: "read", Path: "/secret/path"}},
		Agent:    insights.AgentIdentity{Client: "custom", Role: "main", NodeID: "raw-node"},
		ItemFPRs: []string{"f1", "f2", "g3", "g4"},
	}
	fixture.seed(stepSeed{id: "prev", key: keyOwn, session: testSessionShared, root: root, node: fingerprint(0x11), uncached: i64(100), cacheRead: i64(350),
		output: i64(10), system: 300, user: 100, detail: previous, version: 1})
	fixture.seed(stepSeed{id: "cur", offset: time.Minute, key: keyOwn, session: testSessionShared, root: root, node: fingerprint(0x11), uncached: i64(200), cacheRead: i64(560),
		output: i64(30), system: 300, user: 160, prev: "prev", detail: current, version: 2, events: insights.EventPrune})
	fixture.seed(stepSeed{id: "foreign", offset: 2 * time.Minute, key: keyOther, session: testSessionForeign, root: fingerprint(0xb0), node: fingerprint(0x14),
		uncached: i64(5), prev: "cur", detail: current})
	fixture.seed(stepSeed{id: "no-detail", offset: 3 * time.Minute, key: keyOwn, uncached: i64(5)})

	response, err := fixture.service.Composition(ctx, "cur", scopeFor(keyOwn))
	if err != nil {
		t.Fatal(err)
	}
	if response.AnalysisVersion != 2 || response.PreviousAuditID != "prev" || response.Model != "gpt-4.1" || len(response.Events) != 1 || response.Events[0] != "prune" {
		t.Fatalf("response = %+v", response)
	}
	changes := []string{}
	for _, item := range response.Items {
		changes = append(changes, item.Change)
	}
	if len(changes) != 4 || changes[0] != "kept" || changes[1] != "kept" || changes[2] != "added" || changes[3] != "added" {
		t.Fatalf("changes = %v", changes)
	}
	if response.Diff == nil || response.Diff.AddedItems != 2 || response.Diff.RemovedItems != 1 ||
		response.Diff.ByCategory.User != 60 || response.Diff.ByCategory.System != 0 {
		t.Fatalf("diff = %+v", response.Diff)
	}
	if len(response.FileOps) != 1 || response.FileOps[0].Path != "/secret/path" || response.Agent.NodeID != "raw-node" {
		t.Fatalf("detail not decrypted: %+v", response)
	}
	if response.PromptTotal == nil || *response.PromptTotal != 760 || response.Anchored == nil || response.Anchored.Sum() != 760 {
		t.Fatalf("anchored = %+v prompt=%v", response.Anchored, response.PromptTotal)
	}
	if response.ContextWindow == nil || *response.ContextWindow != 1047576 {
		t.Fatalf("context window = %v", response.ContextWindow)
	}
	if len(response.Tools) != 0 || response.Tools == nil {
		t.Fatalf("tools = %#v", response.Tools)
	}

	// The first step has no previous step: no diff and no change markers.
	first, err := fixture.service.Composition(ctx, "prev", scopeFor(keyOwn))
	if err != nil || first.Diff != nil || first.PreviousAuditID != "" || first.Items[0].Change != "" {
		t.Fatalf("first composition = %+v %v", first, err)
	}
	// A previous step owned by another key is invisible to the developer but
	// visible to an administrator.
	foreign, err := fixture.service.Composition(ctx, "cur", scopeFor(keyOther))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign composition err = %v (%+v)", err, foreign)
	}
	otherView, err := fixture.service.Composition(ctx, "foreign", scopeFor(keyOther))
	if err != nil || otherView.Diff != nil || otherView.PreviousAuditID != "" {
		t.Fatalf("previous outside scope leaked: %+v %v", otherView, err)
	}
	if _, err := fixture.service.Composition(ctx, "no-detail", nil); err != nil {
		t.Fatalf("row without detail: %v", err)
	}
	if _, err := fixture.service.Composition(ctx, "missing", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing audit err = %v", err)
	}
	if _, err := fixture.service.Composition(ctx, "bad/id", nil); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("bad id err = %v", err)
	}
}

func TestInsightsCompositionRejectsTamperedDetail(t *testing.T) {
	t.Parallel()
	fixture := newInsightsFixture(t, nil)
	ctx := context.Background()
	detail := &insights.Detail{Items: []insights.Item{}, ItemFPRs: []string{}}
	fixture.seed(stepSeed{id: "good", key: keyOwn, uncached: i64(1), detail: detail})
	// Rebind the ciphertext to another audit: the AAD no longer matches.
	row, err := fixture.store.LoadAnalysis(ctx, "good")
	if err != nil {
		t.Fatal(err)
	}
	fixture.seed(stepSeed{id: "bad", offset: time.Second, key: keyOwn, uncached: i64(1)})
	moved, err := fixture.store.LoadAnalysis(ctx, "bad")
	if err != nil {
		t.Fatal(err)
	}
	moved.DetailEnc = row.DetailEnc
	if err := fixture.store.SaveAnalysis(ctx, moved); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Composition(ctx, "bad", nil); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("tampered detail err = %v", err)
	}
	if _, err := fixture.service.Composition(ctx, "good", nil); err != nil {
		t.Fatalf("untouched detail: %v", err)
	}
}

func TestInsightsScheduleAwareCostUsesSlots(t *testing.T) {
	t.Parallel()
	override := filepath.Join(t.TempDir(), "prices.json")
	content := `{"schedules":[{"model":"gpt-4.1","start":"12:00","end":"12:30","multiplier":0.5}]}`
	if err := os.WriteFile(override, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	prices, err := pricing.Load(override)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newInsightsFixture(t, prices)
	// 12:00 is inside the discounted window, 12:40 is not.
	fixture.seed(stepSeed{id: "inside", key: keyOwn, session: testSessionShared, uncached: i64(1_000_000)})
	fixture.seed(stepSeed{id: "outside", offset: 40 * time.Minute, key: keyOwn, session: testSessionShared, uncached: i64(1_000_000)})
	from, to := fixture.rangeNS()
	response, err := fixture.service.Overview(context.Background(), OverviewQuery{FromNS: from, ToNS: to})
	if err != nil || response.Totals.EstimatedCostUSD == nil {
		t.Fatalf("overview = %+v %v", response, err)
	}
	if got, want := *response.Totals.EstimatedCostUSD, 1.0+2.0; got < want-1e-9 || got > want+1e-9 {
		t.Fatalf("cost = %v, want %v", got, want)
	}
}

func TestInsightsAuxiliaryStepsDoNotDefineSessionsAndPlainSessionsAreNotTrees(t *testing.T) {
	t.Parallel()
	fixture := newInsightsFixture(t, nil)
	const (
		sessionMain  = "agt_eeeeeeeeeeeeeeeeeeeeeeee"
		sessionChild = "agt_ffffffffffffffffffffffff"
		sessionPlain = "agt_999999999999999999999999"
	)
	rootTree, rootPlain := fingerprint(0xc0), fingerprint(0xd0)
	fixture.seed(stepSeed{id: "m1", offset: 100 * time.Second, key: keyOwn, session: sessionMain, root: rootTree, node: fingerprint(0x21),
		uncached: i64(500), output: i64(5), turnStart: true, system: 50})
	fixture.seed(stepSeed{id: "m2", offset: 110 * time.Second, key: keyOwn, session: sessionMain, root: rootTree, node: fingerprint(0x21),
		uncached: i64(600), output: i64(5), prev: "m1", system: 60})
	fixture.seed(stepSeed{id: "s1", offset: 120 * time.Second, key: keyOwn, session: sessionChild, root: rootTree, node: fingerprint(0x22), parent: fingerprint(0x21),
		role: "subagent", uncached: i64(300), output: i64(5), turnStart: true, system: 30})
	// Auxiliary steps come last in time, claim to start a turn and carry the
	// "128 of 128k" shape of a compaction request.
	fixture.seed(stepSeed{id: "c-main", offset: 130 * time.Second, key: keyOwn, session: sessionMain, root: rootTree, node: fingerprint(0x21),
		role: "compaction", uncached: i64(128), output: i64(5), turnStart: true, prev: "m2", system: 5})
	fixture.seed(stepSeed{id: "c-child", offset: 140 * time.Second, key: keyOwn, session: sessionChild, root: rootTree, node: fingerprint(0x22), parent: fingerprint(0x21),
		role: "compaction", uncached: i64(128), output: i64(5), turnStart: true, prev: "s1", system: 5})
	fixture.seed(stepSeed{id: "p1", offset: 150 * time.Second, key: keyOwn, session: sessionPlain, root: rootPlain, node: fingerprint(0xd1),
		uncached: i64(40), output: i64(5), turnStart: true, system: 4})
	ctx := context.Background()
	from, to := fixture.rangeNS()

	page, err := fixture.service.Sessions(ctx, SessionsQuery{FromNS: from, ToNS: to, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	cards := map[string]insights.SessionCard{}
	for _, card := range page.Items {
		cards[card.SessionID] = card
	}
	main, child, plain := cards[sessionMain], cards[sessionChild], cards[sessionPlain]
	if main.Role != "main" || main.Turns != 1 || main.Steps != 3 || main.Subagents != 1 || main.TreeID == "" {
		t.Fatalf("main card = %+v", main)
	}
	if main.LastPrompt == nil || *main.LastPrompt != 600 || main.LastEstimate.Sum() != 600 {
		t.Fatalf("main card must show its latest main step: %+v", main)
	}
	if child.Role != "subagent" || child.Turns != 1 || child.LastPrompt == nil || *child.LastPrompt != 300 || child.LastEstimate.Sum() != 300 {
		t.Fatalf("child card = %+v", child)
	}
	if plain.TreeID != "" || plain.Subagents != 0 || plain.Turns != 1 {
		t.Fatalf("a lone node is not an agent tree: %+v", plain)
	}

	trend, err := fixture.service.Trend(ctx, sessionMain, nil)
	if err != nil || len(trend.Steps) != 3 {
		t.Fatalf("trend = %+v %v", trend, err)
	}
	last := trend.Steps[2]
	if last.AuditID != "c-main" || last.TurnStart || last.Turn != 1 || trend.TreeID == "" {
		t.Fatalf("auxiliary step must not start a turn: %+v", last)
	}
	plainTrend, err := fixture.service.Trend(ctx, sessionPlain, nil)
	if err != nil || plainTrend.TreeID != "" {
		t.Fatalf("plain trend tree = %q %v", plainTrend.TreeID, err)
	}

	tree, err := fixture.service.Tree(ctx, "c0c0c0c0c0c0c0c0c0c0c0c0", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range tree.Nodes {
		if node.NodeID == "222222222222222222222222" && (node.LastPrompt == nil || *node.LastPrompt != 300 || node.AuxRequests != 1) {
			t.Fatalf("child node must show its main step: %+v", node)
		}
	}

	overview, err := fixture.service.Overview(ctx, OverviewQuery{FromNS: from, ToNS: to})
	if err != nil || overview.Trees != 1 {
		t.Fatalf("overview trees = %d %v", overview.Trees, err)
	}
}

func TestInsightsOverviewHeatmapEndsOnDayContainingExclusiveBoundary(t *testing.T) {
	t.Parallel()
	fixture := newInsightsFixture(t, nil)
	fixture.seedWorld()
	from := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC).UnixNano()
	to := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC).UnixNano()

	response, err := fixture.service.Overview(context.Background(), OverviewQuery{FromNS: &from, ToNS: &to, GroupBy: "model", Scope: scopeFor(keyOwn)})
	if err != nil {
		t.Fatal(err)
	}
	last := response.Heatmap[HeatmapDays-1]
	if len(response.Heatmap) != HeatmapDays || last.Day != "2026-10-10" || last.Requests != 3 || response.Heatmap[0].Day != "2026-08-16" {
		t.Fatalf("heatmap = first %+v last %+v", response.Heatmap[0], last)
	}
}
