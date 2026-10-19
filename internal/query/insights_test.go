package query

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/insights/models"
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

// newInsightsFixture builds a billing-enabled service; windows overrides the
// embedded context windows like insights.context_windows.
func newInsightsFixture(t *testing.T, windows map[string]int64) *insightsFixture {
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
	table, err := models.Load(windows)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewInsights(store, cipher, table, true, map[string]string{"custom": "My Framework", "": "dropped", "blank": ""})
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
	// corruptDetail stores an undecryptable detail_enc instead of detail.
	corruptDetail bool
	version       int
	link          string // agent_link_source
	// billing, when set, resolves the caller through a token link with this
	// NewAPI billing; quota is only used when billing is "billed".
	billing      string
	quota        int64
	quotaPerUnit float64
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
	finish := sqlite.AuditFinish{
		AuditID: seed.id, EndedAtNS: startedAt + int64(length), StatusCode: &status,
		ForwardStatus: sqlite.ForwardCompleted, CaptureStatus: sqlite.CaptureComplete, ParseStatus: sqlite.ParseOK,
	}
	requestID := "req-" + seed.id
	if seed.billing != "" {
		finish.NewAPIRequestID = &requestID
	}
	if err := fixture.store.FinishAudit(ctx, finish); err != nil {
		fixture.t.Fatal(err)
	}
	if seed.billing != "" {
		link := sqlite.TokenLink{
			AuditID: seed.id, NewAPIRequestID: requestID, NewAPIUserID: 9, Username: "user-" + seed.id,
			NewAPITokenID: 3, TokenName: "token", LinkedAtNS: startedAt + 1, Attempts: 1, BillingState: seed.billing,
		}
		if seed.billing == sqlite.BillingBilled {
			quota, quotaPerUnit, prompt, completion := seed.quota, seed.quotaPerUnit, int64(1), int64(1)
			link.Quota, link.QuotaPerUnit, link.BilledPromptTokens, link.BilledCompletionTokens = &quota, &quotaPerUnit, &prompt, &completion
		}
		if err := fixture.store.UpsertTokenLink(ctx, link); err != nil {
			fixture.t.Fatal(err)
		}
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
	if seed.link != "" {
		row.AgentLinkSource = &seed.link
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
	if seed.corruptDetail {
		row.DetailEnc = []byte("not a ciphertext")
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
		uncached: i64(100), cacheRead: i64(900), output: i64(50), turnStart: true, stop: "tool_use", system: 300, user: 100, length: 4 * time.Second,
		billing: sqlite.BillingBilled, quota: 250000, quotaPerUnit: 500000})
	fixture.seed(stepSeed{id: "own-2", offset: 10 * time.Second, key: keyOwn, session: testSessionShared, root: rootOwn, node: fingerprint(0x11),
		uncached: i64(50), cacheRead: i64(1000), output: i64(20), prev: "own-1", events: insights.EventModelSwitch | insights.EventCompaction,
		system: 300, user: 150, model: "mystery-model", billing: sqlite.BillingUnbilled})
	fixture.seed(stepSeed{id: "other-1", offset: 20 * time.Second, key: keyOther, session: testSessionShared, root: rootOwn, node: fingerprint(0x12),
		parent: fingerprint(0x11), role: "subagent", uncached: i64(7000), output: i64(700), system: 5000,
		billing: sqlite.BillingBilled, quota: 1000000, quotaPerUnit: 500000})
	fixture.seed(stepSeed{id: "own-sub", offset: 30 * time.Second, key: keyOwn, session: "agt_bbbbbbbbbbbbbbbbbbbbbbbb", root: rootOwn, node: fingerprint(0x13),
		parent: fingerprint(0x99), role: "subagent", turnStart: true, uncached: i64(10), cacheRead: i64(20), output: i64(5), system: 10,
		detail: &insights.Detail{Agent: insights.AgentIdentity{Client: "custom", Role: "subagent", NodeID: "raw-sub", ParentID: "raw-parent", Name: "researcher"}}})
	fixture.seed(stepSeed{id: "other-2", offset: 40 * time.Second, key: keyOther, session: testSessionForeign, root: rootOther, node: fingerprint(0x14),
		uncached: i64(4000), output: i64(400), system: 4000, billing: sqlite.BillingBilled, quota: 200000, quotaPerUnit: 400000})
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
	// Only own-1 is billed (250000 / 500000); own-2 is unbilled and own-sub
	// has no caller link. The other key's billing is out of scope.
	if totals.BilledRequests != 1 || totals.UnbilledRequests != 2 || totals.CostUSD == nil || *totals.CostUSD != 0.5 {
		t.Fatalf("billing = %+v", totals)
	}
	if !response.BillingEnabled {
		t.Fatal("billing_enabled = false")
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
	// Cost is exactly the sum of quota / quota_per_unit over billed requests,
	// each with its own conversion snapshot: 0.5 + 2 + 0.5.
	if admin.Totals.BilledRequests != 3 || admin.Totals.UnbilledRequests != 2 || admin.Totals.CostUSD == nil || *admin.Totals.CostUSD != 3 {
		t.Fatalf("admin billing = %+v", admin.Totals)
	}
	var groupCost float64
	for _, group := range admin.Groups {
		if group.Usage.CostUSD != nil {
			groupCost += *group.Usage.CostUSD
		}
		if group.Usage.BilledRequests+group.Usage.UnbilledRequests != group.Usage.Requests {
			t.Fatalf("group counts = %+v", group)
		}
	}
	if groupCost != 3 {
		t.Fatalf("group costs sum to %v", groupCost)
	}
	// Client labels ride on the response, and group_by=client shows them in
	// place of the key; the empty and blank entries were dropped.
	if len(admin.ClientLabels) != 1 || admin.ClientLabels["custom"] != "My Framework" {
		t.Fatalf("client labels = %v", admin.ClientLabels)
	}
	byClient, err := fixture.service.Overview(context.Background(), OverviewQuery{FromNS: from, ToNS: to, GroupBy: "client"})
	if err != nil || len(byClient.Groups) != 1 || byClient.Groups[0].Key != "custom" || byClient.Groups[0].Label != "My Framework" {
		t.Fatalf("client groups = %+v %v", byClient.Groups, err)
	}
	byModel, err := fixture.service.Overview(context.Background(), OverviewQuery{FromNS: from, ToNS: to, GroupBy: "model"})
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range byModel.Groups {
		if group.Label != group.Key {
			t.Fatalf("model group label substituted: %+v", group)
		}
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
	if first.PromptTotal == nil || *first.PromptTotal != 1000 || first.CostUSD == nil || *first.CostUSD != 0.5 || second.CostUSD != nil {
		t.Fatalf("usage/cost = %+v / %+v", first, second)
	}
	if trend.ContextWindow != nil {
		t.Fatalf("unknown last model must have no window: %v", *trend.ContextWindow)
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
	// The compaction step is the subagent's latest request but carries another
	// name: the node name comes from the latest non-auxiliary step.
	fixture.seed(stepSeed{id: "own-compact", offset: 35 * time.Second, key: keyOwn, session: "agt_bbbbbbbbbbbbbbbbbbbbbbbb", root: fingerprint(0xa0),
		node: fingerprint(0x13), parent: fingerprint(0x99), role: "compaction", uncached: i64(1),
		detail: &insights.Detail{Agent: insights.AgentIdentity{Client: "custom", Role: "compaction", Name: "compactor"}}})
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
	if placeholder.Visible || placeholder.NodeID == "" || placeholder.Name != "" {
		t.Fatalf("placeholder = %+v", placeholder)
	}
	// own-sub's detail names the agent; the main node has no detail at all.
	if sub.Name != "researcher" || main.Name != "" {
		t.Fatalf("names = main %q sub %q", main.Name, sub.Name)
	}
	if len(tree.ClientLabels) != 1 || tree.ClientLabels["custom"] != "My Framework" {
		t.Fatalf("tree client labels = %v", tree.ClientLabels)
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

func TestInsightsTreeNamesComeFromDetailsAndSurviveBadOnes(t *testing.T) {
	t.Parallel()
	fixture := newInsightsFixture(t, nil)
	root := fingerprint(0xd0)
	fixture.seed(stepSeed{id: "named-main", offset: 0, key: keyOwn, session: "agt_dddddddddddddddddddddd01", root: root, node: fingerprint(0x21), uncached: i64(1),
		detail: &insights.Detail{Agent: insights.AgentIdentity{Client: "custom", Role: "main", Name: "planner"}}})
	// The main agent's latest step carries no name: the name follows the latest step, not the first.
	fixture.seed(stepSeed{id: "named-main-2", offset: time.Second, key: keyOwn, session: "agt_dddddddddddddddddddddd01", root: root, node: fingerprint(0x21), uncached: i64(1),
		detail: &insights.Detail{Agent: insights.AgentIdentity{Client: "custom", Role: "main"}}})
	fixture.seed(stepSeed{id: "corrupt-child", offset: 2 * time.Second, key: keyOwn, session: "agt_dddddddddddddddddddddd02", root: root, node: fingerprint(0x22),
		parent: fingerprint(0x21), role: "subagent", uncached: i64(1), corruptDetail: true})
	fixture.seed(stepSeed{id: "named-child", offset: 3 * time.Second, key: keyOwn, session: "agt_dddddddddddddddddddddd03", root: root, node: fingerprint(0x23),
		parent: fingerprint(0x21), role: "subagent", uncached: i64(1),
		detail: &insights.Detail{Agent: insights.AgentIdentity{Client: "custom", Role: "subagent", Name: "researcher"}}})

	tree, err := fixture.service.Tree(context.Background(), treeIDOf(root), nil)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]string{}
	for _, node := range tree.Nodes {
		names[node.NodeID] = node.Name
	}
	want := map[string]string{treeIDOf(fingerprint(0x21)): "", treeIDOf(fingerprint(0x22)): "", treeIDOf(fingerprint(0x23)): "researcher"}
	if len(names) != len(want) {
		t.Fatalf("nodes = %+v", tree.Nodes)
	}
	for id, name := range want {
		if names[id] != name {
			t.Errorf("node %s name = %q, want %q", id, names[id], name)
		}
	}
	encoded, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(encoded, []byte(`"name":`)) != 1 || !bytes.Contains(encoded, []byte(`"client_labels":{"custom":"My Framework"}`)) {
		t.Fatalf("tree JSON = %s", encoded)
	}
	// Only the raw ids inside the detail are sensitive; the name is display data
	// and the ids never leave the detail.
	if bytes.Contains(encoded, []byte("raw-")) {
		t.Fatalf("tree JSON leaks raw ids: %s", encoded)
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

func TestInsightsContextWindowOverrides(t *testing.T) {
	t.Parallel()
	fixture := newInsightsFixture(t, map[string]int64{"mystery-model": 32000, "openai/gpt-4.1": 500000})
	fixture.seedWorld()
	ctx := context.Background()
	trend, err := fixture.service.Trend(ctx, testSessionShared, scopeFor(keyOwn))
	if err != nil || trend.ContextWindow == nil || *trend.ContextWindow != 32000 {
		t.Fatalf("override window = %v %v", trend.ContextWindow, err)
	}
	from, to := fixture.rangeNS()
	page, err := fixture.service.Sessions(ctx, SessionsQuery{FromNS: from, ToNS: to})
	if err != nil {
		t.Fatal(err)
	}
	for _, card := range page.Items {
		if card.SessionID == testSessionForeign && (card.ContextWindow == nil || *card.ContextWindow != 500000) {
			t.Fatalf("overridden embedded window = %v", card.ContextWindow)
		}
	}
}

func TestInsightsBillingDisabledIsReported(t *testing.T) {
	t.Parallel()
	fixture := newInsightsFixture(t, nil)
	service, err := NewInsights(fixture.store, fixture.cipher, nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	from, to := fixture.rangeNS()
	ctx := context.Background()
	overview, err := service.Overview(ctx, OverviewQuery{FromNS: from, ToNS: to})
	if err != nil || overview.BillingEnabled || overview.Totals.CostUSD != nil {
		t.Fatalf("overview = %+v %v", overview, err)
	}
	sessions, err := service.Sessions(ctx, SessionsQuery{FromNS: from, ToNS: to})
	if err != nil || sessions.BillingEnabled {
		t.Fatalf("sessions = %+v %v", sessions, err)
	}
	encoded, err := json.Marshal(sessions)
	if err != nil || !bytes.Contains(encoded, []byte(`"billing_enabled":false`)) {
		t.Fatalf("sessions JSON = %s %v", encoded, err)
	}
	// Without labels the field is omitted; the fixture service carries one.
	if bytes.Contains(encoded, []byte(`"client_labels"`)) {
		t.Fatalf("sessions JSON without labels = %s", encoded)
	}
	enabled, err := fixture.service.Sessions(ctx, SessionsQuery{FromNS: from, ToNS: to})
	if err != nil || !enabled.BillingEnabled {
		t.Fatalf("enabled sessions = %+v %v", enabled, err)
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

func TestInsightsTrendTruncationKeepsAbsoluteTurnNumbers(t *testing.T) {
	t.Parallel()
	fixture := newInsightsFixture(t, nil)
	root, node := fingerprint(0xa0), fingerprint(0x11)
	steps := []stepSeed{
		{id: "t-1", turnStart: true},
		{id: "t-2", turnStart: true, role: insights.RoleCompaction}, // auxiliary: never a turn
		{id: "t-3", turnStart: true},
		{id: "t-4"},
		{id: "t-5", turnStart: true},
		{id: "t-6"},
	}
	for index, step := range steps {
		step.offset = time.Duration(index) * time.Minute
		step.key, step.session, step.root, step.node = keyOwn, testSessionShared, root, node
		fixture.seed(step)
	}
	fixture.service.trendLimit = 3

	trend, err := fixture.service.Trend(context.Background(), testSessionShared, scopeFor(keyOwn))
	if err != nil {
		t.Fatal(err)
	}
	if !trend.Truncated || len(trend.Steps) != 3 {
		t.Fatalf("trend = truncated %v with %d steps, want 3 truncated", trend.Truncated, len(trend.Steps))
	}
	want := []struct {
		id        string
		turn      int64
		turnStart bool
	}{{"t-4", 2, false}, {"t-5", 3, true}, {"t-6", 3, false}}
	for index, step := range trend.Steps {
		if step.AuditID != want[index].id || step.Turn != want[index].turn || step.TurnStart != want[index].turnStart {
			t.Errorf("step %d = %s turn %d start %v, want %+v", index, step.AuditID, step.Turn, step.TurnStart, want[index])
		}
	}

	// Without truncation the numbering is unchanged.
	fixture.service.trendLimit = MaxTrendSteps
	full, err := fixture.service.Trend(context.Background(), testSessionShared, scopeFor(keyOwn))
	if err != nil || full.Truncated || full.Steps[3].Turn != 2 || full.Steps[4].Turn != 3 {
		t.Fatalf("full trend = %+v %v", full, err)
	}
}

func TestInsightsHeaderIdentifiedSingleNodeIsNotATree(t *testing.T) {
	t.Parallel()
	fixture := newInsightsFixture(t, nil)
	const lone, pair = "agt_eeeeeeeeeeeeeeeeeeeeeeee", "agt_ffffffffffffffffffffffff"
	rootLone, rootPair := fingerprint(0xe0), fingerprint(0xf0)
	// A main agent that only sent a node header: link_source is "header" but the
	// root has one node and no parent.
	fixture.seed(stepSeed{id: "lone-1", offset: 0, key: keyOwn, session: lone, root: rootLone, node: fingerprint(0xe1), link: "header", turnStart: true, uncached: i64(10), output: i64(1)})
	fixture.seed(stepSeed{id: "lone-2", offset: time.Minute, key: keyOwn, session: lone, root: rootLone, node: fingerprint(0xe1), link: "header", uncached: i64(10), output: i64(1)})
	// A real tree: a subagent names its parent.
	fixture.seed(stepSeed{id: "pair-1", offset: 2 * time.Minute, key: keyOwn, session: pair, root: rootPair, node: fingerprint(0xf1), link: "header", turnStart: true, uncached: i64(10), output: i64(1)})
	fixture.seed(stepSeed{id: "pair-2", offset: 3 * time.Minute, key: keyOwn, session: pair, root: rootPair, node: fingerprint(0xf1), parent: fingerprint(0x99), link: "header", role: "subagent", uncached: i64(10), output: i64(1)})
	ctx := context.Background()
	from, to := fixture.rangeNS()

	overview, err := fixture.service.Overview(ctx, OverviewQuery{FromNS: from, ToNS: to})
	if err != nil || overview.Trees != 1 || overview.Sessions != 2 {
		t.Fatalf("overview trees/sessions = %d/%d %v, want 1/2", overview.Trees, overview.Sessions, err)
	}
	page, err := fixture.service.Sessions(ctx, SessionsQuery{FromNS: from, ToNS: to, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, card := range page.Items {
		switch card.SessionID {
		case lone:
			if card.TreeID != "" || card.Subagents != 0 {
				t.Errorf("lone header node card = %+v, want no tree", card)
			}
		case pair:
			if card.TreeID == "" {
				t.Errorf("parented node card = %+v, want a tree", card)
			}
		}
	}
	loneTrend, err := fixture.service.Trend(ctx, lone, nil)
	if err != nil || loneTrend.TreeID != "" {
		t.Fatalf("lone trend tree = %q %v", loneTrend.TreeID, err)
	}
	pairTrend, err := fixture.service.Trend(ctx, pair, nil)
	if err != nil || pairTrend.TreeID == "" {
		t.Fatalf("parented trend tree = %q %v", pairTrend.TreeID, err)
	}
}

func TestInsightsSubagentCountIgnoresTheTimeRange(t *testing.T) {
	t.Parallel()
	fixture := newInsightsFixture(t, nil)
	root := fingerprint(0xc0)
	fixture.seed(stepSeed{id: "main-1", offset: 0, key: keyOwn, session: testSessionShared, root: root, node: fingerprint(0x21),
		uncached: i64(10), output: i64(5), turnStart: true, system: 10})
	// The subagent ran before the selected range but belongs to the same tree.
	fixture.seed(stepSeed{id: "sub-1", offset: -3 * time.Hour, key: keyOwn, session: "agt_cccccccccccccccccccccccc", root: root,
		node: fingerprint(0x22), parent: fingerprint(0x21), role: "subagent", uncached: i64(10), output: i64(5), system: 10})
	from, to := fixture.rangeNS()

	page, err := fixture.service.Sessions(context.Background(), SessionsQuery{FromNS: from, ToNS: to, Scope: scopeFor(keyOwn)})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("sessions = %+v %v", page, err)
	}
	if card := page.Items[0]; card.TreeID == "" || card.Subagents != 1 {
		t.Fatalf("card tree/subagents = %q/%d, want a tree with 1 subagent", card.TreeID, card.Subagents)
	}
}

func TestInsightsUnbilledRequestsAreCountedNotPriced(t *testing.T) {
	t.Parallel()
	fixture := newInsightsFixture(t, nil)
	root, node := fingerprint(0xc0), fingerprint(0x21)
	// Billing does not depend on reported usage: a billed request without
	// usage still costs, and a request with usage but no billing does not.
	fixture.seed(stepSeed{id: "billed", offset: 0, key: keyOwn, session: testSessionShared, root: root, node: node,
		turnStart: true, billing: sqlite.BillingBilled, quota: 1000, quotaPerUnit: 500000})
	fixture.seed(stepSeed{id: "no-link", offset: 10 * time.Second, key: keyOwn, session: testSessionShared, root: root, node: node, prev: "billed",
		uncached: i64(100), output: i64(10)})
	fixture.seed(stepSeed{id: "unbilled", offset: 20 * time.Second, key: keyOwn, session: "agt_bbbbbbbbbbbbbbbbbbbbbbbb",
		root: fingerprint(0xc1), node: fingerprint(0x22), uncached: i64(5), billing: sqlite.BillingUnbilled})
	ctx := context.Background()
	from, to := fixture.rangeNS()
	want := 1000.0 / 500000.0

	overview, err := fixture.service.Overview(ctx, OverviewQuery{FromNS: from, ToNS: to, GroupBy: "model", Scope: scopeFor(keyOwn)})
	if err != nil {
		t.Fatal(err)
	}
	totals := overview.Totals
	if totals.Requests != 3 || totals.BilledRequests != 1 || totals.UnbilledRequests != 2 || totals.CostUSD == nil || *totals.CostUSD != want {
		t.Fatalf("totals = %+v", totals)
	}
	if day := overview.Daily[len(overview.Daily)-1].Usage; day.UnbilledRequests != 2 || day.BilledRequests != 1 {
		t.Fatalf("daily = %+v", day)
	}
	if empty := overview.Daily[0].Usage; len(overview.Daily) > 1 && (empty.CostUSD != nil || empty.UnbilledRequests != 0) {
		t.Fatalf("empty day = %+v", empty)
	}
	sessions, err := fixture.service.Sessions(ctx, SessionsQuery{FromNS: from, ToNS: to, Scope: scopeFor(keyOwn)})
	if err != nil {
		t.Fatal(err)
	}
	for _, card := range sessions.Items {
		switch card.SessionID {
		case testSessionShared:
			if card.Usage.BilledRequests != 1 || card.Usage.UnbilledRequests != 1 || card.Usage.CostUSD == nil || *card.Usage.CostUSD != want {
				t.Fatalf("shared card = %+v", card.Usage)
			}
		default:
			if card.Usage.BilledRequests != 0 || card.Usage.UnbilledRequests != 1 || card.Usage.CostUSD != nil {
				t.Fatalf("unbilled card = %+v", card.Usage)
			}
		}
	}

	tree, err := fixture.service.Tree(ctx, "c0c0c0c0c0c0c0c0c0c0c0c0", scopeFor(keyOwn))
	if err != nil || len(tree.Nodes) != 1 || tree.Nodes[0].Usage.UnbilledRequests != 1 || tree.Nodes[0].Usage.CostUSD == nil || *tree.Nodes[0].Usage.CostUSD != want {
		t.Fatalf("tree = %+v %v", tree, err)
	}

	trend, err := fixture.service.Trend(ctx, testSessionShared, scopeFor(keyOwn))
	if err != nil || len(trend.Steps) != 2 {
		t.Fatalf("trend = %+v %v", trend, err)
	}
	if trend.Steps[0].CostUSD == nil || *trend.Steps[0].CostUSD != want || trend.Steps[1].CostUSD != nil {
		t.Fatalf("step costs = %v / %v", trend.Steps[0].CostUSD, trend.Steps[1].CostUSD)
	}
}

func TestInsightsDeveloperScopeHidesOtherKeysBilling(t *testing.T) {
	t.Parallel()
	fixture := newInsightsFixture(t, nil)
	fixture.seedWorld()
	ctx := context.Background()
	from, to := fixture.rangeNS()
	// The other key owns a billed step inside the caller's shared session and
	// tree; the caller sees neither its cost nor its billed count.
	sessions, err := fixture.service.Sessions(ctx, SessionsQuery{FromNS: from, ToNS: to, Scope: scopeFor(keyOwn)})
	if err != nil {
		t.Fatal(err)
	}
	for _, card := range sessions.Items {
		if card.SessionID == testSessionShared && (card.Usage.BilledRequests != 1 || card.Usage.CostUSD == nil || *card.Usage.CostUSD != 0.5) {
			t.Fatalf("shared card leaks billing: %+v", card.Usage)
		}
	}
	tree, err := fixture.service.Tree(ctx, treeIDOf(fingerprint(0xa0)), scopeFor(keyOwn))
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range tree.Nodes {
		if node.Usage.CostUSD != nil && *node.Usage.CostUSD != 0.5 {
			t.Fatalf("tree node leaks billing: %+v", node)
		}
	}
	trend, err := fixture.service.Trend(ctx, testSessionShared, scopeFor(keyOwn))
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range trend.Steps {
		if step.AuditID == "other-1" {
			t.Fatal("trend exposes the other key's step")
		}
	}
	other, err := fixture.service.Overview(ctx, OverviewQuery{FromNS: from, ToNS: to, Scope: scopeFor(keyOther)})
	if err != nil || other.Totals.BilledRequests != 2 || other.Totals.CostUSD == nil || *other.Totals.CostUSD != 2.5 {
		t.Fatalf("other key overview = %+v %v", other.Totals, err)
	}
}
func TestInsightsTrendContextWindowIgnoresAuxiliaryModel(t *testing.T) {
	t.Parallel()
	fixture := newInsightsFixture(t, nil)
	root, node := fingerprint(0xd0), fingerprint(0x31)
	fixture.seed(stepSeed{id: "main", offset: 0, key: keyOwn, session: testSessionShared, root: root, node: node, uncached: i64(10), turnStart: true})
	fixture.seed(stepSeed{id: "title", offset: 10 * time.Second, key: keyOwn, session: testSessionShared, root: root, node: node,
		role: "title", model: "mystery-model", uncached: i64(1)})
	ctx := context.Background()

	trend, err := fixture.service.Trend(ctx, testSessionShared, scopeFor(keyOwn))
	if err != nil {
		t.Fatal(err)
	}
	want := fixture.service.windows.ContextWindow("gpt-4.1")
	if want == nil || trend.ContextWindow == nil || *trend.ContextWindow != *want {
		t.Fatalf("context window = %v, want %v", trend.ContextWindow, want)
	}

	// Only auxiliary steps: fall back to the last row.
	fixture.seed(stepSeed{id: "only-aux", offset: 20 * time.Second, key: keyOwn, session: "agt_bbbbbbbbbbbbbbbbbbbbbbbb",
		root: fingerprint(0xd1), node: fingerprint(0x32), role: "title", uncached: i64(1)})
	trend, err = fixture.service.Trend(ctx, "agt_bbbbbbbbbbbbbbbbbbbbbbbb", scopeFor(keyOwn))
	if err != nil || trend.ContextWindow == nil || *trend.ContextWindow != *want {
		t.Fatalf("aux-only window = %v %v", trend.ContextWindow, err)
	}
}
