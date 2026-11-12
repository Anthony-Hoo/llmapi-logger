package sessionanalysis

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/config"
	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/storage"
)

// fakeProjects books sessions by agent-tree root, like the organisation
// report service does from its catalog.
type fakeProjects struct {
	byRoot map[string]orgreport.SessionProject
	names  map[int64]string
	groups []orgreport.ReportGroup
	fail   bool
	calls  int
}

func (projects *fakeProjects) ReportGroups() []orgreport.ReportGroup { return projects.groups }

func (projects *fakeProjects) ResolveSession(_ context.Context, root, _ []byte) (orgreport.SessionProject, error) {
	projects.calls++
	if projects.fail {
		return orgreport.SessionProject{}, errors.New("catalog unavailable")
	}
	if project, ok := projects.byRoot[hex.EncodeToString(root)]; ok {
		return project, nil
	}
	return orgreport.SessionProject{Known: true, Project: orgreport.ProjectNoContext}, nil
}

func (projects *fakeProjects) ProjectName(id int64) string { return projects.names[id] }

func (store *memoryStore) ListSessionProjects(_ context.Context, sinceNS, computedBeforeNS int64, limit int) ([]storage.SessionProjectRef, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	out := make([]storage.SessionProjectRef, 0)
	for _, signals := range store.signals {
		if signals.LastNS >= sinceNS && signals.ComputedAtNS < computedBeforeNS {
			out = append(out, storage.SessionProjectRef{
				SessionKey: signals.SessionKey, AgentRootFPR: signals.AgentRootFPR, APIKeyFPR: signals.APIKeyFPR,
				ProjectID: signals.ProjectID, Bucket: signals.Bucket,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].SessionKey, out[j].SessionKey) < 0 })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (store *memoryStore) UpdateSessionProjects(_ context.Context, refs []storage.SessionProjectRef) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, ref := range refs {
		key := hex.EncodeToString(ref.SessionKey)
		if signals, ok := store.signals[key]; ok && signals.Bucket != storage.BucketService {
			signals.ProjectID, signals.Bucket = ref.ProjectID, ref.Bucket
			store.signals[key] = signals
		}
	}
	return nil
}

func projectID(signals storage.SessionSignals) int64 {
	if signals.ProjectID == nil {
		return 0
	}
	return *signals.ProjectID
}

// A session is booked to its project when analysed, re-booked when the rules
// change, and keeps signals only while its caller is a service principal.
func TestRunnerBooksSessionsToProjects(t *testing.T) {
	store := newMemoryStore()
	ownKey := bytes.Repeat([]byte{1}, 32)
	store.sessions[hex.EncodeToString(sessionK)] = []storage.SessionAuditRow{
		auditRow("ag1", baseTime, nodeMain, "main", true),
		auditRow("ag2", baseTime.Add(5*time.Minute), nodeMain, "main", true),
	}
	chatRoot := bytes.Repeat([]byte{0x2a}, 32)
	store.sessions[hex.EncodeToString(chatRoot)] = chatRows("chat1", ownKey, bytes.Repeat([]byte{0x3a}, 32), baseTime.Add(time.Hour))
	views := map[string]*conversation.Conversation{
		"ag2":   convo(user("把导出接口改成流式输出"), answer("好"), user("再补一下接口文档"), answer("完成")),
		"chat1": convo(user("解释一下这段正则"), answer("……")),
	}
	projects := &fakeProjects{names: map[int64]string{10: "orders", 11: "billing"}, byRoot: map[string]orgreport.SessionProject{
		hex.EncodeToString(sessionK): {Known: true, Project: 10, Name: "orders", Level: orgreport.LevelRemote},
	}}
	now := baseTime.Add(24 * time.Hour)
	vocab, insightsVocab := testVocabularies(t)
	cipher := testCipher(t)
	runner, err := NewRunner(Options{
		Config: config.SessionAnalysisConfig{RunAt: "02:00", SessionIdleMinutes: 120, MinUserTurns: 2, MinActiveSeconds: 1, Pack: config.SessionAnalysisPack{MaxTokens: 6000}},
		Store:  store, Loader: &fakeLoader{views: views}, Vocabulary: vocab, Insights: insightsVocab,
		Fingerprints: testFingerprinter{}, Cipher: cipher, Location: time.UTC, Projects: projects,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewQueryService(store, runner, cipher, "")
	if err != nil {
		t.Fatal(err)
	}
	service.UseProjects(projects)
	sessionLine := func(id string) string {
		t.Helper()
		pack, err := service.Pack(context.Background(), id, nil, Viewer{Role: "admin"})
		if err != nil {
			t.Fatal(err)
		}
		line, _, _ := strings.Cut(pack.Text, "\n")
		return line
	}
	agentID, chatID := analysisID(sessionK, ownKey), analysisID(chatRoot, ownKey)
	run := func() storage.SessionAnalysisRun {
		t.Helper()
		summary, err := runner.RunOnce(context.Background(), TriggerManual)
		if err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Hour)
		return summary
	}

	run()
	agent, chat := store.signals[agentID], store.signals[chatID]
	if projectID(agent) != 10 || agent.Bucket != storage.BucketAttributed || !agent.Eligible {
		t.Fatalf("agent booking = %d %q eligible=%v", projectID(agent), agent.Bucket, agent.Eligible)
	}
	if chat.ProjectID != nil || chat.Bucket != storage.BucketNoContext || len(chat.DigestBucket) == 0 {
		t.Fatalf("chat booking = %v %q digest=%d", chat.ProjectID, chat.Bucket, len(chat.DigestBucket))
	}
	firstPack, ok := store.packs[agentID]
	if !ok || len(store.textFPRs[agentID]) == 0 || len(store.packs) != 2 {
		t.Fatalf("packs = %d, own pack %v, fingerprints %d", len(store.packs), ok, len(store.textFPRs[agentID]))
	}
	// The pack names the project and the level it matched at; a chat digest
	// spans sessions and names none.
	if line := sessionLine(agentID); !strings.HasPrefix(line, "[会话] 类型=agent 客户端=Codex 项目=orders(remote) 模型=") {
		t.Fatalf("session line = %s", line)
	}
	if line := sessionLine(chatID); strings.Contains(line, "项目=") {
		t.Fatalf("digest line = %s", line)
	}
	if item := service.sessionItem(agent, true); item.ProjectID != 10 || item.Project != "orders" || item.Bucket != storage.BucketAttributed {
		t.Fatalf("item = %d %q %q", item.ProjectID, item.Project, item.Bucket)
	}

	// A rule change re-books the session without analysing it again.
	projects.byRoot[hex.EncodeToString(sessionK)] = orgreport.SessionProject{Known: true, Project: 11, Name: "billing", Level: orgreport.LevelRoot}
	if summary := run(); summary.Candidates != 0 || summary.Analyzed != 0 {
		t.Fatalf("rebooking analysed sessions: %+v", summary)
	}
	if agent = store.signals[agentID]; projectID(agent) != 11 || agent.Bucket != storage.BucketAttributed || store.packs[agentID].BuiltAtNS != firstPack.BuiltAtNS {
		t.Fatalf("after rule change: %d %q", projectID(agent), agent.Bucket)
	}
	// The pack keeps the name it was built with; the stored booking is current.
	if line := sessionLine(agentID); !strings.Contains(line, "项目=orders(remote)") {
		t.Fatalf("rebooking rebuilt the pack: %s", line)
	}

	// No verdict (identity extraction still running) keeps the stored booking.
	projects.byRoot[hex.EncodeToString(sessionK)] = orgreport.SessionProject{Project: orgreport.ProjectNoContext}
	run()
	if agent = store.signals[agentID]; projectID(agent) != 11 || agent.Bucket != storage.BucketAttributed {
		t.Fatalf("unknown booking overwrote: %d %q", projectID(agent), agent.Bucket)
	}

	// A resolver failure leaves everything as it was.
	projects.fail = true
	if summary := run(); summary.SkipReasons != `{"project_refresh_error":1}` {
		t.Fatalf("skip reasons = %s", summary.SkipReasons)
	}
	projects.fail = false

	// The caller becomes a service principal: both sessions are analysed again
	// and keep signals only.
	projects.byRoot[hex.EncodeToString(sessionK)] = orgreport.SessionProject{Known: true, Project: 11, Name: "billing", Service: true}
	projects.byRoot[hex.EncodeToString(chatRoot)] = orgreport.SessionProject{Known: true, Project: orgreport.ProjectNoContext, Service: true}
	run()
	agent, chat = store.signals[agentID], store.signals[chatID]
	if agent.Bucket != storage.BucketService || agent.Eligible || agent.SkipReason != SkipService || projectID(agent) != 11 {
		t.Fatalf("service agent = %+v", agent)
	}
	if chat.Bucket != storage.BucketService || chat.SkipReason != SkipService || len(chat.DigestBucket) != 0 {
		t.Fatalf("service chat = %q %q digest=%d", chat.Bucket, chat.SkipReason, len(chat.DigestBucket))
	}
	if len(store.packs) != 0 || len(store.textFPRs[agentID]) != 0 {
		t.Fatalf("service sessions kept %d packs, %d fingerprints", len(store.packs), len(store.textFPRs[agentID]))
	}

	// Classified human again while its project is not known yet: the session
	// stops being a service at once and gets its pack back without a booking.
	projects.byRoot[hex.EncodeToString(sessionK)] = orgreport.SessionProject{Project: orgreport.ProjectNoContext}
	run()
	if agent = store.signals[agentID]; agent.Bucket != "" || agent.ProjectID != nil || !agent.Eligible || agent.SkipReason != "" {
		t.Fatalf("reclassified without a verdict: %q %v eligible=%v %q", agent.Bucket, agent.ProjectID, agent.Eligible, agent.SkipReason)
	}
	if _, ok := store.packs[agentID]; !ok || len(store.textFPRs[agentID]) == 0 {
		t.Fatal("reclassified session has no pack or fingerprints")
	}
	// The booking arrives later; the chat is human again too and its digest
	// comes back.
	projects.byRoot[hex.EncodeToString(sessionK)] = orgreport.SessionProject{Known: true, Project: 11, Name: "billing", Level: orgreport.LevelRoot}
	delete(projects.byRoot, hex.EncodeToString(chatRoot))
	run()
	agent, chat = store.signals[agentID], store.signals[chatID]
	if agent.Bucket != storage.BucketAttributed || !agent.Eligible || chat.Bucket != storage.BucketNoContext || len(store.packs) != 2 {
		t.Fatalf("after reclassification: %q eligible=%v, chat %q, packs %d", agent.Bucket, agent.Eligible, chat.Bucket, len(store.packs))
	}
}

// Without organisation reports nothing is booked and nothing changes.
func TestRunnerWithoutProjectsStoresNoBooking(t *testing.T) {
	store := newMemoryStore()
	seedAgentSession(store)
	runner := facetRunner(t, store, nil, baseTime.Add(48*time.Hour))
	if _, err := runner.RunOnce(context.Background(), TriggerManual); err != nil {
		t.Fatal(err)
	}
	for _, signals := range store.signals {
		if signals.ProjectID != nil || signals.Bucket != "" {
			t.Fatalf("booking without org reports: %v %q", signals.ProjectID, signals.Bucket)
		}
	}
}

// With organisation reports, weekly statistics also exist per project and
// per project group; a week with a single caller keeps counts only.
func TestProjectAndGroupReports(t *testing.T) {
	store := newMemoryStore()
	views := map[string]*conversation.Conversation{}
	day := time.Date(2026, 11, 3, 2, 0, 0, 0, time.UTC)
	keyOne, keyTwo := bytes.Repeat([]byte{0x0a}, 32), bytes.Repeat([]byte{0x0b}, 32)
	roots := make([][]byte, 0, 3)
	for index, caller := range []struct {
		key  []byte
		user int64
	}{{keyOne, 5}, {keyTwo, 6}, {keyOne, 5}} {
		root := bytes.Repeat([]byte{byte(0x50 + index)}, 32)
		roots = append(roots, root)
		node := bytes.Repeat([]byte{byte(0x60 + index)}, 32)
		prefix := "pr" + string(rune('a'+index))
		at := day.Add(time.Duration(index) * time.Hour)
		rows := []storage.SessionAuditRow{auditRow(prefix+"1", at, node, "main", true), auditRow(prefix+"2", at.Add(10*time.Minute), node, "main", true)}
		for position := range rows {
			user, quota, unit := caller.user, int64(500000*(index+1)), 1000000.0
			rows[position].APIKeyFPR, rows[position].NewAPIUserID = caller.key, &user
			rows[position].Quota, rows[position].QuotaPerUnit = &quota, &unit
		}
		store.sessions[hex.EncodeToString(root)] = rows
		// Every session writes a file and never verifies it, so each scope
		// has "costliest problem sessions" to show.
		views[prefix+"2"] = convo(
			user("修一下导出接口的分页。提交前先跑一遍全部单元测试"),
			call("w"+prefix, "apply_patch", "*** Begin Patch\n*** Update File: export.go\n*** End Patch"),
			result("w"+prefix, "Success."),
			user("好的，再看一下文档"), answer("完成"))
	}
	projects := &fakeProjects{
		names: map[int64]string{10: "orders", 11: "billing"},
		byRoot: map[string]orgreport.SessionProject{
			hex.EncodeToString(roots[0]): {Known: true, Project: 10, Name: "orders", Level: orgreport.LevelRemote},
			hex.EncodeToString(roots[1]): {Known: true, Project: 10, Name: "orders", Level: orgreport.LevelRemote},
			hex.EncodeToString(roots[2]): {Known: true, Project: 11, Name: "billing", Level: orgreport.LevelRoot},
		},
		groups: []orgreport.ReportGroup{{ID: 1, Name: "payments", Members: []int64{5, 6}}, {ID: 2, Name: "solo", Members: []int64{6}}, {ID: 3, Name: "empty"}},
	}
	vocab, insightsVocab := testVocabularies(t)
	cipher := testCipher(t)
	now := day.Add(48 * time.Hour)
	runner, err := NewRunner(Options{
		Config: testRunnerConfig(),
		Store:  store, Loader: &fakeLoader{views: views}, Vocabulary: vocab, Insights: insightsVocab,
		Fingerprints: testFingerprinter{}, Cipher: cipher, Location: time.UTC, Projects: projects,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// The second run writes narratives with the suggestions the first built.
	for range 2 {
		if _, err := runner.RunOnce(ctx, TriggerManual); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Hour)
	}
	service, err := NewQueryService(store, runner, cipher, "")
	if err != nil {
		t.Fatal(err)
	}
	service.now = runner.options.Now
	service.UseProjects(projects)
	service.UseCalendar(time.UTC, false)

	orders, err := service.Report(ctx, "current", nil, ReportTarget{ProjectID: 10})
	if err != nil {
		t.Fatal(err)
	}
	if orders.Scope != storage.ScopeProject || orders.ScopeID != 10 || orders.ScopeName != "orders" || orders.Stats == nil ||
		orders.Stats.Totals.Sessions != 2 || orders.Stats.Contributors != 2 || orders.Stats.Limited {
		t.Fatalf("orders = %+v stats=%+v", orders, orders.Stats)
	}
	// The two sessions of the project say the same three sentences.
	rule := func(report ReportResponse) *SuggestionItem {
		for index := range report.Suggestions {
			if strings.Contains(report.Suggestions[index].Text, "提交前先跑一遍全部单元测试") {
				return &report.Suggestions[index]
			}
		}
		return nil
	}
	if found := rule(orders); len(orders.Suggestions) != 3 || found == nil || found.Sessions != 2 || found.Status != "open" || len(found.Evidence) != 2 {
		t.Fatalf("orders suggestions = %+v", orders.Suggestions)
	}
	if len(orders.Optimizations) != 2 || orders.Optimizations[0].Project != "orders" {
		t.Fatalf("orders optimizations = %+v", orders.Optimizations)
	}
	// A week without statistics has no caller count: no suggestion texts and
	// no sessions either, although the project has suggestions.
	if earlier, err := service.Report(ctx, "previous", nil, ReportTarget{ProjectID: 10}); err != nil || earlier.Stats != nil || len(earlier.Suggestions) != 0 || len(earlier.Optimizations) != 0 {
		t.Fatalf("project week without statistics = %+v, %v", earlier, err)
	}
	if !strings.Contains(orders.Narrative, "提交前先跑一遍全部单元测试") {
		t.Fatalf("orders narrative = %q", orders.Narrative)
	}
	if len(orders.Projects) != 2 || orders.Projects[0] != (ScopeOption{ID: 10, Name: "orders"}) || orders.Projects[1] != (ScopeOption{ID: 11, Name: "billing"}) ||
		len(orders.Groups) != 3 || orders.Groups[0] != (ScopeOption{ID: 1, Name: "payments"}) {
		t.Fatalf("scopes = %+v / %+v", orders.Projects, orders.Groups)
	}

	// One caller only: counts stay, goals and suggestion texts do not.
	billing, err := service.Report(ctx, "current", nil, ReportTarget{ProjectID: 11})
	if err != nil || billing.Stats == nil || billing.Stats.Totals.Sessions != 1 || billing.Stats.Contributors != 1 || !billing.Stats.Limited ||
		len(billing.Suggestions) != 0 || len(billing.Optimizations) != 0 || strings.Contains(billing.Narrative, "提交前") {
		t.Fatalf("billing = %+v stats=%+v, %v", billing, billing.Stats, err)
	}
	payments, err := service.Report(ctx, "current", nil, ReportTarget{GroupID: 1})
	if err != nil || payments.Scope != storage.ScopeGroup || payments.ScopeName != "payments" || payments.Stats == nil ||
		payments.Stats.Totals.Sessions != 3 || payments.Stats.Contributors != 2 || payments.Stats.Limited || len(payments.Suggestions) != 0 || len(payments.Optimizations) != 3 {
		t.Fatalf("payments = %+v stats=%+v, %v", payments, payments.Stats, err)
	}
	solo, err := service.Report(ctx, "current", nil, ReportTarget{GroupID: 2})
	if err != nil || solo.Stats == nil || solo.Stats.Totals.Sessions != 1 || !solo.Stats.Limited || len(solo.Optimizations) != 0 {
		t.Fatalf("solo = %+v stats=%+v, %v", solo, solo.Stats, err)
	}
	if empty, err := service.Report(ctx, "current", nil, ReportTarget{GroupID: 3}); err != nil || empty.Stats == nil || empty.Stats.Totals.Sessions != 0 || !empty.Stats.Limited {
		t.Fatalf("empty group = %+v, %v", empty, err)
	}
	// The everything and personal scopes are unchanged.
	all, err := service.Report(ctx, "current", nil, ReportTarget{})
	if found := rule(all); err != nil || all.Stats == nil || all.Stats.Totals.Sessions != 3 || all.Stats.Limited || all.Stats.Contributors != 0 || found == nil || found.Sessions != 3 {
		t.Fatalf("all = %+v stats=%+v, %v", all, all.Stats, err)
	}
	own, err := service.Report(ctx, "current", scopeOf(keyOne), ReportTarget{})
	if err != nil || own.Stats == nil || own.Stats.Totals.Sessions != 2 || own.Projects != nil || own.Groups != nil || own.Users != nil {
		t.Fatalf("own = %+v, %v", own, err)
	}
	if len(own.Optimizations) == 0 || own.Optimizations[0].UserID != 0 {
		t.Fatalf("a developer report names a user: %+v", own.Optimizations)
	}

	// An administrator can open one user: every session of that user whatever
	// its project, with the user's own repeated sentences. A single caller
	// does not limit it.
	five, err := service.Report(ctx, "current", nil, ReportTarget{UserID: 5})
	if err != nil || five.Scope != storage.ScopeUser || five.ScopeID != 5 || five.Stats == nil || five.Stats.Totals.Sessions != 2 || five.Stats.Limited {
		t.Fatalf("user 5 = %+v stats=%+v, %v", five, five.Stats, err)
	}
	if found := rule(five); found == nil || found.Sessions != 2 || len(five.Optimizations) != 2 || five.Optimizations[0].UserID != 5 {
		t.Fatalf("user 5 suggestions = %+v optimizations = %+v", five.Suggestions, five.Optimizations)
	}
	if !strings.Contains(five.Narrative, "提交前先跑一遍全部单元测试") {
		t.Fatalf("user 5 narrative = %q", five.Narrative)
	}
	if len(five.Users) != 2 || five.Users[0].ID != 5 || five.Users[1].ID != 6 || len(all.Users) != 2 {
		t.Fatalf("users = %+v / %+v", five.Users, all.Users)
	}
	six, err := service.Report(ctx, "current", nil, ReportTarget{UserID: 6})
	if err != nil || six.Stats == nil || six.Stats.Totals.Sessions != 1 || len(six.Suggestions) != 0 || len(six.Optimizations) != 1 {
		t.Fatalf("user 6 = %+v stats=%+v, %v", six, six.Stats, err)
	}
	// A user without sessions has no report, but the request is valid.
	if nobody, err := service.Report(ctx, "current", nil, ReportTarget{UserID: 99}); err != nil || nobody.Stats != nil || len(nobody.Suggestions) != 0 {
		t.Fatalf("unknown user = %+v, %v", nobody, err)
	}
	if _, err := service.Report(ctx, "current", scopeOf(keyOne), ReportTarget{UserID: 6}); !errors.Is(err, query.ErrInvalidQuery) {
		t.Fatalf("developer opened a user: %v", err)
	}
	if _, err := service.Report(ctx, "current", nil, ReportTarget{ProjectID: 10, UserID: 5}); !errors.Is(err, query.ErrInvalidQuery) {
		t.Fatalf("project and user: %v", err)
	}
	// A user's suggestions are personal: nobody dismisses them here.
	if err := service.DismissSuggestion(ctx, rule(five).ID); !errors.Is(err, query.ErrNotFound) {
		t.Fatalf("dismissed a user suggestion: %v", err)
	}
	// The per-user listing and the user filter of the overview.
	from, to := day.Add(-time.Hour).UnixNano(), day.Add(24*time.Hour).UnixNano()
	listing, err := service.Users(ctx, from, to)
	if err != nil || len(listing.Items) != 2 || *listing.Items[0].UserID != 5 || listing.Items[0].Totals.Sessions != 2 ||
		*listing.Items[1].UserID != 6 || listing.Items[1].Totals.Sessions != 1 {
		t.Fatalf("user listing = %+v, %v", listing, err)
	}
	userSix := int64(6)
	if overview, err := service.Overview(ctx, from, to, nil, &userSix); err != nil || overview.Current.Sessions != 1 {
		t.Fatalf("overview of user 6 = %+v, %v", overview.Current, err)
	}
	if _, err := service.Overview(ctx, from, to, scopeOf(keyOne), &userSix); !errors.Is(err, query.ErrInvalidQuery) {
		t.Fatalf("developer overview of a user: %v", err)
	}
	if _, err := service.Sessions(ctx, SessionsQuery{FromNS: from, ToNS: to, Scope: scopeOf(keyOne), UserID: &userSix}); !errors.Is(err, query.ErrInvalidQuery) {
		t.Fatalf("developer session list of a user: %v", err)
	}

	if _, err := service.Report(ctx, "current", nil, ReportTarget{GroupID: 99}); !errors.Is(err, query.ErrNotFound) {
		t.Fatalf("unknown group: %v", err)
	}
	if _, err := service.Report(ctx, "current", scopeOf(keyOne), ReportTarget{ProjectID: 10}); !errors.Is(err, query.ErrInvalidQuery) {
		t.Fatalf("developer opened a project: %v", err)
	}
	if _, err := service.Report(ctx, "current", nil, ReportTarget{ProjectID: 10, GroupID: 1}); !errors.Is(err, query.ErrInvalidQuery) {
		t.Fatalf("two selectors: %v", err)
	}
	// An administrator can dismiss a project suggestion.
	if err := service.DismissSuggestion(ctx, rule(orders).ID); err != nil {
		t.Fatal(err)
	}
	again, _ := service.Report(ctx, "current", nil, ReportTarget{ProjectID: 10})
	if found := rule(again); found == nil || found.Status != "dismissed" {
		t.Fatalf("project suggestions = %+v", again.Suggestions)
	}
	all, _ = service.Report(ctx, "current", nil, ReportTarget{})
	if found := rule(all); found == nil || found.Status != "open" {
		t.Fatalf("dismissing a project suggestion touched the all-keys one: %+v", found)
	}
	// Without organisation reports the selectors do not exist.
	plain, err := NewQueryService(store, runner, cipher, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plain.Report(ctx, "current", nil, ReportTarget{ProjectID: 10}); !errors.Is(err, query.ErrNotFound) {
		t.Fatalf("project report without org reports: %v", err)
	}
}

func TestWeeksCanStartOnSunday(t *testing.T) {
	wednesday := time.Date(2026, 11, 4, 15, 30, 0, 0, time.UTC)
	start := weekStartOn(wednesday, time.UTC, true)
	if start.Weekday() != time.Sunday || start.Day() != 1 || start.Hour() != 0 {
		t.Fatalf("week start = %v", start)
	}
	if !weekStartOn(time.Date(2026, 11, 7, 23, 59, 0, 0, time.UTC), time.UTC, true).Equal(start) {
		t.Fatal("Saturday belongs to the same week")
	}
	if !weekStartOn(start, time.UTC, true).Equal(start) {
		t.Fatal("a Sunday starts its own week")
	}
	// The narrative names a Sunday-first week after its Monday.
	input := NarrativeInput(WeeklyStats{WeekStartNS: start.UnixNano()}, nil, nil, nil, nil, storage.ScopeProject, time.UTC)
	if !strings.HasPrefix(input, "[范围] 项目 周期=2026-W45\n") {
		t.Fatalf("input = %s", input)
	}
}
