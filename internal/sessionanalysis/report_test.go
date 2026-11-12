package sessionanalysis

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/config"
	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/storage"
)

func TestWeekStartIsMondayMidnight(t *testing.T) {
	wednesday := time.Date(2026, 11, 4, 15, 30, 0, 0, packZone)
	start := WeekStart(wednesday, packZone)
	if start.Weekday() != time.Monday || start.Day() != 2 || start.Hour() != 0 {
		t.Fatalf("week start = %v", start)
	}
	sunday := time.Date(2026, 11, 8, 23, 59, 0, 0, packZone)
	if !WeekStart(sunday, packZone).Equal(start) {
		t.Fatal("Sunday belongs to the same week")
	}
}

// After a model change the week holds rows of both models; each is filtered
// by the calibration of the model that produced it.
func TestWeeklyStatsApplyEachRowsOwnCalibration(t *testing.T) {
	enums := []storage.FacetEnumRow{
		{PromptVersion: PromptVersion, Model: "old-model", Kind: storage.PackKindSession, TaskType: "bugfix", Outcome: "achieved", Friction: `["tool_error"]`},
		{PromptVersion: PromptVersion, Model: "new-model", Kind: storage.PackKindSession, TaskType: "feature", Outcome: "partial", Friction: `["tool_error"]`},
	}
	asked := map[string]int{}
	hidden := func(promptVersion, model string) map[string]bool {
		asked[promptVersion+"/"+model]++
		if model == "old-model" {
			return map[string]bool{"outcome": true, "friction": true}
		}
		return map[string]bool{}
	}
	stats := buildWeeklyStats(time.Unix(0, 0), storage.SessionSignalTotals{}, enums, hidden)
	if stats.FacetsOK != 2 || stats.TaskTypes["bugfix"] != 1 || stats.TaskTypes["feature"] != 1 {
		t.Fatalf("task types = %v (facets %d)", stats.TaskTypes, stats.FacetsOK)
	}
	if len(stats.Outcomes) != 1 || stats.Outcomes["partial"] != 1 {
		t.Fatalf("outcomes = %v: the old model's hidden field leaked", stats.Outcomes)
	}
	if stats.Friction["tool_error"] != 1 {
		t.Fatalf("friction = %v", stats.Friction)
	}
	if asked[PromptVersion+"/old-model"] == 0 || asked[PromptVersion+"/new-model"] == 0 {
		t.Fatalf("calibrations asked = %v", asked)
	}
}

func TestNarrativeNumbersMustComeFromTheInput(t *testing.T) {
	input := "[覆盖] 会话12(+3) 已分析9\n[信号] 死循环2个会话 结束前未验证3(占有写文件会话25%)"
	if !NarrativeNumbersGrounded("本周 12 个会话，死循环 2 个，未验证占 25%。", input) {
		t.Fatal("grounded text rejected")
	}
	if NarrativeNumbersGrounded("本周 12 个会话，效率提升 40%。", input) {
		t.Fatal("invented number accepted")
	}
	text := TemplateNarrative(WeeklyStats{Totals: SignalTotals{Sessions: 4, AgentSessions: 3, ChatSessions: 1, LoopSessions: 1}, FacetsOK: 2,
		TaskTypes: map[string]int64{"bug_fix": 2}, Friction: map[string]int64{"tool_failed": 1}},
		[]string{"修复登录接口"}, []SuggestionLine{{Kind: "instruction", Text: "提交前先跑测试", Sessions: 3}})
	for _, want := range []string{"本周做了什么：共 4 个会话", "修缺陷 2", "主要目标：修复登录接口", "卡在哪里：死循环 1 个会话", "工具失败 1", "“提交前先跑测试”（3 个会话）"} {
		if !strings.Contains(text, want) {
			t.Errorf("template lacks %q:\n%s", want, text)
		}
	}
}

// Three sessions of one key repeat the same instruction; the third already
// carries it in its injected AGENTS.md.
func reportFixture(t *testing.T, model *scriptedModel) (*memoryStore, *Runner) {
	t.Helper()
	store := newMemoryStore()
	views := map[string]*conversation.Conversation{}
	day := time.Date(2026, 11, 3, 2, 0, 0, 0, time.UTC) // Tuesday 10:00 at UTC+8
	for index := 0; index < 3; index++ {
		key := bytes.Repeat([]byte{byte(0x50 + index)}, 32)
		node := bytes.Repeat([]byte{byte(0x60 + index)}, 32)
		prefix := "rp" + string(rune('a'+index))
		at := day.Add(time.Duration(index) * time.Hour)
		rows := []storage.SessionAuditRow{auditRow(prefix+"1", at, node, "main", true), auditRow(prefix+"2", at.Add(10*time.Minute), node, "main", true)}
		cost := float64(index + 1)
		for position := range rows {
			quota, unit := int64(500000*(index+1)), 500000.0*2
			rows[position].Quota, rows[position].QuotaPerUnit = &quota, &unit
		}
		store.sessions[hex.EncodeToString(key)] = rows
		_ = cost
		messages := []msg{}
		if index == 2 {
			messages = append(messages, user("# AGENTS.md instructions for /work\n\n- 提交前先跑 go test ./..."))
		}
		messages = append(messages,
			user("修一下导出接口的分页。提交前先跑 go test ./..."),
			call("w"+prefix, "apply_patch", "*** Begin Patch\n*** Update File: export.go\n*** End Patch"),
			result("w"+prefix, "Success."),
			user("好的，再看一下文档"),
			answer("完成"),
		)
		views[prefix+"2"] = convo(messages...)
	}
	vocab, insightsVocab := testVocabularies(t)
	runner, err := NewRunner(Options{
		Config: testRunnerConfig(),
		Store:  store, Loader: &fakeLoader{views: views}, Vocabulary: vocab, Insights: insightsVocab,
		Fingerprints: testFingerprinter{}, Cipher: testCipher(t), LLM: model, Location: packZone,
		Now: func() time.Time { return day.Add(48 * time.Hour) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return store, runner
}

func TestReportsSuggestionsAndNarrative(t *testing.T) {
	model := &scriptedModel{narrative: "本周做了什么：共 3 个会话。\n卡在哪里：暂无。\n可以沉淀或改进的点：提交前先跑测试（3 个会话）。"}
	store, runner := reportFixture(t, model)
	ctx := context.Background()
	if _, err := runner.RunOnce(ctx, TriggerManual); err != nil {
		t.Fatal(err)
	}
	service, err := NewQueryService(store, runner, runner.options.Cipher, "local-small")
	if err != nil {
		t.Fatal(err)
	}
	service.now = runner.options.Now
	service.location = packZone
	report, err := service.Report(ctx, "current", nil, ReportTarget{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Scope != storage.ScopeAll || report.Stats == nil || report.Stats.Totals.Sessions != 3 {
		t.Fatalf("report = %+v", report)
	}
	if report.NarrativeSource != "model" || !strings.HasPrefix(report.Narrative, "本周做了什么：共 3 个会话") {
		t.Fatalf("narrative (%s) = %q", report.NarrativeSource, report.Narrative)
	}
	var instruction *SuggestionItem
	for index := range report.Suggestions {
		if strings.Contains(report.Suggestions[index].Text, "提交前先跑 go test") {
			instruction = &report.Suggestions[index]
		}
	}
	if instruction == nil {
		t.Fatalf("suggestions = %+v", report.Suggestions)
	}
	// Seen in three sessions, strong; the third already injects it.
	if instruction.Sessions != 3 || !instruction.Strong || instruction.Status != "adopted_detected" || len(instruction.Evidence) != 3 {
		t.Fatalf("instruction = %+v", instruction)
	}
	// A developer sees only their own key's statistics.
	own := scopeOf(bytes.Repeat([]byte{1}, 32))
	personal, err := service.Report(ctx, "current", own, ReportTarget{})
	if err != nil || personal.Scope != storage.ScopePerson || personal.Stats == nil || personal.Stats.Totals.Sessions != 3 || len(personal.Suggestions) == 0 {
		t.Fatalf("personal = %+v, %v", personal, err)
	}
	if foreign, err := service.Report(ctx, "current", scopeOf(bytes.Repeat([]byte{7}, 32)), ReportTarget{}); err != nil || foreign.Stats != nil || len(foreign.Suggestions) != 0 {
		t.Fatalf("foreign = %+v, %v", foreign, err)
	}
	if _, err := service.Report(ctx, "next", nil, ReportTarget{}); err == nil {
		t.Fatal("unknown week accepted")
	}
	// Dismissing an all-keys suggestion survives the next refresh.
	if err := service.DismissSuggestion(ctx, instruction.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.RunOnce(ctx, TriggerManual); err != nil {
		t.Fatal(err)
	}
	refreshed, _ := service.Report(ctx, "current", nil, ReportTarget{})
	for _, item := range refreshed.Suggestions {
		if item.ID == instruction.ID && item.Status != "dismissed" {
			t.Fatalf("dismissed suggestion reopened: %+v", item)
		}
	}
	// Unchanged input: the narrative is not regenerated.
	if model.textCalls == 0 {
		t.Fatal("narrative never requested")
	}
}

// Only the first line of a multi-line user message carries its label; a
// repeated instruction on a later line must still be recovered from the
// pack, while tool and answer lines never count as user text.
func TestSentenceInPackReadsContinuationLines(t *testing.T) {
	_, runner := reportFixture(t, nil)
	text := strings.Join([]string{
		"[会话] 类型=agent 客户端=Codex",
		"[U1] 修一下导出接口的分页",
		"提交前先跑一遍全部单元测试",
		"[REDACTED:contact] 改完之后发给我看一下",
		"[T1] 读×2。提交前先跑 go vet ./...",
		"[U2 10:02] 好的",
		"第二轮的补充说明也要保留",
		"[A] 完成。提交前先跑 golangci-lint run",
	}, "\n")
	pack, err := runner.sealPack(bytes.Repeat([]byte{0x44}, 32), storage.PackKindSession, Pack{Text: text}, nil, nil, "", 1, 2, "a1", 1)
	if err != nil {
		t.Fatal(err)
	}
	find := func(want string) string {
		tag := instructionFingerprint(runner.options.Fingerprints, want)
		return runner.sentenceInPack(pack, func(candidate string) bool {
			return string(instructionFingerprint(runner.options.Fingerprints, candidate)) == string(tag)
		})
	}
	for _, want := range []string{"提交前先跑一遍全部单元测试", "[REDACTED:contact] 改完之后发给我看一下", "第二轮的补充说明也要保留", "修一下导出接口的分页"} {
		if got := find(want); got != want {
			t.Errorf("recovered %q, want %q", got, want)
		}
	}
	for _, foreign := range []string{"提交前先跑 go vet ./...", "提交前先跑 golangci-lint run"} {
		if got := find(foreign); got != "" {
			t.Errorf("non-user line recovered: %q", got)
		}
	}
}

func TestNarrativeFallsBackToTheTemplate(t *testing.T) {
	model := &scriptedModel{narrative: "本周做了什么：效率提升了 87%。"}
	store, runner := reportFixture(t, model)
	if _, err := runner.RunOnce(context.Background(), TriggerManual); err != nil {
		t.Fatal(err)
	}
	service, _ := NewQueryService(store, runner, runner.options.Cipher, "local-small")
	service.now, service.location = runner.options.Now, packZone
	report, err := service.Report(context.Background(), "current", nil, ReportTarget{})
	if err != nil {
		t.Fatal(err)
	}
	if report.NarrativeSource != "template" || strings.Contains(report.Narrative, "87%") || !strings.HasPrefix(report.Narrative, "本周做了什么：共 3 个会话") {
		t.Fatalf("narrative (%s) = %q", report.NarrativeSource, report.Narrative)
	}
	// A narrative cut off at the output limit is dropped even when what is
	// left passes the checks.
	cut := &scriptedModel{narrative: "本周做了什么：共 3 个会话。\n卡在哪里：暂无。\n可以沉淀或改进的点：提交前先跑测试（3 个会话）。", truncated: true}
	cutStore, cutRunner := reportFixture(t, cut)
	if _, err := cutRunner.RunOnce(context.Background(), TriggerManual); err != nil {
		t.Fatal(err)
	}
	service, _ = NewQueryService(cutStore, cutRunner, cutRunner.options.Cipher, "local-small")
	service.now, service.location = cutRunner.options.Now, packZone
	if report, _ := service.Report(context.Background(), "current", nil, ReportTarget{}); report.NarrativeSource != "template" || cut.textCalls == 0 {
		t.Fatalf("truncated narrative source = %s, text calls = %d", report.NarrativeSource, cut.textCalls)
	}
	// Without a model the template is used directly.
	plain, runnerNoModel := reportFixture(t, nil)
	runnerNoModel.options.LLM = nil
	if _, err := runnerNoModel.RunOnce(context.Background(), TriggerManual); err != nil {
		t.Fatal(err)
	}
	service, _ = NewQueryService(plain, runnerNoModel, runnerNoModel.options.Cipher, "")
	service.now, service.location = runnerNoModel.options.Now, packZone
	if report, _ := service.Report(context.Background(), "current", nil, ReportTarget{}); report.NarrativeSource != "template" {
		t.Fatalf("no-model narrative source = %s", report.NarrativeSource)
	}
}

func testRunnerConfig() config.SessionAnalysisConfig {
	return config.SessionAnalysisConfig{RunAt: "02:00", SessionIdleMinutes: 120, L1SettleHours: 24, MinUserTurns: 2, MinActiveSeconds: 1,
		Pack: config.SessionAnalysisPack{MaxTokens: 6000}, LLM: config.SessionAnalysisLLM{MaxConcurrency: 1, TimeoutSeconds: 5, MaxSessionsRun: 10}}
}
