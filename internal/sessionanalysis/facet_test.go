package sessionanalysis

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"llmapi-logger/internal/config"
	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/storage"
)

func TestParseFacetValidatesAgainstTheSchema(t *testing.T) {
	vocab, _ := testVocabularies(t)
	refs := map[string]string{"U1": "a1", "C2": "a2", "T2": "a2", "A": "a3"}
	content := `{"goal":"修复登录接口` + strings.Repeat("长", 100) + `","task_type":"bug_fix","outcome":"great","friction":["tool_failed","made_up","tool_failed","looping","wrong_approach","buggy_code"],
"collaboration":"task_iteration","work_relevance":"work","instructions":["参数校验错误一律返回 400","password=` + strings.Repeat("x", 8) + ` 不要提交","c","d"],
"skill_candidate":"","evidence":{"friction":["C2","Z9"],"outcome":["nope"]}}`
	facet, err := ParseFacet(content, false, refs, vocab)
	if err != nil {
		t.Fatal(err)
	}
	if facet.TaskType != "bug_fix" || facet.Outcome != "" || facet.Collaboration != "task_iteration" || facet.WorkRelevance != "work" {
		t.Fatalf("enums = %+v", facet)
	}
	if strings.Join(facet.InvalidFields, ",") != "friction,outcome" {
		t.Fatalf("invalid fields = %v", facet.InvalidFields)
	}
	if strings.Join(facet.Friction, ",") != "tool_failed,looping,wrong_approach" {
		t.Fatalf("friction = %v", facet.Friction)
	}
	if len([]rune(facet.Goal)) != maxFacetText || len(facet.Instructions) != 3 {
		t.Fatalf("goal=%d instructions=%v", len([]rune(facet.Goal)), facet.Instructions)
	}
	if !strings.Contains(facet.Instructions[1], "[REDACTED:password_assignment]") {
		t.Fatalf("instruction not redacted: %q", facet.Instructions[1])
	}
	if len(facet.Evidence) != 1 || len(facet.Evidence["friction"]) != 1 || facet.Evidence["friction"][0] != "C2" {
		t.Fatalf("evidence = %v", facet.Evidence)
	}
	if _, err := ParseFacet("I think the answer is bug_fix", false, refs, vocab); err == nil {
		t.Fatal("prose accepted")
	}
	digest, err := ParseFacet(`{"goal":"","friction":[],"instructions":[],"skill_candidate":"","evidence":{},
"items":[{"ref":"U1","task_type":"data","work_relevance":"work"},{"ref":"U9","task_type":"data","work_relevance":"work"},{"ref":"A","task_type":"x","work_relevance":"personal"}]}`, true, refs, vocab)
	if err != nil {
		t.Fatal(err)
	}
	if len(digest.Items) != 2 || digest.Items[1].TaskType != "" || digest.Items[1].WorkRelevance != "personal" || digest.Outcome != "unclear" || digest.TaskType != "" {
		t.Fatalf("digest = %+v", digest)
	}
	if strings.Join(digest.InvalidFields, ",") != "items" {
		t.Fatalf("digest invalid = %v", digest.InvalidFields)
	}
}

// scriptedModel answers from a queue and records every call.
type scriptedModel struct {
	mu        sync.Mutex
	answers   []string
	err       error
	calls     int
	textCalls int
	narrative string
}

func (model *scriptedModel) Model() string { return "local-small" }

func (model *scriptedModel) CompleteText(_ context.Context, messages []ChatMessage) (Completion, error) {
	model.mu.Lock()
	defer model.mu.Unlock()
	model.textCalls++
	if model.err != nil {
		return Completion{}, model.err
	}
	return Completion{Content: model.narrative}, nil
}

func (model *scriptedModel) Complete(_ context.Context, messages []ChatMessage, _ map[string]any) (Completion, error) {
	model.mu.Lock()
	defer model.mu.Unlock()
	model.calls++
	if model.err != nil {
		return Completion{}, model.err
	}
	answer := `{"goal":"把导出改成流式","task_type":"refactor","outcome":"achieved","friction":[],"collaboration":"directive","work_relevance":"work","instructions":["提交前先跑 go test"],"skill_candidate":"","evidence":{"outcome":["A"]}}`
	if len(model.answers) > 0 {
		answer, model.answers = model.answers[0], model.answers[1:]
	}
	return Completion{Content: answer, InputTokens: 1000, OutputTokens: 100, Latency: time.Millisecond}, nil
}

func facetRunner(t *testing.T, store *memoryStore, model Completer, now time.Time) *Runner {
	t.Helper()
	vocab, insightsVocab := testVocabularies(t)
	runner, err := NewRunner(Options{
		Config: config.SessionAnalysisConfig{RunAt: "02:00", SessionIdleMinutes: 120, L1SettleHours: 24, MinUserTurns: 2, MinActiveSeconds: 1,
			Pack: config.SessionAnalysisPack{MaxTokens: 6000}, LLM: config.SessionAnalysisLLM{MaxConcurrency: 2, TimeoutSeconds: 5, MaxSessionsRun: 10}},
		Store: store, Loader: &fakeLoader{views: map[string]*conversation.Conversation{
			"ag2": convo(user("把导出改成流式"), call("x", "exec_command", map[string]any{"cmd": "go test ./..."}), result("x", "Process exited with code 0"), user("再补一下文档"), answer("完成")),
		}},
		Vocabulary: vocab, Insights: insightsVocab, Fingerprints: testFingerprinter{}, Cipher: testCipher(t), LLM: model,
		Location: time.UTC, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return runner
}

func seedAgentSession(store *memoryStore) {
	store.sessions[hex.EncodeToString(sessionK)] = []storage.SessionAuditRow{
		auditRow("ag1", baseTime, nodeMain, "main", true),
		auditRow("ag2", baseTime.Add(5*time.Minute), nodeMain, "main", true),
	}
}

func TestFacetStageSettlesCachesAndRetries(t *testing.T) {
	store := newMemoryStore()
	seedAgentSession(store)
	model := &scriptedModel{}
	ctx := context.Background()

	// Not settled yet: signals and pack are built, the model is not called.
	if run, err := facetRunner(t, store, model, baseTime.Add(3*time.Hour)).RunOnce(ctx, TriggerManual); err != nil || run.L1Candidates != 0 || model.calls != 0 {
		t.Fatalf("unsettled run = %+v, calls=%d, %v", run, model.calls, err)
	}
	if len(store.packs) != 1 {
		t.Fatalf("packs = %d", len(store.packs))
	}
	settled := baseTime.Add(30 * time.Hour)
	// First answer is not JSON: one retry, then a valid facet.
	model.answers = []string{"Sure! Here is the analysis."}
	run, err := facetRunner(t, store, model, settled).RunOnce(ctx, TriggerManual)
	if err != nil || run.L1Candidates != 1 || run.L1OK != 1 || model.calls != 2 || run.L1InputTokens != 2000 {
		t.Fatalf("settled run = %+v calls=%d err=%v", run, model.calls, err)
	}
	facet := store.facets[hex.EncodeToString(sessionK)]
	if facet.Status != FacetOK || facet.TaskType != "refactor" || facet.PromptVersion != PromptVersion || facet.Model != "local-small" {
		t.Fatalf("facet = %+v", facet)
	}
	if bytes.Contains(facet.TextEnc, []byte("流式")) || len(facet.TextEnc) == 0 {
		t.Fatal("facet text not encrypted")
	}
	if len(store.facetFPR[hex.EncodeToString(sessionK)]) != 1 {
		t.Fatalf("instruction fingerprints = %d", len(store.facetFPR[hex.EncodeToString(sessionK)]))
	}
	// Cache hit: nothing changed, no call.
	if run, err := facetRunner(t, store, model, settled).RunOnce(ctx, TriggerManual); err != nil || run.L1Candidates != 0 || model.calls != 2 {
		t.Fatalf("cached run = %+v calls=%d", run, model.calls)
	}
}

func TestFacetStageInvalidIsCachedAndOutageIsRetried(t *testing.T) {
	ctx := context.Background()
	settled := baseTime.Add(30 * time.Hour)

	store := newMemoryStore()
	seedAgentSession(store)
	model := &scriptedModel{answers: []string{"no", "still no"}}
	if run, _ := facetRunner(t, store, model, settled).RunOnce(ctx, TriggerManual); run.L1Invalid != 1 || model.calls != 2 {
		t.Fatalf("invalid run = %+v calls=%d", run, model.calls)
	}
	if run, _ := facetRunner(t, store, model, settled).RunOnce(ctx, TriggerManual); run.L1Candidates != 0 || model.calls != 2 {
		t.Fatalf("invalid facet retried: %+v calls=%d", run, model.calls)
	}

	// The model is unreachable: S0 and S1 still run, the facet is retried later.
	outage := newMemoryStore()
	seedAgentSession(outage)
	down := &scriptedModel{err: errors.New("connection refused")}
	run, err := facetRunner(t, outage, down, settled).RunOnce(ctx, TriggerManual)
	if err != nil || run.Analyzed != 1 || run.L1Failed != 1 || len(outage.packs) != 1 || len(outage.signals) != 1 {
		t.Fatalf("outage run = %+v err=%v", run, err)
	}
	down.err = nil
	if run, _ := facetRunner(t, outage, down, settled).RunOnce(ctx, TriggerManual); run.L1OK != 1 {
		t.Fatalf("recovered run = %+v", run)
	}
}

func TestFacetReadAndCalibration(t *testing.T) {
	ctx := context.Background()
	store := newMemoryStore()
	seedAgentSession(store)
	model := &scriptedModel{}
	runner := facetRunner(t, store, model, baseTime.Add(30*time.Hour))
	if _, err := runner.RunOnce(ctx, TriggerManual); err != nil {
		t.Fatal(err)
	}
	service, err := NewQueryService(store, runner, runner.options.Cipher, "local-small")
	if err != nil {
		t.Fatal(err)
	}
	id := hex.EncodeToString(sessionK)
	response, err := service.Facet(ctx, id, scopeOf(bytes.Repeat([]byte{1}, 32)), Viewer{Role: "developer"})
	if err != nil {
		t.Fatal(err)
	}
	if response.Goal != "把导出改成流式" || response.TaskType != "refactor" || len(response.Evidence["outcome"]) != 1 || response.Evidence["outcome"][0].AuditID == "" {
		t.Fatalf("facet = %+v", response)
	}
	// The owner sees work relevance; an administrator does not (no review role yet).
	if response.WorkRelevance != "work" {
		t.Fatalf("owner work relevance = %q", response.WorkRelevance)
	}
	if adminView, err := service.Facet(ctx, id, nil, Viewer{Role: "admin"}); err != nil || adminView.WorkRelevance != "" || adminView.TaskType != "refactor" {
		t.Fatalf("admin facet = %+v, %v", adminView, err)
	}
	if _, err := service.Facet(ctx, id, scopeOf(bytes.Repeat([]byte{9}, 32)), Viewer{Role: "developer"}); err == nil {
		t.Fatal("foreign developer read the facet")
	}
	if len(store.views) != 2 || store.views[0].Resource != "facet" || store.views[1].ViewerRole != "admin" {
		t.Fatalf("views = %+v", store.views)
	}
	labels := make([]CalibrationLabel, 0, 25)
	for index := 0; index < 25; index++ {
		label := CalibrationLabel{SessionID: id, TaskType: "refactor", Outcome: "partial"}
		labels = append(labels, label)
	}
	result, err := service.Calibrate(ctx, labels)
	if err != nil {
		t.Fatal(err)
	}
	if result.Samples != 25 || result.Agreement["task_type"] != 1 || result.Agreement["outcome"] != 0 || strings.Join(result.HiddenFields, ",") != "outcome" {
		t.Fatalf("calibration = %+v", result)
	}
	if again, _ := service.Facet(ctx, id, nil, Viewer{Role: "admin"}); strings.Join(again.HiddenFields, ",") != "outcome" {
		t.Fatalf("hidden fields not applied: %v", again.HiddenFields)
	}
	if _, err := service.Calibrate(ctx, []CalibrationLabel{{SessionID: id, TaskType: "nonsense"}}); err == nil {
		t.Fatal("unknown label accepted")
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), "流式") {
		t.Fatal("calibration leaks facet text")
	}
}
