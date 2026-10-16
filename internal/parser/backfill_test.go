package parser_test

import (
	"bytes"
	"context"
	"testing"

	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

// enableInsights turns analysis on after audits were already parsed without it,
// which is exactly the state backfill exists to repair.
func (harness *insightsHarness) enableInsights(withReconstructor bool) {
	harness.t.Helper()
	key := bytes.Repeat([]byte{0x5a}, security.KeySize)
	cipher, err := security.NewAESGCM(key)
	if err != nil {
		harness.t.Fatal(err)
	}
	runner, err := insights.NewRunner(harness.store, cipher, nil, harness.fp)
	if err != nil {
		harness.t.Fatal(err)
	}
	harness.worker.SetHeaderAllowlist(insights.DefaultVocabulary().HeaderAllowlist())
	harness.worker.SetAnalyzer(runner)
	if withReconstructor {
		service, err := query.New(harness.store, cipher)
		if err != nil {
			harness.t.Fatal(err)
		}
		harness.worker.SetReconstructor(service)
	}
}

func (harness *insightsHarness) hasAnalysis(auditID string) bool {
	_, err := harness.store.LoadAnalysis(context.Background(), auditID)
	return err == nil
}

func (harness *insightsHarness) sendMessages(user string) string {
	h := headers("User-Agent", "example-agent/1.0", "X-Api-Key", "sk-backfillkey", "anthropic-version", "2023-06-01")
	return harness.send("/v1/messages", h, messagesBody("model-example", "You are an agent.", userMessage(user)),
		messagesResponse("model-example", `{"type":"text","text":"ok"}`))
}

func (harness *insightsHarness) sendChat(user string, response upstreamResponse) string {
	h := headers("Authorization", "Bearer sk-backfillkey")
	return harness.send("/v1/chat/completions", h, chatBody("model-example", "You are an agent.", user), response)
}

func TestInsightsBackfillFullRetentionAnthropic(t *testing.T) {
	t.Parallel()
	harness := newInsightsHarness(t, nil)
	older := harness.sendMessages("first task")
	newer := harness.sendMessages("second task")
	ctx := context.Background()
	if harness.hasAnalysis(older) || harness.hasAnalysis(newer) {
		t.Fatal("analysis exists before backfill")
	}
	before, err := harness.store.LoadParserAudit(ctx, older)
	if err != nil {
		t.Fatal(err)
	}

	if got := harness.worker.BackfillForTest(ctx); got != 0 {
		t.Fatalf("backfill without an analyzer attempted %d audits", got)
	}
	if harness.hasAnalysis(older) {
		t.Fatal("disabled insights must not backfill")
	}

	harness.enableInsights(false)
	if got := harness.worker.BackfillForTest(ctx); got != 2 {
		t.Fatalf("backfill attempted %d audits, want 2", got)
	}
	for _, id := range []string{older, newer} {
		row := harness.analysis(id)
		if row.AnalysisVersion != insights.AnalysisVersion || row.UncachedInput == nil || *row.UncachedInput != 20 || row.Output == nil || *row.Output != 3 {
			t.Fatalf("backfilled row %s = version %d usage %v/%v", id, row.AnalysisVersion, row.UncachedInput, row.Output)
		}
	}
	after, err := harness.store.LoadParserAudit(ctx, older)
	if err != nil || after.ParseStatus != before.ParseStatus {
		t.Fatalf("parse status changed: %q -> %q (%v)", before.ParseStatus, after.ParseStatus, err)
	}
	// Nothing is left to do, and the empty pass pauses the scan.
	if got := harness.worker.BackfillForTest(ctx); got != 0 {
		t.Fatalf("second pass attempted %d audits", got)
	}
}

func TestInsightsBackfillMetadataWithoutReconstructorSkipsOnce(t *testing.T) {
	t.Parallel()
	harness := newInsightsHarness(t, nil)
	ctx := context.Background()
	jsonID := harness.sendChat("plain task", chatResponse("model-example", "ok"))
	streamID := harness.sendChat("streamed task", upstreamResponse{contentType: "text/event-stream", body: "" +
		`data: {"id":"chatcmpl-s","object":"chat.completion.chunk","model":"model-example","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"}}]}` + "\n\n" +
		`data: {"id":"chatcmpl-s","object":"chat.completion.chunk","model":"model-example","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":20,"completion_tokens":3,"total_tokens":23}}` + "\n\n" +
		"data: [DONE]\n\n"})
	for _, id := range []string{jsonID, streamID} {
		stage, err := harness.store.LoadParserStage(ctx, id, sqlite.StageRequestReceived)
		if err != nil || stage.Body == nil || stage.Body.RetentionState != sqlite.RetentionMetadata {
			t.Fatalf("audit %s must be metadata-retained: %+v %v", id, stage.Body, err)
		}
	}

	// Without a reconstructor the audits are skipped, once.
	harness.enableInsights(false)
	if got := harness.worker.BackfillForTest(ctx); got != 2 || harness.hasAnalysis(jsonID) {
		t.Fatalf("no reconstructor: attempted %d analysed=%v", got, harness.hasAnalysis(jsonID))
	}
	harness.worker.ResetBackfillForTest()
	if got := harness.worker.BackfillForTest(ctx); got != 0 {
		t.Fatalf("skip set must stop the retry loop, attempted %d", got)
	}

	// Installing the reconstructor later does not revive skipped audits in this process.
	harness.enableInsights(true)
	harness.worker.ResetBackfillForTest()
	if got := harness.worker.BackfillForTest(ctx); got != 0 {
		t.Fatalf("skipped audits retried within one process: %d", got)
	}
}

func TestInsightsBackfillMetadataRetentionUsesReconstructor(t *testing.T) {
	t.Parallel()
	harness := newInsightsHarness(t, nil)
	ctx := context.Background()
	jsonID := harness.sendChat("plain task", chatResponse("model-example", "ok"))
	streamID := harness.sendChat("streamed task", upstreamResponse{contentType: "text/event-stream", body: "" +
		`data: {"id":"chatcmpl-s","object":"chat.completion.chunk","model":"model-example","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"}}]}` + "\n\n" +
		`data: {"id":"chatcmpl-s","object":"chat.completion.chunk","model":"model-example","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":20,"completion_tokens":3,"total_tokens":23}}` + "\n\n" +
		"data: [DONE]\n\n"})
	harness.enableInsights(true)
	if got := harness.worker.BackfillForTest(ctx); got != 2 {
		t.Fatalf("attempted %d audits, want 2", got)
	}
	plain := harness.analysis(jsonID)
	if plain.UncachedInput == nil || *plain.UncachedInput != 20 || plain.Output == nil || *plain.Output != 3 || plain.EstUser == 0 {
		t.Fatalf("reconstructed JSON audit = usage %v/%v est_user %d", plain.UncachedInput, plain.Output, plain.EstUser)
	}
	streamed := harness.analysis(streamID)
	if streamed.UncachedInput == nil || *streamed.UncachedInput != 20 || streamed.Output == nil || *streamed.Output != 3 || streamed.EstUser == 0 {
		t.Fatalf("reconstructed stream audit = usage %v/%v est_user %d", streamed.UncachedInput, streamed.Output, streamed.EstUser)
	}
}

func TestInsightsBackfillVersionUpgradeRecomputes(t *testing.T) {
	t.Parallel()
	harness := newInsightsHarness(t, nil)
	ctx := context.Background()
	id := harness.sendMessages("task")
	harness.enableInsights(false)
	if harness.worker.BackfillForTest(ctx) != 1 {
		t.Fatal("initial backfill did not run")
	}
	row := harness.analysis(id)
	row.AnalysisVersion = insights.AnalysisVersion - 1
	row.EstUser = 0
	if err := harness.store.SaveAnalysis(ctx, row); err != nil {
		t.Fatal(err)
	}
	harness.worker.ResetBackfillForTest()
	if got := harness.worker.BackfillForTest(ctx); got != 1 {
		t.Fatalf("outdated row attempted %d, want 1", got)
	}
	if upgraded := harness.analysis(id); upgraded.AnalysisVersion != insights.AnalysisVersion || upgraded.EstUser == 0 {
		t.Fatalf("row not recomputed: version %d est_user %d", upgraded.AnalysisVersion, upgraded.EstUser)
	}
}

func TestInsightsBackfillYieldsToLiveQueue(t *testing.T) {
	t.Parallel()
	harness := newInsightsHarness(t, nil)
	id := harness.sendMessages("task")
	harness.enableInsights(false)
	if !harness.worker.Notify("live-audit-placeholder") {
		t.Fatal("live queue rejected the notification")
	}
	if got := harness.worker.BackfillForTest(context.Background()); got != 0 || harness.hasAnalysis(id) {
		t.Fatalf("backfill ran with live work queued: attempted %d", got)
	}
}

func TestInsightsAuxiliaryRequestsCarryNoEvents(t *testing.T) {
	t.Parallel()
	harness := newInsightsHarness(t, runnerAnalyzer(t))
	send := func(model string, role string, user string) string {
		h := headers("Authorization", "Bearer sk-aux-events", "X-Agent-Session-Id", "raw-aux-tree", "X-Agent-Id", "raw-aux-main")
		if role != "" {
			h.Set("X-Agent-Role", role)
		}
		return harness.send("/v1/chat/completions", h, chatBody(model, "You are an agent.", user), chatResponse(model, "ok"))
	}
	mainStep := harness.analysis(send("model-a", "", "work"))
	compaction := harness.analysis(send("model-b", "compaction", "summarize"))
	if text := func(value *string) string {
		if value == nil {
			return ""
		}
		return *value
	}; text(compaction.AgentRole) != insights.RoleCompaction || text(compaction.PrevAuditID) != mainStep.AuditID {
		t.Fatalf("compaction row: role=%q prev=%q", text(compaction.AgentRole), text(compaction.PrevAuditID))
	}
	if compaction.EventFlags != 0 {
		t.Fatalf("auxiliary step event flags = %d, want 0", compaction.EventFlags)
	}
}
