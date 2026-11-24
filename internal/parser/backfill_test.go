package parser_test

import (
	"bytes"
	"context"
	"math"
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

// sendGemini sends a request of a protocol without a normalizer, whose raw
// bodies therefore stay fully retained.
func (harness *insightsHarness) sendGemini(user string) string {
	h := headers("User-Agent", "example-agent/1.0", "X-Goog-Api-Key", "sk-backfillkey")
	return harness.send("/v1beta/models/model-example:generateContent", h,
		`{"contents":[{"role":"user","parts":[{"text":"`+user+`"}]}]}`,
		upstreamResponse{contentType: "application/json", body: `{"candidates":[{"content":{"role":"model","parts":[{"text":"ok"}]},"finishReason":"STOP"}],` +
			`"usageMetadata":{"promptTokenCount":20,"candidatesTokenCount":3,"totalTokenCount":23}}`})
}

func (harness *insightsHarness) sendChat(user string, response upstreamResponse) string {
	h := headers("Authorization", "Bearer sk-backfillkey")
	return harness.send("/v1/chat/completions", h, chatBody("model-example", "You are an agent.", user), response)
}

func TestInsightsBackfillFullRetentionGemini(t *testing.T) {
	t.Parallel()
	harness := newInsightsHarness(t, nil)
	older := harness.sendGemini("first task")
	newer := harness.sendGemini("second task")
	ctx := context.Background()
	for _, id := range []string{older, newer} {
		stage, err := harness.store.LoadParserStage(ctx, id, sqlite.StageRequestReceived)
		if err != nil || stage.Body == nil || stage.Body.RetentionState != sqlite.RetentionFull {
			t.Fatalf("audit %s must be fully retained: %+v %v", id, stage.Body, err)
		}
	}
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
	if harness.worker.AnalysisBackfillCovered(math.MaxInt64, 0) {
		t.Fatal("coverage reported without an analyzer")
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
	// That empty listing closed the pass: every candidate was attempted.
	if !harness.worker.AnalysisBackfillCovered(math.MaxInt64, 1) {
		t.Fatal("a completed pass does not report coverage")
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
	harness.enableInsights(true)
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

func TestInsightsBackfillRunsOldestFirstSoNewerAuditsLinkPredecessors(t *testing.T) {
	t.Parallel()
	harness := newInsightsHarness(t, nil)
	ctx := context.Background()
	send := func(user string) string {
		h := headers("Authorization", "Bearer sk-backfill-order", "X-Agent-Session-Id", "raw-order-tree", "X-Agent-Id", "raw-order-main")
		return harness.send("/v1/chat/completions", h, chatBody("model-example", "You are an agent.", user), chatResponse("model-example", "ok"))
	}
	older := send("first task")
	newer := send("second task")
	harness.enableInsights(true)
	if got := harness.worker.BackfillForTest(ctx); got != 2 {
		t.Fatalf("backfill attempted %d audits, want 2", got)
	}
	olderRow, newerRow := harness.analysis(older), harness.analysis(newer)
	if olderRow.PrevAuditID != nil {
		t.Fatalf("oldest audit prev = %q, want none", *olderRow.PrevAuditID)
	}
	if newerRow.PrevAuditID == nil || *newerRow.PrevAuditID != older {
		t.Fatalf("newer audit prev = %v, want %s", newerRow.PrevAuditID, older)
	}
}

// Verified Messages audits release their raw bodies, so backfill rebuilds them
// from the turn graph. Cache reads are most of an agent's prompt and must
// survive that for a stream as well.
func TestInsightsBackfillMetadataRetentionAnthropicKeepsCacheUsage(t *testing.T) {
	t.Parallel()
	harness := newInsightsHarness(t, nil)
	ctx := context.Background()
	h := headers("User-Agent", "example-agent/1.0", "X-Api-Key", "sk-backfillkey", "anthropic-version", "2023-06-01")
	jsonID := harness.send("/v1/messages", h, messagesBody("model-example", "You are an agent.", userMessage("plain task")),
		upstreamResponse{contentType: "application/json", body: `{"id":"msg_plain","type":"message","role":"assistant","model":"model-example",` +
			`"content":[{"type":"text","text":"ok"}],"stop_reason":"max_tokens","usage":{"input_tokens":20,"cache_read_input_tokens":700,"cache_creation_input_tokens":60,"output_tokens":3}}`})
	streamID := harness.send("/v1/messages", h, messagesBody("model-example", "You are an agent.", userMessage("streamed task")),
		upstreamResponse{contentType: "text/event-stream", body: "" +
			"event: message_start\n" + `data: {"type":"message_start","message":{"id":"msg_stream","type":"message","role":"assistant","model":"model-example","content":[],"usage":{"input_tokens":20,"cache_read_input_tokens":700,"cache_creation_input_tokens":60,"output_tokens":1}}}` + "\n\n" +
			"event: content_block_start\n" + `data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n\n" +
			"event: content_block_delta\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}` + "\n\n" +
			"event: content_block_stop\n" + `data: {"type":"content_block_stop","index":0}` + "\n\n" +
			"event: message_delta\n" + `data: {"type":"message_delta","delta":{"stop_reason":"max_tokens"},"usage":{"output_tokens":3}}` + "\n\n" +
			"event: message_stop\n" + `data: {"type":"message_stop"}` + "\n\n"})
	for _, id := range []string{jsonID, streamID} {
		stage, err := harness.store.LoadParserStage(ctx, id, sqlite.StageRequestReceived)
		if err != nil || stage.Body == nil || stage.Body.RetentionState != sqlite.RetentionMetadata {
			t.Fatalf("audit %s must be metadata-retained: %+v %v", id, stage.Body, err)
		}
	}
	harness.enableInsights(true)
	if got := harness.worker.BackfillForTest(ctx); got != 2 {
		t.Fatalf("attempted %d audits, want 2", got)
	}
	for name, id := range map[string]string{"json": jsonID, "stream": streamID} {
		row := harness.analysis(id)
		if row.UncachedInput == nil || *row.UncachedInput != 20 || row.CacheRead == nil || *row.CacheRead != 700 ||
			row.CacheWrite == nil || *row.CacheWrite != 60 || row.Output == nil || *row.Output != 3 || row.EstUser == 0 || row.EstSystem == 0 {
			t.Fatalf("reconstructed %s audit = usage %v/%v/%v/%v est_user %d est_system %d", name,
				row.UncachedInput, row.CacheRead, row.CacheWrite, row.Output, row.EstUser, row.EstSystem)
		}
		if row.StopReason == nil || *row.StopReason != insights.StopLength {
			t.Fatalf("reconstructed %s audit stop reason = %v", name, row.StopReason)
		}
	}
}
