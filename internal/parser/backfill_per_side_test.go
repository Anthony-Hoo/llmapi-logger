package parser_test

import (
	"context"
	"reflect"
	"testing"

	"llmapi-logger/internal/storage/sqlite"
)

// An upstream 5xx releases the request raw and keeps the response raw
// (doc/features/18 section 6). Backfill then rebuilds the request from the
// turn and reads the response from its chunks, and must compute the analysis
// the live parse computed while both raw bodies were still there.
func TestBackfillOfPerSideRetentionMatchesTheRetainedAnalysis(t *testing.T) {
	t.Parallel()
	harness := newInsightsHarness(t, runnerAnalyzer(t))
	ctx := context.Background()
	failures := map[string]upstreamResponse{
		"json": {status: 503, contentType: "application/json",
			body: `{"error":{"message":"upstream overloaded","type":"server_error","code":"overloaded"}}`},
		"rate limited": {status: 429, contentType: "application/json",
			body: `{"error":{"message":"slow down","type":"rate_limit_error","code":"rate_limit_exceeded"}}`},
		// A stream the upstream answered with a server error status: its SSE
		// bytes are retained and must be parsed as SSE, not replaced by the
		// rebuilt stream summary.
		"stream": {status: 500, contentType: "text/event-stream", body: "" +
			`data: {"id":"chatcmpl-s","object":"chat.completion.chunk","model":"model-example","choices":[{"index":0,"delta":{"role":"assistant","content":"partial"}}]}` + "\n\n" +
			`data: {"id":"chatcmpl-s","object":"chat.completion.chunk","model":"model-example","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":20,"completion_tokens":3,"total_tokens":23}}` + "\n\n" +
			"data: [DONE]\n\n"},
	}
	ids := make(map[string]string)
	for name, response := range failures {
		ids[name] = harness.sendChat(name+" task", response)
	}

	live := make(map[string]sqlite.AnalysisRow)
	for name, id := range ids {
		request, err := harness.store.LoadParserStage(ctx, id, sqlite.StageRequestReceived)
		if err != nil || request.Body == nil || request.Body.RetentionState != sqlite.RetentionMetadata {
			t.Fatalf("%s: request must be released: %+v %v", name, request.Body, err)
		}
		response, err := harness.store.LoadParserStage(ctx, id, sqlite.StageResponseReceived)
		if err != nil || response.Body == nil || response.Body.RetentionState != sqlite.RetentionFull {
			t.Fatalf("%s: response must be retained: %+v %v", name, response.Body, err)
		}
		row := harness.analysis(id)
		live[name] = row
		// Make the stored row outdated so backfill recomputes it.
		row.AnalysisVersion--
		if err := harness.store.SaveAnalysis(ctx, row); err != nil {
			t.Fatal(err)
		}
	}

	harness.enableInsights(true)
	for name, id := range ids {
		input, streamSummary, reason, err := harness.worker.BackfillInputForTest(ctx, id)
		if err != nil || reason != "" {
			t.Fatalf("%s: backfill input = %q, %v", name, reason, err)
		}
		// The request is rebuilt from the turn; the retained response is read
		// byte for byte, with its status, and no rebuilt summary replaces it.
		if !input.Request.Present || !input.Request.Complete || len(input.Request.Data) == 0 {
			t.Fatalf("%s: rebuilt request = %+v", name, input.Request)
		}
		if string(input.Response.Data) != failures[name].body || !input.Response.Complete ||
			input.StatusCode == nil || *input.StatusCode != failures[name].status || streamSummary {
			t.Fatalf("%s: response = %q complete=%v status=%v summary=%v", name, input.Response.Data,
				input.Response.Complete, input.StatusCode, streamSummary)
		}
	}
	if got := harness.worker.BackfillForTest(ctx); got != len(ids) {
		t.Fatalf("backfill attempted %d audits, want %d", got, len(ids))
	}
	for name, id := range ids {
		want, got := live[name], harness.analysis(id)
		// The encryption nonce and the time of analysis differ by nature.
		want.DetailEnc, got.DetailEnc = nil, nil
		got.AnalyzedAtNS = want.AnalyzedAtNS
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: backfilled analysis differs from the live one\n got: %+v\nwant: %+v", name, got, want)
		}
	}
}
