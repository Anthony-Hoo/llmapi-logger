package query

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"llmapi-logger/internal/auditmodel"
	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/openai"
	"llmapi-logger/internal/storage/sqlite"
)

// TestConcurrentCodexAgentsSharingPromptCacheKeyKeepSeparateChains replays how
// Codex drives the Responses API with sub-agents: every request is stateless
// (no previous_response_id) and the parent and its sub-agent both send the
// root session id as prompt_cache_key, so the conversation key cannot tell
// them apart. Interleaving their requests used to link every turn to whichever
// agent spoke last; each agent must keep its own chain instead, and every turn
// must still rebuild the exact request and response.
func TestConcurrentCodexAgentsSharingPromptCacheKeyKeepSeparateChains(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cipher := testCipher(t)
	store, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	implementation, err := openai.New(openai.Responses)
	if err != nil {
		t.Fatal(err)
	}

	message := func(role, text string) map[string]any {
		contentType := "input_text"
		if role == "assistant" {
			contentType = "output_text"
		}
		return map[string]any{
			"type": "message", "role": role,
			"content": []any{map[string]any{"type": contentType, "text": text}},
		}
	}
	// Both agents share the base instructions and the environment context, as
	// Codex sub-agents do; only the task and what follows differ.
	environment := message("user", "<environment_context>cwd=/workspace/example</environment_context>")
	parentTask := message("user", "plan the parser refactor")
	parentAnswerOne := message("assistant", "spawning a researcher for the parser")
	parentTaskTwo := message("user", "now draft the migration plan")
	parentAnswerTwo := message("assistant", "migration plan drafted")
	parentTaskThree := message("user", "summarize both plans")
	childTask := message("user", "research how the parser handles tool calls")
	childAnswerOne := message("assistant", "the parser keeps call ids in order")
	childTaskTwo := message("user", "check parallel tool calls too")
	childAnswerTwo := message("assistant", "parallel calls keep their ids as well")
	childTaskThree := message("user", "report back to the parent")

	type sent struct{ request, response []byte }
	bodies := make(map[string]sent)
	send := func(auditID string, createdAtNS int64, input []any, output map[string]any) {
		t.Helper()
		requestBody, err := auditmodel.CanonicalJSON(map[string]any{
			"model":            "model-example",
			"instructions":     "You are a coding agent.",
			"prompt_cache_key": "codex-root-session-example",
			"store":            false,
			"stream":           false,
			"input":            input,
		})
		if err != nil {
			t.Fatal(err)
		}
		responseID := "response-" + auditID
		responseBody, err := auditmodel.CanonicalJSON(map[string]any{
			"id": responseID, "object": "response", "model": "model-result",
			"output": []any{output},
		})
		if err != nil {
			t.Fatal(err)
		}
		bodies[auditID] = sent{request: requestBody, response: responseBody}
		requestURI, err := encryptRequestURI(cipher, auditID, "/v1/responses")
		if err != nil {
			t.Fatal(err)
		}
		if err := store.BeginAudit(ctx, sqlite.AuditRecord{
			AuditID: auditID, StartedAtNS: createdAtNS, RouteID: "responses-route",
			Protocol: "openai", ParserName: openai.Responses, Method: "POST", Path: "/v1/responses",
			RequestURIEnc: requestURI, Mode: "available",
		}); err != nil {
			t.Fatal(err)
		}
		status := 200
		if err := store.FinishAudit(ctx, sqlite.AuditFinish{
			AuditID: auditID, EndedAtNS: createdAtNS + 1, StatusCode: &status,
			ForwardStatus: sqlite.ForwardCompleted, CaptureStatus: sqlite.CaptureComplete, ParseStatus: sqlite.ParsePending,
		}); err != nil {
			t.Fatal(err)
		}
		claimed, err := store.ClaimPendingParse(ctx, auditID)
		if err != nil || !claimed {
			t.Fatalf("claim %s = %v, %v", auditID, claimed, err)
		}
		parserInput := base.Input{
			AuditID: auditID, Protocol: "openai", Endpoint: "/v1/responses",
			Request:  base.BodySource{Present: true, Complete: true, ContentType: "application/json", Data: requestBody},
			Response: base.BodySource{Present: true, Complete: true, ContentType: "application/json", Data: responseBody},
		}
		result := implementation.Parse(ctx, parserInput)
		turn, err := implementation.NormalizeAudit(ctx, parserInput, result)
		if err != nil {
			t.Fatal(err)
		}
		if turn.ConversationKey == "" || turn.PreviousResponseID != "" {
			t.Fatalf("%s: fixture must link by prompt_cache_key alone, key=%q previous=%q", auditID, turn.ConversationKey, turn.PreviousResponseID)
		}
		turn.CreatedAtNS = createdAtNS + 2
		prepared, err := auditmodel.Prepare(turn, cipher)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.SaveParsedAudit(ctx, sqlite.ParsedAudit{
			Result: sqlite.ParsedResult{
				AuditID: auditID, ParserName: openai.Responses, ParserVersion: "2",
				Status: sqlite.ParseOK, ResponseID: &responseID, ParsedAtNS: createdAtNS + 3,
			},
			Turn: &prepared,
		}); err != nil {
			t.Fatalf("save %s: %v", auditID, err)
		}
	}

	// Parent and child alternate, so at every save the latest keyed turn
	// belongs to the other agent.
	send("audit-parent-1", 100, []any{environment, parentTask}, parentAnswerOne)
	send("audit-child-1", 200, []any{environment, childTask}, childAnswerOne)
	send("audit-parent-2", 300, []any{environment, parentTask, parentAnswerOne, parentTaskTwo}, parentAnswerTwo)
	send("audit-child-2", 400, []any{environment, childTask, childAnswerOne, childTaskTwo}, childAnswerTwo)
	send("audit-parent-3", 500, []any{environment, parentTask, parentAnswerOne, parentTaskTwo, parentAnswerTwo, parentTaskThree}, parentAnswerTwo)
	send("audit-child-3", 600, []any{environment, childTask, childAnswerOne, childTaskTwo, childAnswerTwo, childTaskThree}, childAnswerTwo)

	want := []struct {
		auditID, parent, reason string
	}{
		{"audit-parent-1", "", "root"},
		{"audit-child-1", "", "root"},
		{"audit-parent-2", "audit-parent-1", "conversation_key"},
		{"audit-child-2", "audit-child-1", "conversation_key"},
		{"audit-parent-3", "audit-parent-2", "conversation_key"},
		{"audit-child-3", "audit-child-2", "conversation_key"},
	}
	conversationID := ""
	for _, expected := range want {
		detail, err := store.QueryAuditDetail(ctx, expected.auditID, nil)
		if err != nil {
			t.Fatal(err)
		}
		graph := detail.TurnGraph
		if graph == nil {
			t.Fatalf("%s: missing turn graph", expected.auditID)
		}
		gotParent := ""
		if graph.ParentTurnID != nil {
			gotParent = *graph.ParentTurnID
		}
		if gotParent != expected.parent || graph.LinkReason != expected.reason {
			t.Fatalf("%s: parent=%q reason=%q, want parent=%q reason=%q", expected.auditID, gotParent, graph.LinkReason, expected.parent, expected.reason)
		}
		// The key still groups the client session: both agents share one
		// conversation, as separate chains inside it.
		if conversationID == "" {
			conversationID = graph.ConversationID
		} else if graph.ConversationID != conversationID {
			t.Fatalf("%s: conversation = %q, want shared %q", expected.auditID, graph.ConversationID, conversationID)
		}

		rebuilt, err := reconstructTurnGraph(cipher, openai.Responses, graph)
		if err != nil {
			t.Fatalf("%s: rebuild: %v", expected.auditID, err)
		}
		gotRequest, err := auditmodel.CanonicalJSON(rebuilt.Request)
		if err != nil {
			t.Fatal(err)
		}
		gotResponse, err := auditmodel.CanonicalJSON(rebuilt.Response)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(gotRequest, bodies[expected.auditID].request) || !bytes.Equal(gotResponse, bodies[expected.auditID].response) {
			t.Fatalf("%s: reconstruction mismatch\nrequest=%s\nresponse=%s", expected.auditID, gotRequest, gotResponse)
		}
	}
}
