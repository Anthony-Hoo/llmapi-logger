package query

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"llmapi-logger/internal/auditmodel"
	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/openai"
	"llmapi-logger/internal/security"
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
	fixture := newResponsesTurnFixture(t, map[string]any{
		"instructions":     "You are a coding agent.",
		"prompt_cache_key": "codex-root-session-example",
		"store":            false,
	})

	// Both agents share the base instructions and the environment context, as
	// Codex sub-agents do; only the task and what follows differ.
	environment := responsesMessage("user", "<environment_context>cwd=/workspace/example</environment_context>")
	parentTask := responsesMessage("user", "plan the parser refactor")
	parentAnswerOne := responsesMessage("assistant", "spawning a researcher for the parser")
	parentTaskTwo := responsesMessage("user", "now draft the migration plan")
	parentAnswerTwo := responsesMessage("assistant", "migration plan drafted")
	parentTaskThree := responsesMessage("user", "summarize both plans")
	childTask := responsesMessage("user", "research how the parser handles tool calls")
	childAnswerOne := responsesMessage("assistant", "the parser keeps call ids in order")
	childTaskTwo := responsesMessage("user", "check parallel tool calls too")
	childAnswerTwo := responsesMessage("assistant", "parallel calls keep their ids as well")
	childTaskThree := responsesMessage("user", "report back to the parent")

	// Parent and child alternate, so at every save the latest keyed turn
	// belongs to the other agent.
	fixture.send("audit-parent-1", 100, []any{environment, parentTask}, parentAnswerOne)
	fixture.send("audit-child-1", 200, []any{environment, childTask}, childAnswerOne)
	fixture.send("audit-parent-2", 300, []any{environment, parentTask, parentAnswerOne, parentTaskTwo}, parentAnswerTwo)
	fixture.send("audit-child-2", 400, []any{environment, childTask, childAnswerOne, childTaskTwo}, childAnswerTwo)
	fixture.send("audit-parent-3", 500, []any{environment, parentTask, parentAnswerOne, parentTaskTwo, parentAnswerTwo, parentTaskThree}, parentAnswerTwo)
	fixture.send("audit-child-3", 600, []any{environment, childTask, childAnswerOne, childTaskTwo, childAnswerTwo, childTaskThree}, childAnswerTwo)

	// The key still groups the client session: both agents share one
	// conversation, as separate chains inside it.
	fixture.assertTurns([]expectedTurn{
		{"audit-parent-1", "", "root"},
		{"audit-child-1", "", "root"},
		{"audit-parent-2", "audit-parent-1", "conversation_key"},
		{"audit-child-2", "audit-child-1", "conversation_key"},
		{"audit-parent-3", "audit-parent-2", "conversation_key"},
		{"audit-child-3", "audit-child-2", "conversation_key"},
	})
}

// TestServerManagedConversationLinksTurnsWithoutRepeatedContext covers a
// Responses conversation the provider stores: each request names the
// conversation and carries only its new input, so no content is shared between
// turns and the conversation id alone has to link each turn to the previous one.
func TestServerManagedConversationLinksTurnsWithoutRepeatedContext(t *testing.T) {
	t.Parallel()
	fixture := newResponsesTurnFixture(t, map[string]any{"conversation": "conv-example"})

	fixture.send("audit-stateful-1", 100, []any{responsesMessage("user", "first question")}, responsesMessage("assistant", "first answer"))
	fixture.send("audit-stateful-2", 200, []any{responsesMessage("user", "second question")}, responsesMessage("assistant", "second answer"))
	fixture.send("audit-stateful-3", 300, []any{responsesMessage("user", "third question")}, responsesMessage("assistant", "third answer"))

	fixture.assertTurns([]expectedTurn{
		{"audit-stateful-1", "", "root"},
		{"audit-stateful-2", "audit-stateful-1", "conversation_key"},
		{"audit-stateful-3", "audit-stateful-2", "conversation_key"},
	})
}

type expectedTurn struct{ auditID, parent, reason string }

type responsesTurnFixture struct {
	t              *testing.T
	ctx            context.Context
	cipher         security.Cipher
	store          *sqlite.Store
	implementation *openai.Parser
	fields         map[string]any
	bodies         map[string][2][]byte
}

// newResponsesTurnFixture saves Responses audits through the real parser and
// normalizer; fields are added to every request body.
func newResponsesTurnFixture(t *testing.T, fields map[string]any) *responsesTurnFixture {
	t.Helper()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	implementation, err := openai.New(openai.Responses)
	if err != nil {
		t.Fatal(err)
	}
	return &responsesTurnFixture{
		t: t, ctx: ctx, cipher: testCipher(t), store: store, implementation: implementation,
		fields: fields, bodies: make(map[string][2][]byte),
	}
}

func responsesMessage(role, text string) map[string]any {
	contentType := "input_text"
	if role == "assistant" {
		contentType = "output_text"
	}
	return map[string]any{
		"type": "message", "role": role,
		"content": []any{map[string]any{"type": contentType, "text": text}},
	}
}

func (fixture *responsesTurnFixture) send(auditID string, createdAtNS int64, input []any, output map[string]any) {
	t, ctx, store, cipher := fixture.t, fixture.ctx, fixture.store, fixture.cipher
	t.Helper()
	requestValue := map[string]any{"model": "model-example", "stream": false, "input": input}
	for key, value := range fixture.fields {
		requestValue[key] = value
	}
	requestBody, err := auditmodel.CanonicalJSON(requestValue)
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
	fixture.bodies[auditID] = [2][]byte{requestBody, responseBody}
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
	result := fixture.implementation.Parse(ctx, parserInput)
	turn, err := fixture.implementation.NormalizeAudit(ctx, parserInput, result)
	if err != nil {
		t.Fatal(err)
	}
	if turn.ConversationKey == "" || turn.PreviousResponseID != "" {
		t.Fatalf("%s: fixture must link by conversation key alone, key=%q previous=%q", auditID, turn.ConversationKey, turn.PreviousResponseID)
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

// assertTurns checks each turn's parent and link reason, that all of them share
// one conversation, and that each rebuilds the exact request and response.
func (fixture *responsesTurnFixture) assertTurns(want []expectedTurn) {
	t := fixture.t
	t.Helper()
	conversationID := ""
	for _, expected := range want {
		detail, err := fixture.store.QueryAuditDetail(fixture.ctx, expected.auditID, nil)
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
		if conversationID == "" {
			conversationID = graph.ConversationID
		} else if graph.ConversationID != conversationID {
			t.Fatalf("%s: conversation = %q, want shared %q", expected.auditID, graph.ConversationID, conversationID)
		}

		rebuilt, err := reconstructTurnGraph(fixture.cipher, openai.Responses, graph)
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
		sent := fixture.bodies[expected.auditID]
		if !bytes.Equal(gotRequest, sent[0]) || !bytes.Equal(gotResponse, sent[1]) {
			t.Fatalf("%s: reconstruction mismatch\nrequest=%s\nresponse=%s", expected.auditID, gotRequest, gotResponse)
		}
	}
}
