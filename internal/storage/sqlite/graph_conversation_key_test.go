package sqlite

import (
	"context"
	"testing"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/security"
)

// TestConversationKeyLinksByContentAmongTheSessionsTurns covers what the key
// alone cannot decide when one client session runs several agents under the
// same key: a turn links to the session turn its content continues, not to the
// latest one, and a turn that continues none of them starts its own root
// inside the keyed conversation.
func TestConversationKeyLinksByContentAmongTheSessionsTurns(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	cipher := graphTestCipher(t)
	const key = "prompt_cache_key\x00session-example"

	instructions := graphItem("instructions", "shared instructions")
	parentTask := graphItem("user_message", map[string]any{"role": "user", "content": "parent task"})
	parentAnswer := graphItem("assistant_message", map[string]any{"role": "assistant", "content": "parent answer"})
	parentNext := graphItem("user_message", map[string]any{"role": "user", "content": "parent follow-up"})
	childTask := graphItem("user_message", map[string]any{"role": "user", "content": "child task"})
	childAnswer := graphItem("assistant_message", map[string]any{"role": "assistant", "content": "child answer"})

	parent := saveKeyedGraphTestTurn(t, store, cipher, "keyed-parent", key, 100,
		[]graphTestItem{instructions, parentTask}, []graphTestItem{parentAnswer})
	child := saveKeyedGraphTestTurn(t, store, cipher, "keyed-child", key, 200,
		[]graphTestItem{instructions, childTask}, []graphTestItem{childAnswer})
	parentRequest := []graphTestItem{instructions, parentTask, parentAnswer, parentNext}
	parentTwo := saveKeyedGraphTestTurn(t, store, cipher, "keyed-parent-2", key, 300,
		parentRequest, []graphTestItem{parentAnswer})
	// A retry of parentTwo arrives after the child spoke again; it must find
	// the attempt it repeats rather than the newer child turn.
	childTwo := saveKeyedGraphTestTurn(t, store, cipher, "keyed-child-2", key, 400,
		[]graphTestItem{instructions, childTask, childAnswer, graphItem("user_message", map[string]any{"role": "user", "content": "child follow-up"})},
		[]graphTestItem{childAnswer})
	retry := saveKeyedGraphTestTurn(t, store, cipher, "keyed-parent-2-retry", key, 500,
		parentRequest, []graphTestItem{graphItem("assistant_message", map[string]any{"role": "assistant", "content": "parent retried"})})

	assertStoredTurn(t, store, parent, nil, "root")
	assertStoredTurn(t, store, child, nil, "root")
	assertStoredTurn(t, store, parentTwo, graphStringPointer("keyed-parent"), "conversation_key")
	assertStoredTurn(t, store, childTwo, graphStringPointer("keyed-child"), "conversation_key")
	assertStoredTurn(t, store, retry, graphStringPointer("keyed-parent-2"), "retry")

	// Each continuation only adds what is new to its own agent; linking to the
	// other agent's latest turn would have rewritten most of the request.
	var cost int
	if err := store.readerDB.QueryRow(`
SELECT COALESCE(SUM(item_count), 0) FROM turn_context_ops
WHERE turn_id = 'keyed-parent-2' AND operation IN ('insert', 'delete')`).Scan(&cost); err != nil {
		t.Fatal(err)
	}
	if cost != 1 {
		t.Fatalf("keyed-parent-2 delta cost = %d, want 1 (the follow-up only)", cost)
	}

	var conversations, roots int
	if err := store.readerDB.QueryRow(`
SELECT COUNT(DISTINCT conversation_id), SUM(parent_turn_id IS NULL) FROM turns`).Scan(&conversations, &roots); err != nil {
		t.Fatal(err)
	}
	if conversations != 1 || roots != 2 {
		t.Fatalf("conversations = %d, roots = %d; want one keyed conversation holding two chains", conversations, roots)
	}
}

// TestConversationKeyNeverMovesATurnIntoAnotherConversation keeps a keyed turn
// in its keyed conversation: when none of that conversation's turns matches,
// or the key has no turns yet, it becomes a new root there instead of joining
// an unrelated conversation through the protocol-wide content search.
func TestConversationKeyNeverMovesATurnIntoAnotherConversation(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	cipher := graphTestCipher(t)

	developer := graphItem("developer_message", map[string]any{"role": "developer", "content": "follow policy"})
	question := graphItem("user_message", map[string]any{"role": "user", "content": "question"})
	answer := graphItem("assistant_message", map[string]any{"role": "assistant", "content": "answer"})

	saveKeyedGraphTestTurn(t, store, cipher, "keyed-own", "prompt_cache_key\x00own-session", 100,
		[]graphTestItem{graphItem("user_message", map[string]any{"role": "user", "content": "unrelated"})}, []graphTestItem{answer})
	other := saveGraphTestTurn(t, store, cipher, "unkeyed-other", "", "response-other", 200,
		[]graphTestItem{developer, question}, []graphTestItem{answer})
	moved := saveKeyedGraphTestTurn(t, store, cipher, "keyed-continues-other", "prompt_cache_key\x00own-session", 300,
		[]graphTestItem{developer, question, answer, question}, []graphTestItem{answer})

	assertStoredTurn(t, store, moved, nil, "root")
	var ownConversation, movedConversation, otherConversation string
	for turnID, destination := range map[string]*string{"keyed-own": &ownConversation, "keyed-continues-other": &movedConversation, other.AuditID: &otherConversation} {
		if err := store.readerDB.QueryRow(`SELECT conversation_id FROM turns WHERE turn_id = ?`, turnID).Scan(destination); err != nil {
			t.Fatal(err)
		}
	}
	if movedConversation != ownConversation || movedConversation == otherConversation {
		t.Fatalf("keyed turn conversation = %q, own = %q, other = %q", movedConversation, ownConversation, otherConversation)
	}

	// The first turn of a new key must not be adopted by another session
	// either; that would drop the key and orphan every later turn using it.
	first := saveKeyedGraphTestTurn(t, store, cipher, "new-key-first", "prompt_cache_key\x00new-session", 400,
		[]graphTestItem{developer, question, answer, question}, []graphTestItem{answer})
	assertStoredTurn(t, store, first, nil, "root")
	next := saveKeyedGraphTestTurn(t, store, cipher, "new-key-next", "prompt_cache_key\x00new-session", 500,
		[]graphTestItem{developer, question, answer, question, answer, question}, []graphTestItem{answer})
	assertStoredTurn(t, store, next, graphStringPointer("new-key-first"), "conversation_key")
	var firstConversation string
	var keyHash []byte
	if err := store.readerDB.QueryRow(`
SELECT c.conversation_id, c.key_hash FROM turns AS t
JOIN conversations AS c ON c.conversation_id = t.conversation_id
WHERE t.turn_id = 'new-key-first'`).Scan(&firstConversation, &keyHash); err != nil {
		t.Fatal(err)
	}
	if firstConversation == otherConversation || firstConversation == ownConversation ||
		!auditmodel.EqualHash(keyHash, first.ConversationKeyHash) {
		t.Fatalf("new key's first turn joined conversation %q (key recorded: %v)", firstConversation, auditmodel.EqualHash(keyHash, first.ConversationKeyHash))
	}
}

func saveKeyedGraphTestTurn(t *testing.T, store *Store, cipher security.Cipher, auditID, conversationKey string, createdAtNS int64, request, response []graphTestItem) auditmodel.PreparedTurn {
	t.Helper()
	endedAtNS := createdAtNS + 1
	insertRetentionAudit(t, store, auditID, createdAtNS, &endedAtNS, ParseProcessing, false)
	requestItems, requestValues, requestMarkers := graphSide(request)
	responseItems, responseValues, responseMarkers := graphSide(response)
	responseID := "response-" + auditID
	prepared, err := auditmodel.Prepare(auditmodel.Turn{
		AuditID: auditID, Protocol: "openai", ParserName: "parser",
		RequestLayout: auditmodel.LayoutMarkerEnvelope, ResponseLayout: auditmodel.LayoutMarkerEnvelope,
		RequestEnvelope:  map[string]any{"model": "model-example", "items": requestMarkers},
		ResponseEnvelope: map[string]any{"id": responseID, "items": responseMarkers},
		RequestItems:     requestItems, ResponseItems: responseItems,
		RequestOriginal:  map[string]any{"model": "model-example", "items": requestValues},
		ResponseOriginal: map[string]any{"id": responseID, "items": responseValues},
		ResponseID:       responseID, ConversationKey: conversationKey, CreatedAtNS: createdAtNS,
	}, cipher)
	if err != nil {
		t.Fatalf("prepare %s: %v", auditID, err)
	}
	if err := store.SaveParsedAudit(context.Background(), ParsedAudit{
		Result: ParsedResult{AuditID: auditID, ParserName: "parser", ParserVersion: "2", Status: ParseOK, ParsedAtNS: endedAtNS + 1},
		Turn:   &prepared,
	}); err != nil {
		t.Fatalf("save %s: %v", auditID, err)
	}
	return prepared
}
