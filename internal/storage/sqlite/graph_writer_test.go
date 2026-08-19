package sqlite

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/security"
)

type graphTestItem struct {
	kind  string
	value any
}

func TestTurnGraphSupportsRetryEditsSummaryParallelToolsAndBranches(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	cipher := graphTestCipher(t)

	developer := graphItem("developer_message", map[string]any{"role": "developer", "content": "follow policy"})
	userOne := graphItem("user_message", map[string]any{"role": "user", "content": "question one"})
	assistantOne := graphItem("assistant_message", map[string]any{"role": "assistant", "content": "answer one"})
	userTwo := graphItem("user_message", map[string]any{"role": "user", "content": "question two"})
	assistantTwo := graphItem("assistant_message", map[string]any{"role": "assistant", "content": "answer two"})

	root := saveGraphTestTurn(t, store, cipher, "turn-root", "", "response-root", 100,
		[]graphTestItem{developer, userOne}, []graphTestItem{assistantOne})
	continuationRequest := []graphTestItem{developer, userOne, assistantOne, userTwo}
	continuation := saveGraphTestTurn(t, store, cipher, "turn-continuation", "response-root", "response-continuation", 200,
		continuationRequest, []graphTestItem{assistantTwo})
	retry := saveGraphTestTurn(t, store, cipher, "turn-retry", "response-root", "response-retry", 300,
		continuationRequest, []graphTestItem{graphItem("assistant_message", map[string]any{"role": "assistant", "content": "alternate answer"})})
	branch := saveGraphTestTurn(t, store, cipher, "turn-branch", "response-root", "response-branch", 400,
		[]graphTestItem{developer, userOne, assistantOne, graphItem("user_message", map[string]any{"role": "user", "content": "branch question"})},
		[]graphTestItem{graphItem("assistant_message", map[string]any{"role": "assistant", "content": "branch answer"})})

	summary := graphItem("summary", map[string]any{"type": "summary", "text": "Earlier context was compressed."})
	summaryRequest := []graphTestItem{developer, summary, graphItem("user_message", map[string]any{"role": "user", "content": "continue after summary"})}
	summaryTurn := saveGraphTestTurn(t, store, cipher, "turn-summary", "response-continuation", "response-summary", 500,
		summaryRequest, []graphTestItem{graphItem("assistant_message", map[string]any{"role": "assistant", "content": "summary continuation"})})
	truncated := saveGraphTestTurn(t, store, cipher, "turn-truncated", "response-continuation", "response-truncated", 600,
		[]graphTestItem{developer, userOne}, []graphTestItem{graphItem("assistant_message", map[string]any{"role": "assistant", "content": "after truncation"})})
	edited := saveGraphTestTurn(t, store, cipher, "turn-edited", "response-continuation", "response-edited", 700,
		[]graphTestItem{developer, graphItem("user_message", map[string]any{"role": "user", "content": "question one edited"}), assistantOne, userTwo},
		[]graphTestItem{graphItem("assistant_message", map[string]any{"role": "assistant", "content": "after edit"})})
	rollback := saveGraphTestTurn(t, store, cipher, "turn-rollback", "response-continuation", "response-rollback", 800,
		[]graphTestItem{developer, userOne, assistantOne},
		[]graphTestItem{graphItem("assistant_message", map[string]any{"role": "assistant", "content": "after rollback"})})

	toolCallOne := graphItem("function_call", map[string]any{"type": "function_call", "call_id": "call-one", "name": "lookup", "arguments": `{"id":1}`})
	toolCallTwo := graphItem("function_call", map[string]any{"type": "function_call", "call_id": "call-two", "name": "lookup", "arguments": `{"id":2}`})
	toolRequest := append(append([]graphTestItem(nil), summaryRequest...), summaryTurnResponseItem())
	toolTurn := saveGraphTestTurn(t, store, cipher, "turn-tools", "response-summary", "response-tools", 900,
		toolRequest, []graphTestItem{toolCallOne, toolCallTwo})
	toolResultOne := graphItem("function_call_output", map[string]any{"type": "function_call_output", "call_id": "call-one", "output": `{"value":"one"}`})
	toolResultTwo := graphItem("function_call_output", map[string]any{"type": "function_call_output", "call_id": "call-two", "output": `{"value":"two"}`})
	toolResultRequest := append(append([]graphTestItem(nil), toolRequest...), toolCallOne, toolCallTwo, toolResultTwo, toolResultOne)
	toolResultTurn := saveGraphTestTurn(t, store, cipher, "turn-tool-results", "response-tools", "response-tool-results", 1000,
		toolResultRequest, []graphTestItem{graphItem("assistant_message", map[string]any{"role": "assistant", "content": "combined result"})})

	assertStoredTurn(t, store, root, nil, "root")
	assertStoredTurn(t, store, continuation, graphStringPointer("turn-root"), "previous_response_id")
	assertStoredTurn(t, store, retry, graphStringPointer("turn-root"), "retry")
	assertStoredTurn(t, store, branch, graphStringPointer("turn-root"), "branch")
	assertStoredTurn(t, store, summaryTurn, graphStringPointer("turn-continuation"), "previous_response_id")
	assertStoredTurn(t, store, truncated, graphStringPointer("turn-continuation"), "branch")
	assertStoredTurn(t, store, edited, graphStringPointer("turn-continuation"), "branch")
	assertStoredTurn(t, store, rollback, graphStringPointer("turn-continuation"), "branch")
	assertStoredTurn(t, store, toolTurn, graphStringPointer("turn-summary"), "previous_response_id")
	assertStoredTurn(t, store, toolResultTurn, graphStringPointer("turn-tools"), "previous_response_id")

	var objectCount int
	if err := store.readerDB.QueryRow(`SELECT COUNT(*) FROM content_objects`).Scan(&objectCount); err != nil {
		t.Fatal(err)
	}
	totalPreparedObjects := len(root.Objects) + len(continuation.Objects) + len(retry.Objects) + len(branch.Objects) +
		len(summaryTurn.Objects) + len(truncated.Objects) + len(edited.Objects) + len(rollback.Objects) +
		len(toolTurn.Objects) + len(toolResultTurn.Objects)
	if objectCount >= totalPreparedObjects {
		t.Fatalf("content objects = %d, prepared copies = %d; expected cross-turn reuse", objectCount, totalPreparedObjects)
	}

}

func TestBinaryObjectsDeduplicateAcrossMediaLabelsAndBase64Spellings(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	cipher := graphTestCipher(t)
	data := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0x51, 0x29}, 256)...)
	encoded := base64.StdEncoding.EncodeToString(data)
	wrapped := encoded[:32] + "\r\n" + encoded[32:]

	first := graphItem("image", map[string]any{"image_url": "data:image/png;base64," + encoded})
	second := graphItem("image", map[string]any{"image_url": "data:application/octet-stream;base64," + wrapped})
	firstTurn := saveGraphTestTurn(t, store, cipher, "turn-binary-one", "", "response-binary-one", 100, []graphTestItem{first}, nil)
	secondTurn := saveGraphTestTurn(t, store, cipher, "turn-binary-two", "", "response-binary-two", 200, []graphTestItem{second}, nil)
	if len(firstTurn.Binaries) != 1 || len(secondTurn.Binaries) != 1 ||
		!auditmodel.EqualHash(firstTurn.Binaries[0].Hash, secondTurn.Binaries[0].Hash) {
		t.Fatalf("binary hashes were not reused")
	}
	if firstTurn.Binaries[0].MediaType != "application/octet-stream" || secondTurn.Binaries[0].MediaType != "application/octet-stream" {
		t.Fatalf("binary object media types = %q and %q", firstTurn.Binaries[0].MediaType, secondTurn.Binaries[0].MediaType)
	}
	assertTableCount(t, store.readerDB, "binary_objects", 1)
	assertTableCount(t, store.readerDB, "content_binary_refs", 2)
}

func graphItem(kind string, value any) graphTestItem {
	return graphTestItem{kind: kind, value: value}
}

func summaryTurnResponseItem() graphTestItem {
	return graphItem("assistant_message", map[string]any{"role": "assistant", "content": "summary continuation"})
}

func saveGraphTestTurn(t *testing.T, store *Store, cipher security.Cipher, auditID, previousResponseID, responseID string, createdAtNS int64, request, response []graphTestItem) auditmodel.PreparedTurn {
	t.Helper()
	endedAtNS := createdAtNS + 1
	insertRetentionAudit(t, store, auditID, createdAtNS, &endedAtNS, ParseProcessing, false)
	requestItems, requestValues, requestMarkers := graphSide(request)
	responseItems, responseValues, responseMarkers := graphSide(response)
	prepared, err := auditmodel.Prepare(auditmodel.Turn{
		AuditID: auditID, Protocol: "openai", ParserName: "parser",
		RequestLayout: auditmodel.LayoutMarkerEnvelope, ResponseLayout: auditmodel.LayoutMarkerEnvelope,
		RequestEnvelope:  map[string]any{"model": "model-example", "items": requestMarkers},
		ResponseEnvelope: map[string]any{"id": responseID, "items": responseMarkers},
		RequestItems:     requestItems, ResponseItems: responseItems,
		RequestOriginal:    map[string]any{"model": "model-example", "items": requestValues},
		ResponseOriginal:   map[string]any{"id": responseID, "items": responseValues},
		PreviousResponseID: previousResponseID, ResponseID: responseID, CreatedAtNS: createdAtNS,
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

func graphSide(values []graphTestItem) ([]auditmodel.Item, []any, []any) {
	items := make([]auditmodel.Item, 0, len(values))
	original := make([]any, 0, len(values))
	markers := make([]any, 0, len(values))
	for index, value := range values {
		items = append(items, auditmodel.Item{Slot: auditmodel.SlotInput, Kind: value.kind, Value: value.value})
		original = append(original, value.value)
		markers = append(markers, auditmodel.ItemMarker(index))
	}
	return items, original, markers
}

func assertStoredTurn(t *testing.T, store *Store, prepared auditmodel.PreparedTurn, wantParent *string, wantReason string) {
	t.Helper()
	detail, err := store.QueryAuditDetail(context.Background(), prepared.AuditID, nil)
	if err != nil {
		t.Fatal(err)
	}
	graph := detail.TurnGraph
	if graph == nil || !sameOptionalString(graph.ParentTurnID, wantParent) || graph.LinkReason != wantReason ||
		len(graph.RequestRefs) != len(prepared.RequestRefs) || len(graph.ResponseRefs) != len(prepared.ResponseRefs) ||
		!auditmodel.EqualHash(auditmodel.SequenceHash(graph.RequestRefs), prepared.RequestSequenceHash) ||
		!auditmodel.EqualHash(auditmodel.SequenceHash(graph.ResponseRefs), prepared.ResponseSequenceHash) {
		t.Fatalf("stored graph %s = %+v", prepared.AuditID, graph)
	}
}

func sameOptionalString(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func graphStringPointer(value string) *string {
	return &value
}

func graphTestCipher(t *testing.T) security.Cipher {
	t.Helper()
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{0x48}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}
