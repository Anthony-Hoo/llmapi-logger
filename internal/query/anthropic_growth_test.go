package query

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"llmapi-logger/internal/auditmodel"
	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/anthropic"
	"llmapi-logger/internal/storage/sqlite"
)

// An agent session resends its whole history with every Messages call. The
// test models what such a client does to the request: cache_control moves to
// the newest message, and the first system block changes per request.
func TestAnthropicStorageGrowsWithUniqueMessagesInsteadOfRepeatedHistory(t *testing.T) {
	t.Parallel()
	const turnCount = 40
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	cipher := testCipher(t)
	implementation := anthropic.New()

	textCanary := "anthropic-plaintext-canary-51c0e7aa"
	padding := strings.Repeat("tool output line with details. ", 64)
	userMessage := func(index int, newest bool) map[string]any {
		block := map[string]any{"type": "text", "text": fmt.Sprintf("%s step %02d %s", textCanary, index, padding)}
		if newest {
			block["cache_control"] = map[string]any{"type": "ephemeral"}
		}
		return map[string]any{"role": "user", "content": []any{block}}
	}
	tools := make([]any, 0, 8)
	for index := 0; index < 8; index++ {
		tools = append(tools, map[string]any{
			"name": fmt.Sprintf("tool_%d", index), "description": strings.Repeat("describes the tool. ", 32),
			"input_schema": map[string]any{"type": "object", "properties": map[string]any{"path": map[string]any{"type": "string"}}},
		})
	}

	var history []any // earlier messages, none of them marked as newest
	var repeatedWireBytes int64
	var itemOccurrences int
	requestBodies := make([][]byte, turnCount)
	responseBodies := make([][]byte, turnCount)
	conversations := make([][]byte, turnCount)
	for index := 0; index < turnCount; index++ {
		messages := append(append([]any(nil), history...), userMessage(index, true))
		requestValue := map[string]any{
			"model": "model-example", "max_tokens": 1024, "tools": tools,
			"system": []any{
				map[string]any{"type": "text", "text": fmt.Sprintf("request header %02d", index)},
				map[string]any{"type": "text", "text": "You are an agent. " + padding, "cache_control": map[string]any{"type": "ephemeral"}},
			},
			"messages": messages,
		}
		answer := fmt.Sprintf("answer %02d", index)
		stream := index%2 == 1
		requestValue["stream"] = stream
		requestBody, err := auditmodel.CanonicalJSON(requestValue)
		if err != nil {
			t.Fatal(err)
		}
		responseID := fmt.Sprintf("msg_%02d", index)
		var responseBody []byte
		contentType := "application/json"
		if stream {
			contentType = "text/event-stream"
			responseBody = []byte("event: message_start\n" +
				`data: {"type":"message_start","message":{"id":"` + responseID + `","type":"message","role":"assistant","model":"model-example","content":[],"usage":{"input_tokens":5,"cache_read_input_tokens":900,"output_tokens":1}}}` + "\n\n" +
				"event: content_block_start\n" + `data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n\n" +
				"event: content_block_delta\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"` + answer + `"}}` + "\n\n" +
				"event: content_block_stop\n" + `data: {"type":"content_block_stop","index":0}` + "\n\n" +
				"event: message_delta\n" + `data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":4}}` + "\n\n" +
				"event: message_stop\n" + `data: {"type":"message_stop"}` + "\n\n")
		} else {
			responseBody, err = auditmodel.CanonicalJSON(map[string]any{
				"id": responseID, "type": "message", "role": "assistant", "model": "model-example",
				"content":     []any{map[string]any{"type": "text", "text": answer}},
				"stop_reason": "end_turn", "usage": map[string]any{"input_tokens": 5, "cache_read_input_tokens": 900, "output_tokens": 4},
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		requestBodies[index] = append([]byte(nil), requestBody...)
		responseBodies[index] = append([]byte(nil), responseBody...)
		repeatedWireBytes += int64(len(requestBody) + len(responseBody))
		itemOccurrences += len(messages) + 2 + 1 // messages + system blocks + response

		auditID := fmt.Sprintf("audit-messages-%02d", index)
		requestURI, err := encryptRequestURI(cipher, auditID, "/v1/messages")
		if err != nil {
			t.Fatal(err)
		}
		if err := store.BeginAudit(ctx, sqlite.AuditRecord{
			AuditID: auditID, StartedAtNS: int64(index*10 + 1), RouteID: "messages-route",
			Protocol: "anthropic", ParserName: anthropic.Messages, Method: "POST", Path: "/v1/messages",
			RequestURIEnc: requestURI, Mode: "available",
		}); err != nil {
			t.Fatal(err)
		}
		status := 200
		if err := store.FinishAudit(ctx, sqlite.AuditFinish{
			AuditID: auditID, EndedAtNS: int64(index*10 + 2), StatusCode: &status,
			ForwardStatus: sqlite.ForwardCompleted, CaptureStatus: sqlite.CaptureComplete, ParseStatus: sqlite.ParsePending,
		}); err != nil {
			t.Fatal(err)
		}
		claimed, err := store.ClaimPendingParse(ctx, auditID)
		if err != nil || !claimed {
			t.Fatalf("claim %s = %v, %v", auditID, claimed, err)
		}
		input := base.Input{
			AuditID: auditID, Protocol: "anthropic", Endpoint: "/v1/messages",
			Request:  base.BodySource{Present: true, Complete: true, ContentType: "application/json", Data: requestBody},
			Response: base.BodySource{Present: true, Complete: true, ContentType: contentType, Data: responseBody},
		}
		result := implementation.Parse(ctx, input)
		if result.Status != base.StatusOK {
			t.Fatalf("parse %s = %s (%s)", auditID, result.Status, result.ErrorCode)
		}
		if conversations[index], err = json.Marshal(result.Conversation); err != nil {
			t.Fatal(err)
		}
		turn, err := implementation.NormalizeAudit(ctx, input, result)
		if err != nil {
			t.Fatal(err)
		}
		turn.CreatedAtNS = int64(index*10 + 3)
		prepared, err := auditmodel.Prepare(turn, cipher)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.SaveParsedAudit(ctx, sqlite.ParsedAudit{
			Result: sqlite.ParsedResult{
				AuditID: auditID, ParserName: anthropic.Messages, ParserVersion: implementation.Version(),
				Status: sqlite.ParseOK, ResponseID: &responseID, ParsedAtNS: int64(index*10 + 4),
			},
			Turn: &prepared,
		}); err != nil {
			t.Fatal(err)
		}
		history = append(history, userMessage(index, false),
			map[string]any{"role": "assistant", "content": []any{map[string]any{"type": "text", "text": answer}}})
	}

	service, err := New(store, cipher)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < turnCount; index++ {
		auditID := fmt.Sprintf("audit-messages-%02d", index)
		rebuilt, err := service.ReconstructTurn(ctx, auditID)
		if err != nil {
			t.Fatalf("reconstruct %s: %v", auditID, err)
		}
		requestBody, err := auditmodel.CanonicalJSON(rebuilt.Request)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(requestBody, requestBodies[index]) {
			t.Fatalf("reconstructed request differs for %s", auditID)
		}
		if index%2 == 0 {
			responseBody, err := auditmodel.CanonicalJSON(rebuilt.Response)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(responseBody, responseBodies[index]) {
				t.Fatalf("reconstructed response differs for %s", auditID)
			}
		} else if rebuilt.Turn.ResponseLayout != auditmodel.LayoutAnthropicStreamResponse {
			t.Fatalf("stream layout of %s = %s", auditID, rebuilt.Turn.ResponseLayout)
		}
		view, err := json.Marshal(rebuilt.Conversation)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(view, conversations[index]) {
			t.Fatalf("conversation of %s differs from the parsed one:\n%s\n%s", auditID, view, conversations[index])
		}
		bodies, err := service.ReconstructBodies(ctx, auditID)
		if err != nil {
			t.Fatal(err)
		}
		if bodies.ResponseIsStream != (index%2 == 1) || !bytes.Equal(bodies.Request, requestBodies[index]) {
			t.Fatalf("reconstructed bodies of %s: stream=%v", auditID, bodies.ResponseIsStream)
		}
		if bodies.ResponseIsStream {
			usage := bodies.StreamNormalized
			if usage == nil || usage.CacheRead == nil || *usage.CacheRead != 900 || usage.UncachedInput == nil || *usage.UncachedInput != 5 ||
				usage.Output == nil || *usage.Output != 4 || bodies.Conversation == nil || len(bodies.Response) != 0 {
				t.Fatalf("stream reconstruction of %s = %+v", auditID, bodies)
			}
		}
	}

	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	var turns, linkedTurns, contentObjects, contextOps int
	var semanticPlaintextBytes sql.NullInt64
	if err := database.QueryRow(`
SELECT
    (SELECT COUNT(*) FROM turns),
    (SELECT COUNT(*) FROM turns WHERE parent_turn_id IS NOT NULL),
    (SELECT COUNT(*) FROM content_objects),
    (SELECT COUNT(*) FROM turn_context_ops),
    (SELECT SUM(plaintext_length) FROM content_objects)
`).Scan(&turns, &linkedTurns, &contentObjects, &contextOps, &semanticPlaintextBytes); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if turns != turnCount {
		t.Fatalf("turns = %d", turns)
	}
	// Each turn adds a bounded number of objects: its new messages, the
	// message that lost cache_control, the changed system header and the
	// response. Short histories fall below the 70% prefix rule and start new
	// roots; once linked, a turn stores only its delta.
	if contentObjects > turnCount*8 || contentObjects*4 >= itemOccurrences {
		t.Fatalf("content objects/item occurrences = %d/%d", contentObjects, itemOccurrences)
	}
	if linkedTurns < turnCount-8 || contextOps > turnCount*12 {
		t.Fatalf("linked turns/context ops = %d/%d", linkedTurns, contextOps)
	}
	if !semanticPlaintextBytes.Valid || semanticPlaintextBytes.Int64*8 >= repeatedWireBytes {
		t.Fatalf("stored semantic bytes/wire bytes = %d/%d", semanticPlaintextBytes.Int64, repeatedWireBytes)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	assertSQLiteFilesDoNotContain(t, path, [][]byte{[]byte(textCanary)})
	t.Logf("turns=%d linked=%d item_occurrences=%d content_objects=%d context_ops=%d semantic_plaintext_bytes=%d repeated_wire_bytes=%d",
		turns, linkedTurns, itemOccurrences, contentObjects, contextOps, semanticPlaintextBytes.Int64, repeatedWireBytes)
}
