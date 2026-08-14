package query

import (
	"bytes"
	"context"
	"encoding/base64"
	"path/filepath"
	"testing"

	"llmapi-logger/internal/auditmodel"
	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/openai"
	"llmapi-logger/internal/storage/sqlite"
)

func TestGetReconstructsContentAddressedChatTurn(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cipher := testCipher(t)
	store, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	auditID := "audit-turn-query"
	requestURI, err := cipher.Encrypt([]byte(auditID+"\x00request_uri"), []byte("/v1/chat/completions"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginAudit(ctx, sqlite.AuditRecord{
		AuditID: auditID, StartedAtNS: 1, RouteID: "route-example", Protocol: "openai",
		ParserName: "openai.chat_completions", Method: "POST", Path: "/v1/chat/completions",
		RequestURIEnc: requestURI, Mode: "available",
	}); err != nil {
		t.Fatal(err)
	}
	status := 200
	if err := store.FinishAudit(ctx, sqlite.AuditFinish{
		AuditID: auditID, EndedAtNS: 2, StatusCode: &status,
		ForwardStatus: sqlite.ForwardCompleted, CaptureStatus: sqlite.CaptureComplete, ParseStatus: sqlite.ParsePending,
	}); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimPendingParse(ctx, auditID)
	if err != nil || !claimed {
		t.Fatalf("claim = %v, %v", claimed, err)
	}
	requestMessage := map[string]any{"role": "user", "content": "secret request"}
	responseMessage := map[string]any{"role": "assistant", "content": "secret response"}
	prepared, err := auditmodel.Prepare(auditmodel.Turn{
		AuditID: auditID, Protocol: "openai", ParserName: "openai.chat_completions",
		RequestLayout: auditmodel.LayoutOpenAIChatRequest, ResponseLayout: auditmodel.LayoutMarkerEnvelope,
		RequestEnvelope: map[string]any{"model": "model-example"},
		ResponseEnvelope: map[string]any{
			"id":      "response-example",
			"choices": []any{map[string]any{"message": auditmodel.ItemMarker(0)}},
		},
		RequestItems:  []auditmodel.Item{{Slot: auditmodel.SlotMessages, Kind: "user_message", Value: requestMessage}},
		ResponseItems: []auditmodel.Item{{Slot: auditmodel.SlotChoice, Kind: "assistant_message", Value: responseMessage}},
		RequestOriginal: map[string]any{
			"model": "model-example", "messages": []any{requestMessage},
		},
		ResponseOriginal: map[string]any{
			"id": "response-example", "choices": []any{map[string]any{"message": responseMessage}},
		},
		ResponseID: "response-example", CreatedAtNS: 3,
	}, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveParsedAudit(ctx, sqlite.ParsedAudit{
		Result: sqlite.ParsedResult{
			AuditID: auditID, ParserName: "openai.chat_completions", ParserVersion: "2",
			Status: sqlite.ParseOK, ParsedAtNS: 4,
		},
		Turn: &prepared,
	}); err != nil {
		t.Fatal(err)
	}
	service, err := New(store, cipher)
	if err != nil {
		t.Fatal(err)
	}
	detail, err := service.Get(ctx, auditID)
	if err != nil {
		storageDetail, readErr := store.QueryAuditDetail(ctx, auditID)
		if readErr != nil {
			t.Fatalf("Get: %v; read graph: %v", err, readErr)
		}
		rebuilt, rebuildErr := reconstructTurnGraph(cipher, storageDetail.Audit.ParserName, storageDetail.TurnGraph)
		t.Fatalf("Get: %v; rebuild: %v; rebuilt=%+v; graph=%+v", err, rebuildErr, rebuilt.Turn, storageDetail.TurnGraph)
	}
	if detail.Conversation == nil || len(detail.Conversation.Messages) != 2 ||
		detail.Conversation.Messages[0].Content[0].Text != "secret request" ||
		detail.Conversation.Messages[1].Content[0].Text != "secret response" {
		t.Fatalf("conversation = %+v", detail.Conversation)
	}
	if detail.Turn == nil || detail.Turn.ResponseID == nil || *detail.Turn.ResponseID != "response-example" {
		t.Fatalf("turn = %+v", detail.Turn)
	}
	if bytes.Contains(prepared.Objects[0].DataEnc, []byte("secret request")) {
		t.Fatal("content object leaked plaintext")
	}
}

func TestReconstructTurnGraphFromOpenAINormalizer(t *testing.T) {
	t.Parallel()
	cipher := testCipher(t)
	implementation, err := openai.New(openai.ChatCompletions)
	if err != nil {
		t.Fatal(err)
	}
	requestBody := []byte(`{"model":"gpt-personal","stream":false,"messages":[{"role":"user","content":"admin-api-prompt-secret"}]}`)
	responseBody := []byte(`{"id":"chatcmpl-local","model":"gpt-personal-result","choices":[{"message":{"role":"assistant","content":"admin-api-response-secret"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}}`)
	input := base.Input{
		AuditID: "audit-normalized-query", Protocol: "openai", Endpoint: "/v1/chat/completions",
		Request:  base.BodySource{Present: true, Complete: true, ContentType: "application/json", Data: requestBody},
		Response: base.BodySource{Present: true, Complete: true, ContentType: "application/json", Data: responseBody},
	}
	result := implementation.Parse(context.Background(), input)
	turn, err := implementation.NormalizeAudit(context.Background(), input, result)
	if err != nil {
		t.Fatal(err)
	}
	turn.CreatedAtNS = 1
	prepared, err := auditmodel.Prepare(turn, cipher)
	if err != nil {
		t.Fatal(err)
	}
	graph := graphFromPrepared(prepared)
	rebuilt, err := reconstructTurnGraph(cipher, openai.ChatCompletions, graph)
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.Conversation == nil || len(rebuilt.Conversation.Messages) != 2 {
		t.Fatalf("conversation = %+v", rebuilt.Conversation)
	}
}

func TestReconstructResponsesTurnWithHistoryReasoningParallelToolsAndMultimodalContent(t *testing.T) {
	t.Parallel()
	cipher := testCipher(t)
	implementation, err := openai.New(openai.Responses)
	if err != nil {
		t.Fatal(err)
	}
	png := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0x62, 0x19}, 256)...)
	fileBytes := bytes.Repeat([]byte("reusable file text\n"), 40)
	requestValue := map[string]any{
		"model":                "model-example",
		"instructions":         "Use the developer policy.",
		"previous_response_id": "response-previous",
		"metadata":             map[string]any{"conversation_id": "conversation-example"},
		"input": []any{
			map[string]any{
				"type": "message", "role": "user",
				"content": []any{
					map[string]any{"type": "input_text", "text": "inspect both attachments"},
					map[string]any{"type": "input_image", "image_url": "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), "file_id": "file-example-image"},
					map[string]any{"type": "input_file", "filename": "facts.txt", "mime_type": "text/plain", "file_data": base64.StdEncoding.EncodeToString(fileBytes), "file_id": "file-example-text"},
				},
			},
			map[string]any{"type": "reasoning", "id": "reasoning-previous", "summary": []any{map[string]any{"type": "summary_text", "text": "Earlier reasoning summary"}}},
			map[string]any{"type": "function_call", "id": "function-one", "call_id": "call-one", "name": "lookup", "arguments": `{"id":1}`},
			map[string]any{"type": "function_call", "id": "function-two", "call_id": "call-two", "name": "lookup", "arguments": `{"id":2}`},
			map[string]any{"type": "function_call_output", "call_id": "call-two", "output": `{"value":"two"}`},
			map[string]any{"type": "function_call_output", "call_id": "call-one", "output": `{"value":"one"}`},
		},
	}
	responseValue := map[string]any{
		"id": "response-current", "object": "response", "model": "model-result",
		"output": []any{
			map[string]any{"type": "reasoning", "id": "reasoning-current", "summary": []any{map[string]any{"type": "summary_text", "text": "Checked both results"}}},
			map[string]any{"type": "message", "id": "message-current", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": "Both look valid."}}},
			map[string]any{"type": "function_call", "id": "function-three", "call_id": "call-three", "name": "archive", "arguments": `{"ok":true}`},
			map[string]any{"type": "function_call", "id": "function-four", "call_id": "call-four", "name": "notify", "arguments": `{"ok":true}`},
		},
		"usage": map[string]any{"input_tokens": 123, "output_tokens": 45, "total_tokens": 168},
	}
	requestBody, err := auditmodel.CanonicalJSON(requestValue)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err := auditmodel.CanonicalJSON(responseValue)
	if err != nil {
		t.Fatal(err)
	}
	input := base.Input{
		AuditID: "audit-responses-complex", Protocol: "openai", Endpoint: "/v1/responses",
		Request:  base.BodySource{Present: true, Complete: true, ContentType: "application/json", Data: requestBody},
		Response: base.BodySource{Present: true, Complete: true, ContentType: "application/json", Data: responseBody},
	}
	result := implementation.Parse(context.Background(), input)
	turn, err := implementation.NormalizeAudit(context.Background(), input, result)
	if err != nil {
		t.Fatal(err)
	}
	turn.CreatedAtNS = 10
	prepared, err := auditmodel.Prepare(turn, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.Binaries) != 2 || len(prepared.RequestRefs) != 7 || len(prepared.ResponseRefs) != 4 {
		t.Fatalf("prepared refs: request=%d response=%d binaries=%d", len(prepared.RequestRefs), len(prepared.ResponseRefs), len(prepared.Binaries))
	}
	rebuilt, err := reconstructTurnGraph(cipher, openai.Responses, graphFromPrepared(prepared))
	if err != nil {
		t.Fatal(err)
	}
	gotRequest, err := auditmodel.CanonicalJSON(rebuilt.Request)
	if err != nil {
		t.Fatal(err)
	}
	gotResponse, err := auditmodel.CanonicalJSON(rebuilt.Response)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotRequest, requestBody) || !bytes.Equal(gotResponse, responseBody) {
		t.Fatalf("reconstruction mismatch\nrequest=%s\nresponse=%s", gotRequest, gotResponse)
	}
	if rebuilt.Conversation == nil || len(rebuilt.Conversation.Messages) < 8 {
		t.Fatalf("conversation = %+v", rebuilt.Conversation)
	}
}

func graphFromPrepared(prepared auditmodel.PreparedTurn) *sqlite.TurnGraph {
	graph := &sqlite.TurnGraph{
		TurnID: prepared.AuditID, ConversationID: "conv-" + prepared.AuditID,
		ParentBase: "root", LinkReason: "root", LinkConfidence: 100,
		RequestLayout: prepared.RequestLayout, ResponseLayout: prepared.ResponseLayout,
		RequestEnvelopeHash: prepared.RequestEnvelopeHash, ResponseEnvelopeHash: prepared.ResponseEnvelopeHash,
		RequestRefs: prepared.RequestRefs, ResponseRefs: prepared.ResponseRefs,
		RequestSequenceHash: prepared.RequestSequenceHash, ResponseSequenceHash: prepared.ResponseSequenceHash,
		RequestReconstructionHash: prepared.RequestReconstructionHash, ResponseReconstructionHash: prepared.ResponseReconstructionHash,
		ReconstructionStatus: "verified", CreatedAtNS: prepared.CreatedAtNS,
		Objects:  make([]auditmodel.StoredContent, 0, len(prepared.Objects)),
		Binaries: make([]auditmodel.StoredBinary, 0, len(prepared.Binaries)),
	}
	if prepared.PreviousResponseID != "" {
		value := prepared.PreviousResponseID
		graph.PreviousResponseID = &value
	}
	if prepared.ResponseID != "" {
		value := prepared.ResponseID
		graph.ResponseID = &value
	}
	for _, object := range prepared.Objects {
		graph.Objects = append(graph.Objects, auditmodel.StoredContent{
			Hash: object.Hash, SemanticHash: object.SemanticHash, Kind: object.Kind,
			Compression: object.Compression, PlaintextLength: object.PlaintextLength,
			EncodedLength: object.EncodedLength, DataEnc: object.DataEnc,
		})
	}
	for _, binary := range prepared.Binaries {
		graph.Binaries = append(graph.Binaries, auditmodel.StoredBinary{
			Hash: binary.Hash, MediaType: binary.MediaType, Compression: binary.Compression,
			PlaintextLength: binary.PlaintextLength, EncodedLength: binary.EncodedLength, DataEnc: binary.DataEnc,
		})
	}
	return graph
}
