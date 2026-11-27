package parser_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/parser/streamevidence"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

func messagesStream(extra string) string {
	return "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_residue\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"model-example\",\"content\":[],\"usage\":{\"input_tokens\":5,\"output_tokens\":1}}}\n\n" +
		extra +
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n\n" +
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":2}}\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
}

// TestStreamResidueOverLimitKeepsRawEvidence runs Anthropic streams through
// the proxy, the store and the parser worker. A stream whose residue (here
// one unknown event) fits is stored as a verified turn and its raw bodies
// are released; one whose residue exceeds the limit is declined, so all of
// its raw bodies stay, the parse is partial with normalization_failed, and
// the conversation is stored as the fallback copy.
func TestStreamResidueOverLimitKeepsRawEvidence(t *testing.T) {
	t.Parallel()
	harness := newInsightsHarness(t, nil)
	ctx := context.Background()
	h := headers("User-Agent", "example-agent/1.0", "X-Api-Key", "sk-residuekey", "anthropic-version", "2023-06-01")
	request := messagesBody("model-example", "You are an agent.", userMessage("hello"))
	small := harness.send("/v1/messages", h, request, upstreamResponse{contentType: "text/event-stream",
		body: messagesStream("event: x_unknown\ndata: {\"type\":\"x_unknown\",\"value\":\"kept\"}\n\n")})
	padding := strings.Repeat("p", streamevidence.MaxResidueBytes)
	large := harness.send("/v1/messages", h, request, upstreamResponse{contentType: "text/event-stream",
		body: messagesStream("event: x_unknown\ndata: {\"type\":\"x_unknown\",\"padding\":\"" + padding + "\"}\n\n")})

	retention := func(auditID string) []string {
		var states []string
		for _, stage := range []string{sqlite.StageRequestReceived, sqlite.StageResponseReceived} {
			loaded, err := harness.store.LoadParserStage(ctx, auditID, stage)
			if err != nil || loaded.Body == nil {
				t.Fatalf("%s %s: %+v %v", auditID, stage, loaded.Body, err)
			}
			states = append(states, loaded.Body.RetentionState)
		}
		return states
	}
	if got := retention(small); got[0] != sqlite.RetentionMetadata || got[1] != sqlite.RetentionMetadata {
		t.Fatalf("stream with a small residue: retention %q, want metadata", got)
	}
	if got := retention(large); got[0] != sqlite.RetentionFull || got[1] != sqlite.RetentionFull {
		t.Fatalf("stream over the residue limit: retention %q, want full", got)
	}

	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{0x5a}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	service, err := query.New(harness.store, cipher)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := service.ReconstructTurn(ctx, small)
	if err != nil {
		t.Fatal(err)
	}
	if response, _ := json.Marshal(rebuilt.Response); !bytes.Contains(response, []byte(`{"data":{"type":"x_unknown","value":"kept"},"index":1}`)) {
		t.Fatalf("the unknown event is not in the rebuilt response: %s", response)
	}

	detail, err := harness.store.QueryAuditDetail(ctx, large, nil)
	if err != nil {
		t.Fatal(err)
	}
	if detail.TurnGraph != nil || detail.ParsedResult == nil || detail.ParsedResult.Status != sqlite.ParsePartial ||
		detail.ParsedResult.ErrorCode == nil || *detail.ParsedResult.ErrorCode != "normalization_failed" {
		t.Fatalf("declined stream: turn %v, parsed %+v", detail.TurnGraph != nil, detail.ParsedResult)
	}
	plaintext, err := auditmodel.OpenParsedResult(cipher, large, "anthropic.messages", detail.ParsedResult.ParsedJSONEnc)
	if err != nil || !bytes.Contains(plaintext, []byte(`"conversation"`)) || !bytes.Contains(plaintext, []byte(`"ok"`)) {
		t.Fatalf("declined stream has no fallback conversation: %v", err)
	}
}
