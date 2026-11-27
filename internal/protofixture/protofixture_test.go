package protofixture

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"net/url"
	"testing"

	"llmapi-logger/internal/auditmodel"
	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/builtin"
	"llmapi-logger/internal/security"
)

func parsers() map[string]base.Parser {
	indexed := make(map[string]base.Parser)
	for _, implementation := range builtin.All() {
		indexed[implementation.Name()] = implementation
	}
	return indexed
}

// parserInput builds the Input the parser worker would load for exchange.
func parserInput(exchange Exchange) base.Input {
	path := exchange.Path
	if parsed, err := url.Parse(path); err == nil {
		path = parsed.Path
	}
	response := exchange.Response
	status := response.Status
	broken := response.CutAt > 0
	return base.Input{
		AuditID:  "apx_fixture",
		Protocol: exchange.Protocol.Family(),
		Endpoint: path,
		Request: base.BodySource{Present: true, Complete: true, ContentType: exchange.RequestHeader.Get("Content-Type"),
			Data: exchange.RequestBody},
		Response: base.BodySource{Present: true, Complete: !broken, ContentType: response.Header.Get("Content-Type"),
			Data: response.Seen()},
		StatusCode: &status,
	}
}

func int64Text(value *int64) string {
	if value == nil {
		return "nil"
	}
	return fmt.Sprint(*value)
}

func checkExpectation(t *testing.T, label string, result base.Result, expect Expectation) {
	t.Helper()
	if result.Status != expect.Status {
		t.Errorf("%s: status = %q (error_code %q), want %q", label, result.Status, result.ErrorCode, expect.Status)
	}
	if expect.ErrorCode != "" && result.ErrorCode != expect.ErrorCode {
		t.Errorf("%s: error_code = %q, want %q", label, result.ErrorCode, expect.ErrorCode)
	}
	if result.ErrorType != expect.ErrorType {
		t.Errorf("%s: error_type = %q, want %q", label, result.ErrorType, expect.ErrorType)
	}
	if result.RequestModel != expect.RequestModel || result.ResponseModel != expect.ResponseModel {
		t.Errorf("%s: models = %q/%q, want %q/%q", label, result.RequestModel, result.ResponseModel, expect.RequestModel, expect.ResponseModel)
	}
	if result.ResponseID != expect.ResponseID {
		t.Errorf("%s: response id = %q, want %q", label, result.ResponseID, expect.ResponseID)
	}
	if result.ObservedStream == nil || *result.ObservedStream != expect.ObservedStream {
		t.Errorf("%s: observed stream = %v, want %v", label, result.ObservedStream, expect.ObservedStream)
	}
	for _, pair := range []struct {
		name      string
		got, want *int64
	}{{"input", result.Usage.Input, expect.Usage.Input}, {"output", result.Usage.Output, expect.Usage.Output}, {"total", result.Usage.Total, expect.Usage.Total}} {
		if int64Text(pair.got) != int64Text(pair.want) {
			t.Errorf("%s: usage %s = %s, want %s", label, pair.name, int64Text(pair.got), int64Text(pair.want))
		}
	}
	if result.MessageCount == nil || *result.MessageCount != expect.MessageCount {
		t.Errorf("%s: message count = %v, want %d", label, result.MessageCount, expect.MessageCount)
	}
	if result.ToolCallCount == nil || *result.ToolCallCount != expect.ToolCallCount {
		t.Errorf("%s: tool call count = %v, want %d", label, result.ToolCallCount, expect.ToolCallCount)
	}
}

// TestCatalogParsesAsExpected feeds every fixture through the repository's
// parsers. For OpenAI exchanges the worker additionally normalizes and
// prepares a turn graph; a failure there would downgrade ok to partial in a
// real run, so it is checked too.
func TestCatalogParsesAsExpected(t *testing.T) {
	t.Parallel()
	indexed := parsers()
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range Catalog() {
		exchanges, err := Build(value, Options{Seed: 42})
		if err != nil {
			t.Fatalf("%s: %v", value, err)
		}
		for index, exchange := range exchanges {
			label := fmt.Sprintf("%s#%d", value, index)
			implementation := indexed[exchange.ParserName]
			if implementation == nil {
				t.Fatalf("%s: no parser %q", label, exchange.ParserName)
			}
			input := parserInput(exchange)
			result := implementation.Parse(context.Background(), input)
			checkExpectation(t, label, result, exchange.Expect)
			normalizer, ok := implementation.(base.AuditNormalizer)
			if !ok || result.Status != base.StatusOK || !input.Response.Complete {
				continue
			}
			turn, err := normalizer.NormalizeAudit(context.Background(), input, result)
			if err != nil {
				t.Errorf("%s: normalize: %v", label, err)
				continue
			}
			turn.AuditID, turn.Protocol, turn.ParserName, turn.CreatedAtNS = input.AuditID, input.Protocol, exchange.ParserName, 1
			if _, err := auditmodel.PrepareWithLookup(turn, cipher, nil); err != nil {
				t.Errorf("%s: prepare: %v", label, err)
			}
			if turn.ConversationKey == "" {
				t.Errorf("%s: OpenAI fixture has no conversation key", label)
			}
		}
	}
}

func TestMixedTurnsParse(t *testing.T) {
	t.Parallel()
	indexed := parsers()
	for _, protocol := range Protocols() {
		for _, stream := range []bool{false, true} {
			conversation := NewConversation(protocol, stream, Options{Seed: 9, HistoryItems: 12}, 3)
			for turn := range 6 {
				exchange := conversation.Next(ScenarioMixed, conversation.MixedFeatures())
				result := indexed[exchange.ParserName].Parse(context.Background(), parserInput(exchange))
				checkExpectation(t, fmt.Sprintf("%s/%v/turn%d", protocol, stream, turn), result, exchange.Expect)
			}
		}
	}
}

func TestGenerationIsDeterministic(t *testing.T) {
	t.Parallel()
	for _, value := range Catalog() {
		first, err := Build(value, Options{Seed: 5, HistoryItems: 4})
		if err != nil {
			t.Fatal(err)
		}
		second, _ := Build(value, Options{Seed: 5, HistoryItems: 4})
		other, _ := Build(value, Options{Seed: 6, HistoryItems: 4})
		for index := range first {
			if !bytes.Equal(first[index].RequestBody, second[index].RequestBody) || !bytes.Equal(first[index].Response.Body(), second[index].Response.Body()) {
				t.Fatalf("%s#%d: same seed produced different bytes", value, index)
			}
			if bytes.Equal(first[index].RequestBody, other[index].RequestBody) {
				t.Fatalf("%s#%d: different seeds produced the same request", value, index)
			}
		}
	}
}

func TestEachTurnResendsTheWholeHistory(t *testing.T) {
	t.Parallel()
	for _, protocol := range Protocols() {
		exchanges, err := Build(Case{Protocol: protocol, Scenario: ScenarioMultiTurn, Stream: true}, Options{Seed: 3})
		if err != nil {
			t.Fatal(err)
		}
		for index := 1; index < len(exchanges); index++ {
			previous, current := exchanges[index-1].Expect.MessageCount, exchanges[index].Expect.MessageCount
			if current <= previous {
				t.Errorf("%s turn %d: %d messages, previous turn had %d", protocol, index+1, current, previous)
			}
		}
		branch, _ := Build(Case{Protocol: protocol, Scenario: ScenarioBranch, Stream: false}, Options{Seed: 3})
		left, right := branch[2], branch[3]
		if bytes.Equal(left.RequestBody, right.RequestBody) || left.Expect.MessageCount != right.Expect.MessageCount {
			t.Errorf("%s: branch continuations must differ in content but not in length", protocol)
		}
	}
}

func TestMultimodalCarriesValidPNG(t *testing.T) {
	t.Parallel()
	// Every PNG starts with the same eight bytes, whose base64 form is fixed.
	const signature = "iVBORw0KGgo"
	for _, protocol := range Protocols() {
		exchanges, _ := Build(Case{Protocol: protocol, Scenario: ScenarioMultimodal}, Options{Seed: 11})
		body := exchanges[0].RequestBody
		start := bytes.Index(body, []byte(signature))
		if start < 0 {
			t.Errorf("%s: multimodal request carries no inline PNG", protocol)
			continue
		}
		end := bytes.IndexByte(body[start:], '"')
		data, err := base64.StdEncoding.DecodeString(string(body[start : start+end]))
		if err != nil {
			t.Errorf("%s: inline PNG is not base64: %v", protocol, err)
			continue
		}
		if _, err := png.Decode(bytes.NewReader(data)); err != nil {
			t.Errorf("%s: inline PNG does not decode: %v", protocol, err)
		}
	}
}

func TestHeavyProfileSize(t *testing.T) {
	t.Parallel()
	conversation := NewConversation(OpenAIResponses, true, Options{Seed: 1, HistoryItems: 214, ItemBytes: 4600, ToolDefinitions: 12, SystemBytes: 12000}, 0)
	exchange := conversation.Next(ScenarioMixed, Features{Reasoning: true})
	size := len(exchange.RequestBody)
	if size < 800_000 || size > 1_400_000 {
		t.Fatalf("heavy request body = %d bytes, want about 1 MB", size)
	}
	if exchange.Expect.MessageCount < 210 || exchange.Expect.MessageCount > 240 {
		t.Fatalf("heavy request has %d input items, want about 220", exchange.Expect.MessageCount)
	}
}

// TestFindingGeminiStreamWithoutTerminalParsesOK pins current behaviour: the
// Gemini parser has no terminal-event check, so a stream that stops cleanly
// between two events is indistinguishable from a complete one.
func TestFindingGeminiStreamWithoutTerminalParsesOK(t *testing.T) {
	t.Parallel()
	exchanges, err := Build(Case{Protocol: Gemini, Scenario: ScenarioNoTerminal, Stream: true}, Options{Seed: 2})
	if err != nil {
		t.Fatal(err)
	}
	result := parsers()[exchanges[0].ParserName].Parse(context.Background(), parserInput(exchanges[0]))
	if result.Status != base.StatusOK {
		t.Fatalf("status = %q; the finding no longer holds, update the expectation and the documentation", result.Status)
	}
}

// TestAnthropicStreamKeepsSignatureAndCitations: the stream fold carries
// signature_delta and citations_delta into the content blocks, as the
// non-stream body has them, so both survive the release of the raw bytes:
// the response rebuilt from the sealed objects holds the same thinking and
// text blocks as the non-stream answer of the same seed, and both yield the
// same conversation.
func TestAnthropicStreamKeepsSignatureAndCitations(t *testing.T) {
	t.Parallel()
	streamed, err := Build(Case{Protocol: AnthropicMessages, Scenario: ScenarioReasoning, Stream: true}, Options{Seed: 4})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := Build(Case{Protocol: AnthropicMessages, Scenario: ScenarioReasoning, Stream: false}, Options{Seed: 4})
	if err != nil {
		t.Fatal(err)
	}
	body := streamed[0].Response.Body()
	if !bytes.Contains(body, []byte("signature_delta")) || !bytes.Contains(body, []byte("citations_delta")) {
		t.Fatal("fixture lacks signature_delta or citations_delta")
	}
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	input := parserInput(streamed[0])
	implementation := parsers()[streamed[0].ParserName]
	result := implementation.Parse(context.Background(), input)
	turn, err := implementation.(base.AuditNormalizer).NormalizeAudit(context.Background(), input, result)
	if err != nil {
		t.Fatal(err)
	}
	turn.AuditID, turn.Protocol, turn.ParserName, turn.CreatedAtNS = input.AuditID, input.Protocol, streamed[0].ParserName, 1
	prepared, err := auditmodel.Prepare(turn, cipher)
	if err != nil {
		t.Fatal(err)
	}
	response := rebuildResponse(t, cipher, prepared)

	var want map[string]any
	if err := auditmodel.DecodeJSON(plain[0].Response.Body(), &want); err != nil {
		t.Fatal(err)
	}
	aggregate, _ := response.(map[string]any)[auditmodel.SlotAggregate].(map[string]any)
	got, _ := auditmodel.CanonicalJSON(aggregate["content"])
	expected, _ := auditmodel.CanonicalJSON(want["content"])
	if !bytes.Contains(got, []byte(`"signature":"`)) || !bytes.Contains(got, []byte(`"citations":[{`)) || !bytes.Equal(got, expected) {
		t.Fatalf("rebuilt stream content = %s\nnon-stream content   = %s", got, expected)
	}
	view, err := builtin.Registry().RebuildConversation(streamed[0].ParserName, nil, response, prepared.ResponseLayout)
	if err != nil {
		t.Fatal(err)
	}
	plainResult := implementation.Parse(context.Background(), base.Input{Response: parserInput(plain[0]).Response})
	streamView, _ := json.Marshal(view)
	plainView, _ := json.Marshal(plainResult.Conversation)
	if !bytes.Equal(streamView, plainView) {
		t.Fatalf("stream conversation = %s\nnon-stream conversation = %s", streamView, plainView)
	}
}

// TestStreamAndJSONAnswersYieldTheSameConversation: a stream is folded into
// the non-stream body, so the same answer streamed or not parses to the same
// response conversation, for every normal scenario of the protocols with a
// stream fold.
func TestStreamAndJSONAnswersYieldTheSameConversation(t *testing.T) {
	t.Parallel()
	indexed := parsers()
	for _, protocol := range []Protocol{OpenAIResponses, OpenAIChat, AnthropicMessages} {
		for _, scenario := range NormalScenarios() {
			if protocol == AnthropicMessages && scenario == ScenarioExtensions {
				// The streamed answer adds a server_tool_use block the JSON
				// answer does not have.
				continue
			}
			streamed, err := Build(Case{Protocol: protocol, Scenario: scenario, Stream: true}, Options{Seed: 8})
			if err != nil {
				t.Fatal(err)
			}
			plain, err := Build(Case{Protocol: protocol, Scenario: scenario, Stream: false}, Options{Seed: 8})
			if err != nil {
				t.Fatal(err)
			}
			for index := range streamed {
				implementation := indexed[streamed[index].ParserName]
				fromStream := implementation.Parse(context.Background(), base.Input{Response: parserInput(streamed[index]).Response})
				fromJSON := implementation.Parse(context.Background(), base.Input{Response: parserInput(plain[index]).Response})
				got, _ := json.Marshal(fromStream.Conversation)
				want, _ := json.Marshal(fromJSON.Conversation)
				if !bytes.Equal(got, want) {
					t.Errorf("%s/%s#%d: stream conversation = %s\njson conversation = %s", protocol, scenario, index, got, want)
				}
			}
		}
	}
}

// rebuildResponse assembles the response of a prepared turn from its sealed
// objects alone.
func rebuildResponse(t *testing.T, cipher security.Cipher, prepared auditmodel.PreparedTurn) any {
	t.Helper()
	objects := map[string]auditmodel.ContentObject{}
	for _, object := range prepared.Objects {
		objects[fmt.Sprintf("%x", object.Hash)] = object
	}
	open := func(hash []byte) auditmodel.DecodedObject {
		object := objects[fmt.Sprintf("%x", hash)]
		decoded, err := auditmodel.OpenObject(cipher, auditmodel.StoredContent{Hash: object.Hash, SemanticHash: object.SemanticHash, Kind: object.Kind,
			Compression: object.Compression, PlaintextLength: object.PlaintextLength, EncodedLength: object.EncodedLength, DataEnc: object.DataEnc})
		if err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	items := make([]auditmodel.Item, 0, len(prepared.ResponseRefs))
	for _, ref := range prepared.ResponseRefs {
		decoded := open(ref.ObjectHash)
		items = append(items, auditmodel.Item{Slot: ref.Slot, Kind: decoded.Kind, Value: decoded.Value})
	}
	response, err := auditmodel.Assemble(prepared.ResponseLayout, open(prepared.ResponseEnvelopeHash).Value, items)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
