package builtin_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"testing"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/insights"
	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/builtin"
	"llmapi-logger/internal/parser/streamevidence"
	"llmapi-logger/internal/protofixture"
	"llmapi-logger/internal/security"
)

func testCipher(t *testing.T) security.Cipher {
	t.Helper()
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

// stored is one normalized turn after it went through Prepare and was
// rebuilt from the sealed objects alone, the way the query service rebuilds a
// turn whose raw bodies were released.
type stored struct {
	result   base.Result
	turn     auditmodel.Turn
	request  any
	response any
	view     *conversation.Conversation
}

func storeAndRebuild(t *testing.T, cipher security.Cipher, parserName string, input base.Input) (stored, error) {
	t.Helper()
	adapter, ok := builtin.Registry().Lookup(parserName)
	if !ok || adapter.Normalizer() == nil {
		return stored{}, fmt.Errorf("no normalizer %q", parserName)
	}
	result := adapter.Parser.Parse(context.Background(), input)
	if result.Status != base.StatusOK {
		return stored{result: result}, fmt.Errorf("parse status %s (%s)", result.Status, result.ErrorCode)
	}
	turn, err := adapter.Normalizer().NormalizeAudit(context.Background(), input, result)
	if err != nil {
		return stored{result: result}, err
	}
	turn.AuditID, turn.Protocol, turn.ParserName, turn.CreatedAtNS = "apx_fidelity", input.Protocol, parserName, 1
	prepared, err := auditmodel.Prepare(turn, cipher)
	if err != nil {
		return stored{result: result}, fmt.Errorf("prepare: %w", err)
	}
	objects := map[string]auditmodel.ContentObject{}
	for _, object := range prepared.Objects {
		objects[hex.EncodeToString(object.Hash)] = object
	}
	open := func(hash []byte) (auditmodel.DecodedObject, error) {
		object, ok := objects[hex.EncodeToString(hash)]
		if !ok {
			return auditmodel.DecodedObject{}, errors.New("missing object")
		}
		return auditmodel.OpenObject(cipher, auditmodel.StoredContent{Hash: object.Hash, SemanticHash: object.SemanticHash, Kind: object.Kind,
			Compression: object.Compression, PlaintextLength: object.PlaintextLength, EncodedLength: object.EncodedLength, DataEnc: object.DataEnc})
	}
	binaries := map[string]auditmodel.BinaryObject{}
	for _, binary := range prepared.Binaries {
		binaries[hex.EncodeToString(binary.Hash)] = binary
	}
	resolve := func(hash []byte) ([]byte, error) {
		binary, ok := binaries[hex.EncodeToString(hash)]
		if !ok {
			return nil, errors.New("missing binary")
		}
		return auditmodel.OpenBinary(cipher, auditmodel.StoredBinary{Hash: binary.Hash, MediaType: binary.MediaType, Compression: binary.Compression,
			PlaintextLength: binary.PlaintextLength, EncodedLength: binary.EncodedLength, DataEnc: binary.DataEnc})
	}
	side := func(layout string, envelopeHash []byte, refs []auditmodel.ObjectRef, wantHash []byte) (any, error) {
		envelope, err := open(envelopeHash)
		if err != nil {
			return nil, err
		}
		items := make([]auditmodel.Item, 0, len(refs))
		for _, ref := range refs {
			decoded, err := open(ref.ObjectHash)
			if err != nil {
				return nil, err
			}
			items = append(items, auditmodel.Item{Slot: ref.Slot, Kind: decoded.Kind, Value: decoded.Value})
		}
		value, err := auditmodel.Assemble(layout, envelope.Value, items)
		if err != nil {
			return nil, err
		}
		canonical, err := auditmodel.CanonicalJSON(value)
		if err != nil || !auditmodel.EqualHash(auditmodel.ReconstructionHash(canonical), wantHash) {
			return nil, errors.New("reconstruction hash mismatch")
		}
		return auditmodel.RestoreBinaries(value, resolve)
	}
	request, err := side(prepared.RequestLayout, prepared.RequestEnvelopeHash, prepared.RequestRefs, prepared.RequestReconstructionHash)
	if err != nil {
		return stored{}, fmt.Errorf("rebuild request: %w", err)
	}
	response, err := side(prepared.ResponseLayout, prepared.ResponseEnvelopeHash, prepared.ResponseRefs, prepared.ResponseReconstructionHash)
	if err != nil {
		return stored{}, fmt.Errorf("rebuild response: %w", err)
	}
	view, err := builtin.Registry().RebuildConversation(parserName, request, response, prepared.ResponseLayout)
	if err != nil {
		return stored{}, fmt.Errorf("rebuild conversation: %w", err)
	}
	return stored{result: result, turn: turn, request: request, response: response, view: view}, nil
}

type zeroFingerprinter struct{}

func (zeroFingerprinter) Fingerprint(string, []byte) []byte { return make([]byte, 32) }

func analyze(t *testing.T, input insights.Input) insights.Analysis {
	t.Helper()
	analysis, err := insights.Analyze(input, nil, zeroFingerprinter{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	return analysis
}

func endpointOf(parserName string) string {
	_, suffix, _ := strings.Cut(parserName, ".")
	return suffix
}

func usageText(value any) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

// checkFidelity requires the evidence parsed from the raw bodies and the
// evidence rebuilt from the stored graph to agree on the conversation, the
// usage, the tool calls and the stop reason. For a stream the rebuilt side is
// what the insights backfill has once the SSE bytes are gone: the envelope
// summary and the rebuilt conversation, and the aggregate body.
func checkFidelity(t *testing.T, label, parserName string, input base.Input, value stored) {
	t.Helper()
	parsed, _ := json.Marshal(value.result.Conversation)
	rebuilt, _ := json.Marshal(value.view)
	if !bytes.Equal(parsed, rebuilt) {
		t.Errorf("%s: conversation differs\nraw:     %s\nrebuilt: %s", label, parsed, rebuilt)
	}
	adapter, _ := builtin.Registry().Lookup(parserName)
	live := insights.Input{Protocol: input.Protocol, Endpoint: endpointOf(parserName), Request: input.Request.Data, RequestComplete: true,
		Response: input.Response.Data, ResponseComplete: true, ResponseIsStream: value.result.ObservedStream != nil && *value.result.ObservedStream,
		Usage: value.result.Normalized, Conversation: value.result.Conversation}
	liveAnalysis := analyze(t, live)
	requestBody, err := json.Marshal(value.request)
	if err != nil {
		t.Fatal(err)
	}
	// The rebuilt request with the rebuilt response body (for a stream, the
	// aggregate, which is the non-stream body) parses to the same usage and
	// tool call count.
	reparse := func(responseBody []byte) {
		again := adapter.Parser.Parse(context.Background(), base.Input{AuditID: input.AuditID, Protocol: input.Protocol, Endpoint: input.Endpoint,
			Request:  base.BodySource{Present: true, Complete: true, ContentType: "application/json", Data: requestBody},
			Response: base.BodySource{Present: input.Response.Present, Complete: true, ContentType: "application/json", Data: responseBody}})
		if usageText(again.Usage) != usageText(value.result.Usage) || usageText(again.Normalized) != usageText(value.result.Normalized) {
			t.Errorf("%s: usage raw %s/%s, rebuilt %s/%s", label, usageText(value.result.Usage), usageText(value.result.Normalized), usageText(again.Usage), usageText(again.Normalized))
		}
		if usageText(again.ToolCallCount) != usageText(value.result.ToolCallCount) {
			t.Errorf("%s: tool calls raw %s, rebuilt %s", label, usageText(value.result.ToolCallCount), usageText(again.ToolCallCount))
		}
	}
	if !auditmodel.StreamLayout(value.turn.ResponseLayout) {
		responseBody, _ := json.Marshal(value.response)
		reparse(responseBody)
		rebuiltInput := live
		rebuiltInput.Request, rebuiltInput.Response, rebuiltInput.Conversation = requestBody, responseBody, value.view
		if got := analyze(t, rebuiltInput); got.StopReason != liveAnalysis.StopReason || got.ResponseToolCalls != liveAnalysis.ResponseToolCalls {
			t.Errorf("%s: stop/tool calls raw %q/%d, rebuilt %q/%d", label, liveAnalysis.StopReason, liveAnalysis.ResponseToolCalls, got.StopReason, got.ResponseToolCalls)
		}
		return
	}
	root, _ := value.response.(map[string]any)
	encoded, _ := json.Marshal(root["summary"])
	var summary struct {
		Usage      base.Usage
		Normalized *insights.Usage `json:"normalized_usage"`
		StopReason string          `json:"stop_reason"`
	}
	if err := json.Unmarshal(encoded, &summary); err != nil {
		t.Errorf("%s: stream summary: %v", label, err)
		return
	}
	if usageText(summary.Usage) != usageText(value.result.Usage) || summary.Normalized == nil || usageText(*summary.Normalized) != usageText(value.result.Normalized) {
		t.Errorf("%s: usage raw %s/%s, summary %s/%s", label, usageText(value.result.Usage), usageText(value.result.Normalized), usageText(summary.Usage), usageText(summary.Normalized))
	}
	// The insights backfill of a released stream: no response bytes, the
	// summary's stop reason and usage, the rebuilt conversation.
	backfill := live
	backfill.Request, backfill.Response, backfill.StopReason, backfill.Conversation = requestBody, nil, summary.StopReason, value.view
	if summary.Normalized != nil {
		backfill.Usage = *summary.Normalized
	}
	if got := analyze(t, backfill); got.StopReason != liveAnalysis.StopReason || got.ResponseToolCalls != liveAnalysis.ResponseToolCalls {
		t.Errorf("%s: stop/tool calls raw %q/%d, backfill %q/%d", label, liveAnalysis.StopReason, liveAnalysis.ResponseToolCalls, got.StopReason, got.ResponseToolCalls)
	}
	// The aggregate is the non-stream body, so it yields the same stop reason
	// read as a JSON response.
	body, _ := json.Marshal(root[auditmodel.SlotAggregate])
	reparse(body)
	asBody := live
	asBody.Request, asBody.Response, asBody.ResponseIsStream, asBody.Conversation = requestBody, body, false, value.view
	if got := analyze(t, asBody); got.StopReason != liveAnalysis.StopReason {
		t.Errorf("%s: stop reason raw %q, aggregate body %q", label, liveAnalysis.StopReason, got.StopReason)
	}
}

// handStreams covers the parsers the fixture catalogue has no protocol for.
func handStreams() []normalizeCase {
	status := 200
	input := func(protocol, path, request, response string) base.Input {
		return base.Input{AuditID: "apx_hand", Protocol: protocol, Endpoint: path, StatusCode: &status,
			Request: jsonBody(request), Response: sseBody(response)}
	}
	completions := "data: {\"id\":\"cmpl-hand\",\"object\":\"text_completion\",\"created\":1,\"model\":\"model-example\",\"choices\":[{\"index\":0,\"text\":\"ans\",\"logprobs\":null,\"finish_reason\":null}]}\n\n" +
		"data: {\"id\":\"cmpl-hand\",\"object\":\"text_completion\",\"created\":1,\"model\":\"model-example\",\"choices\":[{\"index\":0,\"text\":\"wer\",\"logprobs\":null,\"finish_reason\":\"length\"}]}\n\n" +
		"data: {\"id\":\"cmpl-hand\",\"object\":\"text_completion\",\"created\":1,\"model\":\"model-example\",\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\n" +
		"data: [DONE]\n\n"
	compactOutput := `[{"id":"cmp_1","type":"compaction","encrypted_content":"opaque"},{"id":"msg_1","type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"done","annotations":[]}]}]`
	compact := "event: response.created\ndata: {\"type\":\"response.created\",\"sequence_number\":0,\"response\":{\"id\":\"resp-hand\",\"object\":\"response\",\"status\":\"in_progress\",\"model\":\"model-example\",\"output\":[]}}\n\n" +
		"event: response.completed\ndata: {\"type\":\"response.completed\",\"sequence_number\":1,\"response\":{\"id\":\"resp-hand\",\"object\":\"response\",\"status\":\"completed\",\"model\":\"model-example\",\"output\":" + compactOutput +
		",\"usage\":{\"input_tokens\":9,\"input_tokens_details\":{\"cached_tokens\":4},\"output_tokens\":2,\"total_tokens\":11}}}\n\n"
	return []normalizeCase{
		{"completions/sse", "openai.completions", input("openai", "/v1/completions", `{"model":"model-example","prompt":"hello","stream":true}`, completions)},
		{"responses_compact/sse", "openai.responses_compact", input("openai", "/v1/responses/compact", `{"model":"model-example","input":[{"role":"user","content":"hello"}],"stream":true}`, compact)},
	}
}

// TestNormalizersKeepFidelity takes every exchange of the fixture catalogue
// (and hand streams for the parsers it has no protocol for) down both paths:
// parsed from the raw bodies, and rebuilt from the sealed turn objects with
// the raw bodies gone. A parser registered as a normalizer must pass on every
// exchange it parses as ok, must have at least one exchange, and, when the
// catalogue streams to it, at least one stream. A protocol given a normalizer
// later is held to this as soon as it is registered.
func TestNormalizersKeepFidelity(t *testing.T) {
	t.Parallel()
	cipher := testCipher(t)
	checked := map[string]int{}
	streamed := map[string]int{}
	catalogStreams := map[string]bool{}
	cases := append(fixtureCases(t), handStreams()...)
	for _, value := range protofixture.Catalog() {
		if value.Stream {
			catalogStreams[value.Protocol.ParserName(true)] = true
		}
	}
	for _, test := range handStreams() {
		catalogStreams[test.parser] = true
	}
	for _, test := range cases {
		adapter, ok := builtin.Registry().Lookup(test.parser)
		if !ok {
			t.Fatalf("%s: no adapter %q", test.label, test.parser)
		}
		if adapter.Normalizer() == nil {
			continue
		}
		value, err := storeAndRebuild(t, cipher, test.parser, test.input)
		if value.result.Status != base.StatusOK {
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", test.label, err)
			continue
		}
		checkFidelity(t, test.label, test.parser, test.input, value)
		checked[test.parser]++
		if auditmodel.StreamLayout(value.turn.ResponseLayout) {
			streamed[test.parser]++
		}
	}
	var names []string
	for _, adapter := range builtin.Registry().Adapters() {
		if adapter.Normalizer() != nil {
			names = append(names, adapter.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		if checked[name] == 0 {
			t.Errorf("normalizer %q has no fidelity exchange", name)
		}
		if catalogStreams[name] && streamed[name] == 0 {
			t.Errorf("normalizer %q has stream exchanges but none passed the fidelity check", name)
		}
	}
	t.Logf("checked exchanges per normalizer: %v (streams %v)", checked, streamed)
}

// TestStreamResidueCarriesFixtureExtensions checks that the extension
// fields and events of the catalogue survive the release of the raw bytes.
func TestStreamResidueCarriesFixtureExtensions(t *testing.T) {
	t.Parallel()
	cipher := testCipher(t)
	for _, protocol := range []protofixture.Protocol{protofixture.OpenAIResponses, protofixture.OpenAIChat, protofixture.AnthropicMessages} {
		exchanges, err := protofixture.Build(protofixture.Case{Protocol: protocol, Scenario: protofixture.ScenarioExtensions, Stream: true}, protofixture.Options{Seed: 42})
		if err != nil {
			t.Fatal(err)
		}
		exchange := exchanges[0]
		status := exchange.Response.Status
		path, _ := url.Parse(exchange.Path)
		input := base.Input{AuditID: "apx_ext", Protocol: protocol.Family(), Endpoint: path.Path, StatusCode: &status,
			Request:  base.BodySource{Present: true, Complete: true, ContentType: "application/json", Data: exchange.RequestBody},
			Response: base.BodySource{Present: true, Complete: true, ContentType: exchange.Response.Header.Get("Content-Type"), Data: exchange.Response.Seen()}}
		value, err := storeAndRebuild(t, cipher, exchange.ParserName, input)
		if err != nil {
			t.Fatalf("%s: %v", protocol, err)
		}
		rebuilt, _ := auditmodel.CanonicalJSON(value.response)
		for _, event := range base.DecodeSSE(exchange.Response.Seen()) {
			var root map[string]any
			if auditmodel.DecodeJSON(event.Data, &root) != nil {
				continue
			}
			for key, field := range root {
				if !strings.HasPrefix(key, "x_bench") && key != "obfuscation" && key != "detail" && key != "annotation" {
					continue
				}
				encoded, _ := auditmodel.CanonicalJSON(field)
				if !bytes.Contains(rebuilt, encoded) {
					t.Errorf("%s: extension %s=%s is lost", protocol, key, encoded)
				}
			}
		}
	}
}

func TestOverLimitResidueKeepsTheRawBody(t *testing.T) {
	t.Parallel()
	status := 200
	padding := strings.Repeat("p", streamevidence.MaxResidueBytes)
	stream := "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_big\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"m\",\"content\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n" +
		"event: x_unknown\ndata: {\"type\":\"x_unknown\",\"padding\":\"" + padding + "\"}\n\n" +
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n" +
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1}}\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	input := base.Input{AuditID: "apx_big", Protocol: "anthropic", Endpoint: "/v1/messages", StatusCode: &status,
		Request: jsonBody(`{"model":"m","max_tokens":8,"stream":true,"messages":[{"role":"user","content":"hi"}]}`), Response: sseBody(stream)}
	_, err := storeAndRebuild(t, testCipher(t), "anthropic.messages", input)
	if !errors.Is(err, streamevidence.ErrResidueTooLarge) {
		t.Fatalf("error = %v, want ErrResidueTooLarge", err)
	}
}
