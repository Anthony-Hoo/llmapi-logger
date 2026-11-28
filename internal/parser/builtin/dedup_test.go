package builtin_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strings"
	"testing"

	"llmapi-logger/internal/auditmodel"
	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/builtin"
	"llmapi-logger/internal/protofixture"
	"llmapi-logger/internal/security"
)

func prepareTurn(t *testing.T, cipher security.Cipher, parserName string, input base.Input) auditmodel.PreparedTurn {
	t.Helper()
	adapter, _ := builtin.Registry().Lookup(parserName)
	result := adapter.Parser.Parse(context.Background(), input)
	if result.Status != base.StatusOK {
		t.Fatalf("%s: parse status %s (%s)", parserName, result.Status, result.ErrorCode)
	}
	turn, err := adapter.Normalizer().NormalizeAudit(context.Background(), input, result)
	if err != nil {
		t.Fatalf("%s: normalize: %v", parserName, err)
	}
	turn.AuditID, turn.Protocol, turn.ParserName, turn.CreatedAtNS = input.AuditID, input.Protocol, parserName, 1
	prepared, err := auditmodel.Prepare(turn, cipher)
	if err != nil {
		t.Fatalf("%s: prepare: %v", parserName, err)
	}
	return prepared
}

func exchangeInput(exchange protofixture.Exchange) base.Input {
	status := exchange.Response.Status
	path, _ := url.Parse(exchange.Path)
	return base.Input{AuditID: "apx_dedup", Protocol: exchange.Protocol.Family(), Endpoint: path.Path, StatusCode: &status,
		Request:  base.BodySource{Present: true, Complete: true, ContentType: "application/json", Data: exchange.RequestBody},
		Response: base.BodySource{Present: true, Complete: true, ContentType: exchange.Response.Header.Get("Content-Type"), Data: exchange.Response.Seen()}}
}

// responseItemHashes lists the response item objects, leaving out the echo
// items only a Responses stream stores.
func responseItemHashes(prepared auditmodel.PreparedTurn) (items, echoes []string) {
	for _, ref := range prepared.ResponseRefs {
		hash := hex.EncodeToString(ref.ObjectHash)
		if ref.Slot == auditmodel.SlotInstructions || ref.Slot == auditmodel.SlotTools {
			echoes = append(echoes, ref.Slot)
			continue
		}
		items = append(items, hash)
	}
	sort.Strings(items)
	sort.Strings(echoes)
	return items, echoes
}

// TestStreamAndJSONResponsesShareItemObjects: a stream is stored with the
// item split of the non-stream response, so a streamed answer and the same
// answer without streaming store the same response item objects; only the
// envelopes differ, and a Responses stream adds its echoed instructions and
// tools as items of their own.
func TestStreamAndJSONResponsesShareItemObjects(t *testing.T) {
	t.Parallel()
	cipher := testCipher(t)
	type pair struct {
		label, parser string
		stream, plain base.Input
	}
	var pairs []pair
	// The catalogue renders Responses and Anthropic answers the same way
	// streamed or not. Its Chat answers differ on purpose (a non-stream
	// message carries "annotations": [] and a null content where a stream
	// sends ""), as real ones do, so Chat and Completions use hand pairs.
	for _, protocol := range []protofixture.Protocol{protofixture.OpenAIResponses, protofixture.AnthropicMessages, protofixture.Gemini} {
		for _, scenario := range protofixture.NormalScenarios() {
			if protocol == protofixture.AnthropicMessages && scenario == protofixture.ScenarioExtensions {
				continue // the streamed answer has an extra server_tool_use block
			}
			streamed, _ := protofixture.Build(protofixture.Case{Protocol: protocol, Scenario: scenario, Stream: true}, protofixture.Options{Seed: 21})
			plain, _ := protofixture.Build(protofixture.Case{Protocol: protocol, Scenario: scenario, Stream: false}, protofixture.Options{Seed: 21})
			for index := range streamed {
				pairs = append(pairs, pair{fmt.Sprintf("%s/%s#%d", protocol, scenario, index), streamed[index].ParserName,
					exchangeInput(streamed[index]), exchangeInput(plain[index])})
				if plain[index].ParserName != streamed[index].ParserName {
					// Gemini's two operations are two parsers that store
					// either form the same way.
					pairs = append(pairs, pair{fmt.Sprintf("%s/%s#%d/%s", protocol, scenario, index, plain[index].ParserName), plain[index].ParserName,
						exchangeInput(streamed[index]), exchangeInput(plain[index])})
				}
			}
		}
	}
	status := 200
	hand := func(parser, path, request, stream, plain string) base.Input {
		input := base.Input{AuditID: "apx_dedup", Protocol: "openai", Endpoint: path, StatusCode: &status, Request: jsonBody(request), Response: sseBody(stream)}
		if plain != "" {
			input.Response = jsonBody(plain)
		}
		return input
	}
	chatStream := chunkStream(`{"role":"assistant","content":"Hel"}`, `{"content":"lo"}`,
		`{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"lookup","arguments":""}}]}`,
		`{"tool_calls":[{"index":0,"function":{"arguments":"{\"q\":1}"}}]}`)
	chatPlain := `{"id":"chatcmpl-x","object":"chat.completion","created":1,"model":"model-example","choices":[{"index":0,"message":{"role":"assistant","content":"Hello",` +
		`"tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{\"q\":1}"}}]},"finish_reason":"tool_calls"}]}`
	chatRequest := `{"model":"model-example","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	pairs = append(pairs, pair{"chat/hand", "openai.chat_completions", hand("openai.chat_completions", "/v1/chat/completions", chatRequest, chatStream, ""),
		hand("openai.chat_completions", "/v1/chat/completions", chatRequest, "", chatPlain)})
	completionsStream := "data: {\"id\":\"cmpl-x\",\"object\":\"text_completion\",\"created\":1,\"model\":\"model-example\",\"choices\":[{\"index\":0,\"text\":\"ans\",\"finish_reason\":null}]}\n\n" +
		"data: {\"id\":\"cmpl-x\",\"object\":\"text_completion\",\"created\":1,\"model\":\"model-example\",\"choices\":[{\"index\":0,\"text\":\"wer\",\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"
	completionsPlain := `{"id":"cmpl-x","object":"text_completion","created":1,"model":"model-example","choices":[{"index":0,"text":"answer","finish_reason":"stop"}]}`
	completionsRequest := `{"model":"model-example","stream":true,"prompt":"hi"}`
	pairs = append(pairs, pair{"completions/hand", "openai.completions", hand("openai.completions", "/v1/completions", completionsRequest, completionsStream, ""),
		hand("openai.completions", "/v1/completions", completionsRequest, "", completionsPlain)})

	covered := map[string]bool{}
	for _, test := range pairs {
		streamed := prepareTurn(t, cipher, test.parser, test.stream)
		plain := prepareTurn(t, cipher, test.parser, test.plain)
		streamItems, echoes := responseItemHashes(streamed)
		plainItems, _ := responseItemHashes(plain)
		if !slices.Equal(streamItems, plainItems) || len(plainItems) == 0 {
			t.Errorf("%s: stream items %q, non-stream items %q", test.label, streamItems, plainItems)
		}
		wantEchoes := []string(nil)
		if strings.HasPrefix(test.parser, "openai.responses") {
			wantEchoes = []string{auditmodel.SlotInstructions, auditmodel.SlotTools}
		}
		if !slices.Equal(echoes, wantEchoes) {
			t.Errorf("%s: echo items %q, want %q", test.label, echoes, wantEchoes)
		}
		if auditmodel.EqualHash(streamed.ResponseEnvelopeHash, plain.ResponseEnvelopeHash) {
			t.Errorf("%s: the stream and non-stream envelopes are one object", test.label)
		}
		covered[test.parser] = true
	}
	for _, adapter := range builtin.Registry().Adapters() {
		if adapter.Normalizer() != nil && adapter.Name() != "openai.responses_compact" && !covered[adapter.Name()] {
			t.Errorf("stream normalizer %q has no stream/non-stream pair", adapter.Name())
		}
	}
}

func chunkStream(deltas ...string) string {
	var body strings.Builder
	for index, delta := range deltas {
		finish := "null"
		if index == len(deltas)-1 {
			finish = `"tool_calls"`
		}
		body.WriteString(`data: {"id":"chatcmpl-x","object":"chat.completion.chunk","created":1,"model":"model-example","choices":[{"index":0,"delta":` +
			delta + `,"finish_reason":` + finish + "}]}\n\n")
	}
	body.WriteString("data: [DONE]\n\n")
	return body.String()
}

// objectStore stands in for content_objects: it remembers every object hash
// a turn stored and reports what a later turn has to insert.
type objectStore map[string]string

func (store objectStore) insert(prepared auditmodel.PreparedTurn) (inserted map[string]string) {
	inserted = map[string]string{}
	for _, object := range prepared.Objects {
		key := hex.EncodeToString(object.Hash)
		if _, exists := store[key]; !exists {
			store[key] = object.Kind
			inserted[key] = object.Kind
		}
	}
	return inserted
}

func kinds(objects map[string]string) []string {
	var result []string
	for _, kind := range objects {
		result = append(result, kind)
	}
	sort.Strings(result)
	return result
}

func itemKinds(values []string) []string {
	var result []string
	for _, kind := range values {
		if !strings.HasSuffix(kind, "_envelope") {
			result = append(result, kind)
		}
	}
	return result
}

func refHashes(refs []auditmodel.ObjectRef) map[string]bool {
	result := map[string]bool{}
	for _, ref := range refs {
		result[hex.EncodeToString(ref.ObjectHash)] = true
	}
	return result
}

// reused lists the first turn's response item objects the second turn's
// request refers to.
func reused(first, second auditmodel.PreparedTurn) []string {
	request := refHashes(second.RequestRefs)
	var result []string
	for _, ref := range first.ResponseRefs {
		if ref.Slot == auditmodel.SlotInstructions || ref.Slot == auditmodel.SlotTools {
			continue // echoes only a stream stores as items
		}
		if key := hex.EncodeToString(ref.ObjectHash); request[key] {
			result = append(result, ref.Slot+":"+key[:12])
		}
	}
	sort.Strings(result)
	return result
}

// TestStreamedConversationSharesObjectsWithTheNextRequest runs two turns with
// full-history resend, streamed and not. The second request refers to the
// first turn's response objects in exactly the cases it does for the
// non-stream answer, and a Responses stream's echoed instructions and tools
// are stored once across both turns.
func TestStreamedConversationSharesObjectsWithTheNextRequest(t *testing.T) {
	t.Parallel()
	cipher := testCipher(t)
	type turnPair struct {
		label, parser  string
		stream, plain  [2]base.Input
		wantReuse      bool
		wantEchoesOnce bool
	}
	var cases []turnPair
	for _, protocol := range []protofixture.Protocol{protofixture.OpenAIResponses, protofixture.OpenAIChat, protofixture.AnthropicMessages, protofixture.Gemini} {
		streamed, _ := protofixture.Build(protofixture.Case{Protocol: protocol, Scenario: protofixture.ScenarioMultiTurn, Stream: true}, protofixture.Options{Seed: 13})
		plain, _ := protofixture.Build(protofixture.Case{Protocol: protocol, Scenario: protofixture.ScenarioMultiTurn, Stream: false}, protofixture.Options{Seed: 13})
		cases = append(cases, turnPair{label: string(protocol) + "/catalogue", parser: streamed[0].ParserName,
			stream:         [2]base.Input{exchangeInput(streamed[0]), exchangeInput(streamed[1])},
			plain:          [2]base.Input{exchangeInput(plain[0]), exchangeInput(plain[1])},
			wantEchoesOnce: protocol == protofixture.OpenAIResponses,
			// The catalogue client resends a Gemini answer's content as it
			// came, which is the object the response stored.
			wantReuse: protocol == protofixture.Gemini})
	}
	status := 200
	input := func(path, request, response string) base.Input {
		body := jsonBody(response)
		if strings.HasPrefix(response, "event:") || strings.HasPrefix(response, "data:") {
			body = sseBody(response)
		}
		return base.Input{AuditID: "apx_dedup", Protocol: "openai", Endpoint: path, StatusCode: &status, Request: jsonBody(request), Response: body}
	}
	// A client that resends the answer's output items verbatim, as agent
	// clients with store=false do.
	tools := `[{"type":"function","name":"lookup","description":"Look a word up.","parameters":{"type":"object","properties":{"q":{"type":"string"}}}}]`
	message := `{"id":"msg_1","type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":"Calling.","annotations":[]}]}`
	call := `{"id":"fc_1","type":"function_call","status":"completed","call_id":"call_1","name":"lookup","arguments":"{\"q\":\"x\"}"}`
	response := func(id, output string) string {
		return `{"id":"` + id + `","object":"response","status":"completed","model":"model-example","instructions":"Be brief.","tools":` + tools +
			`,"output":` + output + `,"usage":{"input_tokens":9,"output_tokens":3,"total_tokens":12}}`
	}
	streamOf := func(body string) string {
		return "event: response.completed\ndata: {\"type\":\"response.completed\",\"sequence_number\":0,\"response\":" + body + "}\n\n"
	}
	request := func(input string) string {
		return `{"model":"model-example","stream":true,"instructions":"Be brief.","tools":` + tools + `,"store":false,"prompt_cache_key":"session-1","input":` + input + `}`
	}
	user := `{"type":"message","role":"user","content":[{"type":"input_text","text":"look up x"}]}`
	second := `[` + user + `,` + message + `,` + call + `,{"type":"function_call_output","call_id":"call_1","output":"found"}]`
	answer := `[{"id":"msg_2","type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":"Done.","annotations":[]}]}]`
	cases = append(cases, turnPair{label: "responses/verbatim resend", parser: "openai.responses", wantReuse: true, wantEchoesOnce: true,
		stream: [2]base.Input{input("/v1/responses", request(`[`+user+`]`), streamOf(response("resp_1", `[`+message+`,`+call+`]`))),
			input("/v1/responses", request(second), streamOf(response("resp_2", answer)))},
		plain: [2]base.Input{input("/v1/responses", request(`[`+user+`]`), response("resp_1", `[`+message+`,`+call+`]`)),
			input("/v1/responses", request(second), response("resp_2", answer))}})
	chatRequest := func(messages string) string {
		return `{"model":"model-example","stream":true,"messages":` + messages + `}`
	}
	chatPlain := func(content string) string {
		return `{"id":"chatcmpl-` + content + `","object":"chat.completion","created":1,"model":"model-example","choices":[{"index":0,"message":{"role":"assistant","content":"` +
			content + `"},"finish_reason":"stop"}]}`
	}
	chatStream := func(content string) string {
		return "data: {\"id\":\"chatcmpl-" + content + "\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"model-example\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"" +
			content + "\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"
	}
	firstChat := `[{"role":"user","content":"hi"}]`
	secondChat := `[{"role":"user","content":"hi"},{"role":"assistant","content":"Hello."},{"role":"user","content":"again"}]`
	cases = append(cases, turnPair{label: "chat/verbatim resend", parser: "openai.chat_completions", wantReuse: true,
		stream: [2]base.Input{input("/v1/chat/completions", chatRequest(firstChat), chatStream("Hello.")), input("/v1/chat/completions", chatRequest(secondChat), chatStream("Again."))},
		plain:  [2]base.Input{input("/v1/chat/completions", chatRequest(firstChat), chatPlain("Hello.")), input("/v1/chat/completions", chatRequest(secondChat), chatPlain("Again."))}})

	for _, test := range cases {
		var reuse [2][]string
		var inserted [2][2]map[string]string
		for mode, inputs := range [2][2]base.Input{test.stream, test.plain} {
			store := objectStore{}
			first := prepareTurn(t, cipher, test.parser, inputs[0])
			second := prepareTurn(t, cipher, test.parser, inputs[1])
			inserted[mode][0] = store.insert(first)
			inserted[mode][1] = store.insert(second)
			reuse[mode] = reused(first, second)
		}
		if !slices.Equal(reuse[0], reuse[1]) || (test.wantReuse && len(reuse[0]) == 0) {
			t.Errorf("%s: next request reuses %q streamed, %q not streamed", test.label, reuse[0], reuse[1])
		}
		streamSecond, plainSecond := kinds(inserted[0][1]), kinds(inserted[1][1])
		// Both modes insert the same item objects on the second turn; only
		// envelopes may differ.
		if !slices.Equal(itemKinds(streamSecond), itemKinds(plainSecond)) {
			t.Errorf("%s: second turn inserts %q streamed, %q not streamed", test.label, streamSecond, plainSecond)
		}
		if test.wantEchoesOnce {
			counts := map[string]int{}
			for _, turn := range inserted[0] {
				for _, kind := range turn {
					counts[kind]++
				}
			}
			if counts["instructions"] != 1 || counts["tools"] != 1 {
				encoded, _ := json.Marshal(counts)
				t.Errorf("%s: echo objects inserted across both streamed turns: %s", test.label, encoded)
			}
		}
		t.Logf("%s: second turn inserts %d objects streamed %q, %d not streamed %q; reuses %q", test.label,
			len(streamSecond), streamSecond, len(plainSecond), plainSecond, reuse[0])
	}
}
