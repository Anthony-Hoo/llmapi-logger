package builtin_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"llmapi-logger/internal/auditmodel"
	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/anthropic"
	"llmapi-logger/internal/parser/openai"
)

// probes builds an SSE stream in which every event, and the nested objects
// the tests name, carry a field no parser reads, each with its own value.
type probes struct {
	values []string
	body   strings.Builder
	types  map[string]bool
}

func newProbes() *probes { return &probes{types: map[string]bool{}} }

// next returns a new probe value.
func (stream *probes) next() string {
	value := fmt.Sprintf("probe-%03d", len(stream.values))
	stream.values = append(stream.values, value)
	return value
}

// event writes one event. fields gets "x_probe" with a new value, and type
// when typed is set.
func (stream *probes) event(name, typed string, fields map[string]any) {
	fields["x_probe"] = stream.next()
	if typed != "" {
		fields["type"] = typed
		stream.types[typed] = true
	}
	encoded, err := json.Marshal(fields)
	if err != nil {
		panic(err)
	}
	if name != "" {
		stream.body.WriteString("event: " + name + "\n")
	}
	stream.body.WriteString("data: " + string(encoded) + "\n\n")
}

// probed returns object with a new probe field added.
func (stream *probes) probed(object map[string]any) map[string]any {
	object["x_probe"] = stream.next()
	return object
}

type m = map[string]any

func anthropicProbeStream() *probes {
	stream := newProbes()
	ev := func(typed string, fields m) { stream.event(typed, typed, fields) }
	ev("message_start", m{"message": stream.probed(m{"id": "msg_probe", "type": "message", "role": "assistant", "model": "model-example",
		"content": []any{}, "stop_reason": nil, "stop_sequence": nil, "usage": m{"input_tokens": 3, "output_tokens": 1}})})
	ev("ping", m{})
	ev("content_block_start", m{"index": 0, "content_block": stream.probed(m{"type": "thinking", "thinking": "", "signature": ""})})
	ev("content_block_delta", m{"index": 0, "delta": stream.probed(m{"type": "thinking_delta", "thinking": "consider"})})
	ev("content_block_delta", m{"index": 0, "delta": stream.probed(m{"type": "signature_delta", "signature": "signature-probe"})})
	ev("content_block_stop", m{"index": 0})
	ev("content_block_start", m{"index": 1, "content_block": stream.probed(m{"type": "text", "text": ""})})
	ev("content_block_delta", m{"index": 1, "delta": stream.probed(m{"type": "text_delta", "text": "answer"})})
	ev("content_block_delta", m{"index": 1, "delta": stream.probed(m{"type": "citations_delta", "citation": m{"type": "char_location",
		"cited_text": "ans", "document_index": 0, "start_char_index": 0, "end_char_index": 3}})})
	// A delta type no parser knows.
	ev("content_block_delta", m{"index": 1, "delta": m{"type": "x_probe_delta", "value": stream.next()}})
	ev("content_block_stop", m{"index": 1})
	ev("content_block_start", m{"index": 2, "content_block": stream.probed(m{"type": "tool_use", "id": "toolu_probe", "name": "lookup", "input": m{}})})
	ev("content_block_delta", m{"index": 2, "delta": stream.probed(m{"type": "input_json_delta", "partial_json": `{"q":`})})
	ev("content_block_delta", m{"index": 2, "delta": m{"type": "input_json_delta", "partial_json": `"x"}`}})
	ev("content_block_stop", m{"index": 2})
	// An event type no parser knows.
	stream.event("x_probe_event", "x_probe_event", m{"value": stream.next()})
	ev("message_delta", m{"delta": stream.probed(m{"stop_reason": "end_turn", "stop_sequence": nil}), "usage": stream.probed(m{"output_tokens": 7})})
	ev("message_stop", m{})
	return stream
}

func chatProbeStream() *probes {
	stream := newProbes()
	chunk := func(fields m) m {
		for key, value := range (m{"id": "chatcmpl-probe", "object": "chat.completion.chunk", "created": 1, "model": "model-example",
			"system_fingerprint": "fp_probe", "service_tier": "default"}) {
			fields[key] = value
		}
		return fields
	}
	choice := func(fields m) []any { return []any{stream.probed(fields)} }
	stream.event("", "", chunk(m{"choices": choice(m{"index": 0, "delta": stream.probed(m{"role": "assistant", "content": "", "refusal": nil}),
		"logprobs": nil, "finish_reason": nil})}))
	stream.event("", "", chunk(m{"choices": choice(m{"index": 0, "delta": stream.probed(m{"reasoning_content": "think"})})}))
	stream.event("", "", chunk(m{"choices": choice(m{"index": 0, "delta": m{"reasoning": "more", "thinking": "still"}})}))
	stream.event("", "", chunk(m{"choices": choice(m{"index": 0, "delta": m{"content": "Hel", "name": "assistant-name"},
		"logprobs": stream.probed(m{"content": []any{m{"token": "Hel", "logprob": -0.5, "bytes": []any{72, 101, 108}, "top_logprobs": []any{}}}, "refusal": nil})})}))
	stream.event("", "", chunk(m{"choices": choice(m{"index": 0, "delta": m{"content": "lo", "refusal": "no"}})}))
	stream.event("", "", chunk(m{"choices": choice(m{"index": 0, "delta": m{"tool_calls": []any{stream.probed(m{"index": 0, "id": "call_probe", "type": "function",
		"function": stream.probed(m{"name": "lookup", "arguments": ""})})}}})}))
	stream.event("", "", chunk(m{"choices": choice(m{"index": 0, "delta": m{"tool_calls": []any{m{"index": 0, "function": m{"arguments": `{"q":1}`}}}}})}))
	stream.event("", "", chunk(m{"choices": choice(m{"index": 0, "delta": m{"function_call": stream.probed(m{"name": "legacy", "arguments": "{}"})}})}))
	// A second choice that sends its whole message; its delta stays in the
	// residue.
	stream.event("", "", chunk(m{"choices": choice(m{"index": 1, "message": stream.probed(m{"role": "assistant", "content": "other"}), "finish_reason": "stop"})}))
	stream.event("", "", chunk(m{"choices": choice(m{"index": 1, "delta": stream.probed(m{"content": "ignored"})})}))
	stream.event("", "", chunk(m{"choices": choice(m{"index": 0, "delta": m{}, "finish_reason": "tool_calls"})}))
	stream.event("", "", chunk(m{"choices": []any{}, "usage": stream.probed(m{"prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7})}))
	// An event of a shape no parser knows.
	stream.event("x_probe", "x.probe", m{"value": stream.next()})
	stream.body.WriteString("data: [DONE]\n\n")
	return stream
}

func completionsProbeStream() *probes {
	stream := newProbes()
	chunk := func(choice m) m {
		return m{"id": "cmpl-probe", "object": "text_completion", "created": 1, "model": "model-example", "choices": []any{stream.probed(choice)}}
	}
	stream.event("", "", chunk(m{"index": 0, "text": "an", "logprobs": nil, "finish_reason": nil}))
	stream.event("", "", chunk(m{"index": 0, "text": "swer", "finish_reason": "stop",
		"logprobs": stream.probed(m{"tokens": []any{"swer"}, "token_logprobs": []any{-0.1}, "top_logprobs": nil, "text_offset": []any{2}})}))
	stream.body.WriteString("data: [DONE]\n\n")
	return stream
}

// responsesProbeStream covers every Responses event type the fold consumes
// in a stream that ends with terminal, completed, incomplete or failed.
func responsesProbeStream(terminal string) *probes {
	stream := newProbes()
	sequence := 0
	ev := func(typed string, fields m) {
		fields["sequence_number"] = sequence
		sequence++
		stream.event(typed, typed, fields)
	}
	reasoningDone := m{"id": "rs_probe", "type": "reasoning", "summary": []any{m{"type": "summary_text", "text": "thinking"}},
		"content": []any{m{"type": "reasoning_text", "text": "raw"}}}
	messageDone := m{"id": "msg_probe", "type": "message", "status": "completed", "role": "assistant", "content": []any{
		m{"type": "output_text", "text": "Hello", "annotations": []any{}, "logprobs": []any{}}, m{"type": "refusal", "refusal": "no"}}}
	callDone := m{"id": "fc_probe", "type": "function_call", "status": "completed", "arguments": `{"q":1}`, "call_id": "call_probe", "name": "lookup"}
	response := func(status string, output []any, usage any) m {
		return m{"id": "resp_probe", "object": "response", "status": status, "model": "model-example", "output": output, "usage": usage}
	}
	ev("response.created", m{"response": stream.probed(response("in_progress", []any{}, nil))})
	ev("response.queued", m{"response": response("queued", []any{}, nil)})
	ev("response.in_progress", m{"response": response("in_progress", []any{}, nil)})
	ev("response.output_item.added", m{"output_index": 0, "item": stream.probed(m{"id": "rs_probe", "type": "reasoning", "summary": []any{}})})
	ev("response.reasoning_summary_part.added", m{"item_id": "rs_probe", "output_index": 0, "summary_index": 0, "part": stream.probed(m{"type": "summary_text", "text": ""})})
	ev("response.reasoning_summary_text.delta", m{"item_id": "rs_probe", "output_index": 0, "summary_index": 0, "delta": "thin"})
	ev("response.reasoning_summary_text.delta", m{"item_id": "rs_probe", "output_index": 0, "summary_index": 0, "delta": "king"})
	ev("response.reasoning_summary_text.done", m{"item_id": "rs_probe", "output_index": 0, "summary_index": 0, "text": "thinking"})
	ev("response.reasoning_summary_part.done", m{"item_id": "rs_probe", "output_index": 0, "summary_index": 0, "part": m{"type": "summary_text", "text": "thinking"}})
	ev("response.reasoning_text.delta", m{"item_id": "rs_probe", "output_index": 0, "content_index": 0, "delta": "raw"})
	ev("response.reasoning_text.done", m{"item_id": "rs_probe", "output_index": 0, "content_index": 0, "text": "raw"})
	ev("response.output_item.done", m{"output_index": 0, "item": reasoningDone})
	ev("response.output_item.added", m{"output_index": 1, "item": m{"id": "msg_probe", "type": "message", "status": "in_progress", "role": "assistant", "content": []any{}}})
	ev("response.content_part.added", m{"item_id": "msg_probe", "output_index": 1, "content_index": 0, "part": m{"type": "output_text", "text": "", "annotations": []any{}, "logprobs": []any{}}})
	ev("response.output_text.delta", m{"item_id": "msg_probe", "output_index": 1, "content_index": 0, "delta": "Hel", "logprobs": []any{}})
	ev("response.output_text.delta", m{"item_id": "msg_probe", "output_index": 1, "content_index": 0, "delta": "lo", "logprobs": []any{}})
	ev("response.output_text.done", m{"item_id": "msg_probe", "output_index": 1, "content_index": 0, "text": "Hello", "logprobs": []any{}})
	ev("response.content_part.done", m{"item_id": "msg_probe", "output_index": 1, "content_index": 0, "part": m{"type": "output_text", "text": "Hello", "annotations": []any{}, "logprobs": []any{}}})
	ev("response.content_part.added", m{"item_id": "msg_probe", "output_index": 1, "content_index": 1, "part": m{"type": "refusal", "refusal": ""}})
	ev("response.refusal.delta", m{"item_id": "msg_probe", "output_index": 1, "content_index": 1, "delta": "no"})
	ev("response.refusal.done", m{"item_id": "msg_probe", "output_index": 1, "content_index": 1, "refusal": "no"})
	ev("response.content_part.done", m{"item_id": "msg_probe", "output_index": 1, "content_index": 1, "part": m{"type": "refusal", "refusal": "no"}})
	ev("response.output_item.done", m{"output_index": 1, "item": messageDone})
	ev("response.output_item.added", m{"output_index": 2, "item": m{"id": "fc_probe", "type": "function_call", "status": "in_progress", "arguments": "", "call_id": "call_probe", "name": "lookup"}})
	ev("response.function_call_arguments.delta", m{"item_id": "fc_probe", "output_index": 2, "delta": `{"q":`})
	ev("response.function_call_arguments.delta", m{"item_id": "fc_probe", "output_index": 2, "delta": `1}`})
	ev("response.function_call_arguments.done", m{"item_id": "fc_probe", "output_index": 2, "arguments": `{"q":1}`})
	ev("response.output_item.done", m{"output_index": 2, "item": callDone})
	// An event type no parser knows.
	ev("response.x_probe.added", m{"value": stream.next()})
	final := response("completed", []any{reasoningDone, messageDone, callDone}, m{"input_tokens": 5, "output_tokens": 6, "total_tokens": 11})
	switch terminal {
	case "response.incomplete":
		final["status"] = "incomplete"
		final["incomplete_details"] = m{"reason": "max_output_tokens"}
	case "response.failed":
		final["status"] = "failed"
		final["error"] = m{"code": "server_error", "message": "failed"}
	}
	ev(terminal, m{"response": stream.probed(final)})
	return stream
}

// TestUnknownFieldsSurviveRelease puts a field no parser reads on every
// event type each stream fold consumes (and on the nested objects it reads),
// adds an event type and a delta type it does not know, and requires every
// value back from the turn rebuilt from its sealed objects without the raw
// bytes. It also requires the probe streams to cover every consumed event
// type the parsers list, so a new consumed type needs a probe.
func TestUnknownFieldsSurviveRelease(t *testing.T) {
	t.Parallel()
	cipher := testCipher(t)
	type probeCase struct {
		label, parser, protocol, path, request string
		stream                                 *probes
	}
	cases := []probeCase{
		{"anthropic", "anthropic.messages", "anthropic", "/v1/messages", `{"model":"model-example","max_tokens":64,"stream":true,"messages":[{"role":"user","content":"hi"}]}`, anthropicProbeStream()},
		{"chat", "openai.chat_completions", "openai", "/v1/chat/completions", `{"model":"model-example","stream":true,"messages":[{"role":"user","content":"hi"}]}`, chatProbeStream()},
		{"completions", "openai.completions", "openai", "/v1/completions", `{"model":"model-example","stream":true,"prompt":"hi"}`, completionsProbeStream()},
	}
	for _, terminal := range []string{"response.completed", "response.incomplete", "response.failed"} {
		for _, parser := range []string{"openai.responses", "openai.responses_compact"} {
			cases = append(cases, probeCase{parser + "/" + terminal, parser, "openai", "/v1/responses",
				`{"model":"model-example","stream":true,"input":[{"role":"user","content":"hi"}]}`, responsesProbeStream(terminal)})
		}
	}
	coveredAnthropic, coveredResponses := map[string]bool{}, map[string]bool{}
	for _, test := range cases {
		status := 200
		input := base.Input{AuditID: "apx_probe", Protocol: test.protocol, Endpoint: test.path, StatusCode: &status,
			Request: jsonBody(test.request), Response: sseBody(test.stream.body.String())}
		value, err := storeAndRebuild(t, cipher, test.parser, input)
		if err != nil {
			t.Fatalf("%s: %v", test.label, err)
		}
		if layout := value.turn.ResponseLayout; !auditmodel.StreamLayout(layout) {
			t.Fatalf("%s: response layout %q", test.label, layout)
		}
		rebuilt, err := auditmodel.CanonicalJSON(value.response)
		if err != nil {
			t.Fatal(err)
		}
		for _, probe := range test.stream.values {
			if !bytes.Contains(rebuilt, []byte(`"`+probe+`"`)) {
				t.Errorf("%s: %s is lost after release", test.label, probe)
			}
		}
		checkFidelity(t, test.label, test.parser, input, value)
		for typed := range test.stream.types {
			if test.parser == "anthropic.messages" {
				coveredAnthropic[typed] = true
			} else {
				coveredResponses[typed] = true
			}
		}
		if test.parser == "anthropic.messages" {
			for _, event := range base.DecodeSSE(input.Response.Data) {
				var root map[string]any
				_ = json.Unmarshal(event.Data, &root)
				if delta, _ := root["delta"].(map[string]any); delta != nil {
					if typed, _ := delta["type"].(string); typed != "" {
						coveredAnthropic["delta:"+typed] = true
					}
				}
			}
		}
		if test.parser == "openai.chat_completions" || test.parser == "openai.completions" {
			body := test.stream.body.String()
			for _, fields := range [][]string{openai.ConsumedChatChunkFields, openai.ConsumedChatChoiceFields, openai.ConsumedChatDeltaFields,
				openai.ConsumedChatToolCallFields, openai.ConsumedChatFunctionFields} {
				for _, field := range fields {
					if test.parser == "openai.chat_completions" && field != "text" && !strings.Contains(body, `"`+field+`":`) {
						t.Errorf("%s: probe stream never sends consumed field %q", test.label, field)
					}
				}
			}
		}
	}
	var missing []string
	for typed := range anthropic.ConsumedStreamEvents {
		if !coveredAnthropic[typed] {
			missing = append(missing, "anthropic "+typed)
		}
	}
	for typed := range anthropic.ConsumedDeltaTypes {
		if !coveredAnthropic["delta:"+typed] {
			missing = append(missing, "anthropic delta "+typed)
		}
	}
	for typed := range openai.ConsumedResponsesEvents {
		if !coveredResponses[typed] {
			missing = append(missing, "responses "+typed)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("consumed event types without a probe: %q", missing)
	}
}
