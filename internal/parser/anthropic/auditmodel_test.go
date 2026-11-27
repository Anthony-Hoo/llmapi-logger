package anthropic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"llmapi-logger/internal/auditmodel"
	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/security"
)

const streamFixture = "" +
	"event: message_start\n" +
	`data: {"type":"message_start","message":{"id":"msg_stream","type":"message","role":"assistant","model":"model-example","content":[],"usage":{"input_tokens":7,"cache_read_input_tokens":500,"cache_creation_input_tokens":40,"output_tokens":1}}}` + "\n\n" +
	"event: content_block_start\n" +
	`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n\n" +
	"event: content_block_delta\n" +
	`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello "}}` + "\n\n" +
	"event: content_block_delta\n" +
	`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"world"}}` + "\n\n" +
	"event: content_block_stop\n" +
	`data: {"type":"content_block_stop","index":0}` + "\n\n" +
	"event: message_delta\n" +
	`data: {"type":"message_delta","delta":{"stop_reason":"max_tokens"},"usage":{"output_tokens":9}}` + "\n\n" +
	"event: message_stop\n" +
	`data: {"type":"message_stop"}` + "\n\n"

func normalizerCipher(t *testing.T) *security.AESGCM {
	t.Helper()
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{0x42}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

func messagesInput(auditID, request, response, responseType string) base.Input {
	input := base.Input{AuditID: auditID, Protocol: "anthropic", Endpoint: "/v1/messages"}
	if request != "" {
		input.Request = base.BodySource{Present: true, Complete: true, ContentType: "application/json", Data: []byte(request)}
	}
	if response != "" {
		input.Response = base.BodySource{Present: true, Complete: true, ContentType: responseType, Data: []byte(response)}
	}
	return input
}

// normalize parses and normalizes one audit and proves the split is lossless:
// Prepare fails unless the assembled values equal the provider originals.
func normalize(t *testing.T, input base.Input) (auditmodel.Turn, auditmodel.PreparedTurn, base.Result) {
	t.Helper()
	parser := New()
	result := parser.Parse(context.Background(), input)
	if result.Status != base.StatusOK {
		t.Fatalf("parse status = %q (%s)", result.Status, result.ErrorCode)
	}
	turn, err := parser.NormalizeAudit(context.Background(), input, result)
	if err != nil {
		t.Fatal(err)
	}
	turn.CreatedAtNS = 1
	prepared, err := auditmodel.Prepare(turn, normalizerCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	return turn, prepared, result
}

func canonical(t *testing.T, value any) string {
	t.Helper()
	encoded, err := auditmodel.CanonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func decoded(t *testing.T, body string) any {
	t.Helper()
	var value any
	if err := auditmodel.DecodeJSON([]byte(body), &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func slots(items []auditmodel.Item) string {
	names := make([]string, 0, len(items))
	for _, item := range items {
		names = append(names, item.Slot)
	}
	return strings.Join(names, ",")
}

func TestNormalizeRequestSplitsMessagesAndSystem(t *testing.T) {
	t.Parallel()
	const messages = `"messages":[{"role":"user","content":"first"},{"role":"assistant","content":[{"type":"text","text":"second"}]}]`
	for _, test := range []struct {
		name, system, layout, slots string
		systemInEnvelope            bool
	}{
		{name: "no system", layout: auditmodel.LayoutAnthropicMessagesRequestSystemNone, slots: "messages,messages"},
		{name: "null system", system: `"system":null,`, layout: auditmodel.LayoutAnthropicMessagesRequestSystemNone, slots: "messages,messages", systemInEnvelope: true},
		{name: "string system", system: `"system":"be brief",`, layout: auditmodel.LayoutAnthropicMessagesRequestSystemSingle, slots: "messages,messages,system"},
		{name: "empty string system", system: `"system":"",`, layout: auditmodel.LayoutAnthropicMessagesRequestSystemSingle, slots: "messages,messages,system"},
		{name: "block system", system: `"system":[{"type":"text","text":"header"},{"type":"text","text":"be brief","cache_control":{"type":"ephemeral"}}],`,
			layout: auditmodel.LayoutAnthropicMessagesRequestSystemArray, slots: "messages,messages,system,system"},
		{name: "empty block system", system: `"system":[],`, layout: auditmodel.LayoutAnthropicMessagesRequestSystemArray, slots: "messages,messages"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			body := `{"model":"model-example","max_tokens":64,` + test.system + `"tools":[{"name":"lookup","input_schema":{"type":"object"}}],` + messages + `}`
			turn, _, _ := normalize(t, messagesInput("audit-request", body, "", ""))
			if turn.RequestLayout != test.layout || slots(turn.RequestItems) != test.slots {
				t.Fatalf("layout/slots = %s / %s", turn.RequestLayout, slots(turn.RequestItems))
			}
			envelope := turn.RequestEnvelope.(map[string]any)
			if _, exists := envelope["messages"]; exists {
				t.Fatal("messages left in the envelope")
			}
			if _, exists := envelope["system"]; exists != test.systemInEnvelope {
				t.Fatalf("system in envelope = %v", exists)
			}
			if _, exists := envelope["tools"]; !exists {
				t.Fatal("tools must stay in the envelope")
			}
			rebuilt, err := auditmodel.Assemble(turn.RequestLayout, turn.RequestEnvelope, turn.RequestItems)
			if err != nil {
				t.Fatal(err)
			}
			if canonical(t, rebuilt) != canonical(t, decoded(t, body)) {
				t.Fatalf("rebuilt request = %s", canonical(t, rebuilt))
			}
		})
	}
}

func TestNormalizeRejectsRequestsItCannotSplit(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"no messages":        `{"model":"model-example"}`,
		"messages not array": `{"model":"model-example","messages":"hi"}`,
		"not an object":      `["model-example"]`,
		"item marker":        `{"messages":[{"role":"user","content":{"$llmapi_logger_item_v1":0}}]}`,
		"binary marker":      `{"messages":[],"metadata":{"$llmapi_logger_binary_v1":{}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			input := messagesInput("audit-reject", body, "", "")
			if _, err := New().NormalizeAudit(context.Background(), input, base.Result{}); err == nil {
				t.Fatal("normalization accepted the request")
			}
		})
	}
	input := messagesInput("audit-reject", `{"messages":[]}`, `{"content":[{"$llmapi_logger_item_v1":0}]}`, "application/json")
	if _, err := New().NormalizeAudit(context.Background(), input, base.Result{}); !errors.Is(err, auditmodel.ErrReservedMarker) {
		t.Fatalf("response marker error = %v", err)
	}
}

func TestAssembleRejectsSystemItemsThatDoNotFitTheLayout(t *testing.T) {
	t.Parallel()
	system := auditmodel.Item{Slot: auditmodel.SlotSystem, Kind: "system", Value: "be brief"}
	envelope := map[string]any{"model": "model-example"}
	for name, test := range map[string]struct {
		layout string
		items  []auditmodel.Item
	}{
		"none with a system item":    {auditmodel.LayoutAnthropicMessagesRequestSystemNone, []auditmodel.Item{system}},
		"single without system item": {auditmodel.LayoutAnthropicMessagesRequestSystemSingle, nil},
		"single with two items":      {auditmodel.LayoutAnthropicMessagesRequestSystemSingle, []auditmodel.Item{system, system}},
	} {
		if _, err := auditmodel.Assemble(test.layout, envelope, test.items); !errors.Is(err, auditmodel.ErrReconstruction) {
			t.Fatalf("%s: error = %v", name, err)
		}
	}
	if _, err := auditmodel.Assemble(auditmodel.LayoutAnthropicMessagesRequestSystemArray, "not an object", nil); !errors.Is(err, auditmodel.ErrReconstruction) {
		t.Fatalf("non-object envelope: error = %v", err)
	}
}

// A client resends the history with every call, moves cache_control to the
// newest message and may change the first system block per request.
func TestResentHistoryReusesObjectsAndKeepsTheMessagePrefix(t *testing.T) {
	t.Parallel()
	request := func(header string, messages string) string {
		return `{"model":"model-example","max_tokens":64,"tools":[{"name":"lookup","input_schema":{"type":"object"}}],` +
			`"system":[{"type":"text","text":"` + header + `"},{"type":"text","text":"stable instructions"}],"messages":[` + messages + `]}`
	}
	const first = `{"role":"user","content":"first question"}`
	_, earlier, _ := normalize(t, messagesInput("audit-earlier", request("request 1", first), "", ""))
	_, later, _ := normalize(t, messagesInput("audit-later", request("request 2",
		first+`,{"role":"assistant","content":"an answer"},{"role":"user","content":"second question"}`), "", ""))

	if !bytes.Equal(earlier.RequestEnvelopeHash, later.RequestEnvelopeHash) {
		t.Fatal("a changed system block or message list changed the envelope")
	}
	if len(earlier.RequestRefs) != 3 || len(later.RequestRefs) != 5 {
		t.Fatalf("ref counts = %d / %d", len(earlier.RequestRefs), len(later.RequestRefs))
	}
	if !bytes.Equal(earlier.RequestRefs[0].ObjectHash, later.RequestRefs[0].ObjectHash) {
		t.Fatal("the resent first message is not the first ref of both turns")
	}
	stored := make(map[string]bool)
	for _, object := range earlier.Objects {
		stored[string(object.Hash)] = true
	}
	added := 0
	for _, object := range later.Objects {
		if !stored[string(object.Hash)] {
			added++
		}
	}
	// Two new messages and the changed system header; the envelope, the first
	// message and the stable system block are reused.
	if added != 3 {
		t.Fatalf("later turn adds %d objects, want 3", added)
	}

	// Unrelated sessions of one client share the system prompt, which must
	// not look like a common history prefix.
	_, other, _ := normalize(t, messagesInput("audit-other", request("request 1", `{"role":"user","content":"another topic"}`), "", ""))
	if bytes.Equal(earlier.RequestRefs[0].SemanticHash, other.RequestRefs[0].SemanticHash) {
		t.Fatal("sessions that share only the system prompt share a sequence prefix")
	}
}

func TestNormalizeJSONResponseItemizesContentBlocks(t *testing.T) {
	t.Parallel()
	const request = `{"model":"model-example","max_tokens":64,"system":"be brief","messages":[{"role":"user","content":"question"}]}`
	const response = `{"id":"msg_json","type":"message","role":"assistant","model":"model-example",` +
		`"content":[{"type":"thinking","thinking":"consider","signature":"sig"},{"type":"text","text":"answer"},{"type":"tool_use","id":"toolu_1","name":"lookup","input":{"q":"x"}}],` +
		`"stop_reason":"tool_use","usage":{"input_tokens":20,"cache_read_input_tokens":300,"output_tokens":3}}`
	turn, _, result := normalize(t, messagesInput("audit-json", request, response, "application/json"))
	if turn.ResponseLayout != auditmodel.LayoutMarkerEnvelope || slots(turn.ResponseItems) != "content,content,content" {
		t.Fatalf("layout/slots = %s / %s", turn.ResponseLayout, slots(turn.ResponseItems))
	}
	if kinds := turn.ResponseItems[0].Kind + "," + turn.ResponseItems[1].Kind + "," + turn.ResponseItems[2].Kind; kinds != "thinking,text,tool_use" {
		t.Fatalf("kinds = %s", kinds)
	}
	if turn.ResponseID != "msg_json" || turn.ConversationKey != "" || turn.PreviousResponseID != "" {
		t.Fatalf("turn identity = %q %q %q", turn.ResponseID, turn.ConversationKey, turn.PreviousResponseID)
	}
	rebuiltRequest, err := auditmodel.Assemble(turn.RequestLayout, turn.RequestEnvelope, turn.RequestItems)
	if err != nil {
		t.Fatal(err)
	}
	rebuiltResponse, err := auditmodel.Assemble(turn.ResponseLayout, turn.ResponseEnvelope, turn.ResponseItems)
	if err != nil {
		t.Fatal(err)
	}
	if canonical(t, rebuiltResponse) != canonical(t, decoded(t, response)) {
		t.Fatalf("rebuilt response = %s", canonical(t, rebuiltResponse))
	}
	assertSameConversation(t, rebuiltRequest, rebuiltResponse, turn.ResponseLayout, result)

	// An error body has no content array; it is kept whole.
	failed, _, _ := normalize(t, messagesInput("audit-error", request, `{"type":"error","error":{"type":"overloaded_error","message":"busy"}}`, "application/json"))
	if len(failed.ResponseItems) != 0 || canonical(t, failed.ResponseEnvelope) != canonical(t, failed.ResponseOriginal) {
		t.Fatalf("error response items = %d", len(failed.ResponseItems))
	}
}

func TestNormalizeStreamResponseKeepsDescriptionAggregateResidueAndCacheUsage(t *testing.T) {
	t.Parallel()
	const request = `{"model":"model-example","max_tokens":64,"stream":true,"messages":[{"role":"user","content":"question"}]}`
	turn, _, result := normalize(t, messagesInput("audit-stream", request, streamFixture, "text/event-stream"))
	if turn.ResponseLayout != auditmodel.LayoutAnthropicStreamResponse || len(turn.ResponseItems) != 1 ||
		turn.ResponseItems[0].Slot != auditmodel.SlotAggregate || turn.ResponseItems[0].Kind != "stream_body" {
		t.Fatalf("layout/items = %s / %+v", turn.ResponseLayout, turn.ResponseItems)
	}
	// The aggregate is the body the answer has without streaming.
	wantBody := `{"content":[{"text":"hello world","type":"text"}],"id":"msg_stream","model":"model-example","role":"assistant",` +
		`"stop_reason":"max_tokens","type":"message","usage":{"cache_creation_input_tokens":40,"cache_read_input_tokens":500,"input_tokens":7,"output_tokens":9}}`
	if got := canonical(t, turn.ResponseItems[0].Value); got != wantBody {
		t.Fatalf("aggregate = %s", got)
	}
	// message_delta replaced the start usage's output_tokens; the residue
	// keeps the replaced value with the event that sent it.
	if got := canonical(t, turn.ResponseEnvelope.(map[string]any)["residue"]); got != `[{"data":{"message":{"usage":{"output_tokens":1}}},"index":0}]` {
		t.Fatalf("residue = %s", got)
	}
	encoded, err := json.Marshal(turn.ResponseEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Format string `json:"format"`
		Events struct {
			Names   [][2]any `json:"names"`
			Lengths []int    `json:"data_lengths"`
			SHA256  string   `json:"sha256"`
		} `json:"events"`
		Summary struct {
			ResponseID string `json:"response_id"`
			StopReason string `json:"stop_reason"`
			Normalized struct {
				UncachedInput *int64 `json:"uncached_input"`
				CacheRead     *int64 `json:"cache_read"`
				CacheWrite    *int64 `json:"cache_write"`
				Output        *int64 `json:"output"`
			} `json:"normalized_usage"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatal(err)
	}
	names, _ := json.Marshal(envelope.Events.Names)
	if envelope.Format != "sse" || string(names) != `[["message_start",1],["content_block_start",1],["content_block_delta",2],["content_block_stop",1],["message_delta",1],["message_stop",1]]` ||
		len(envelope.Events.Lengths) != 7 || envelope.Events.Lengths[6] != len(`{"type":"message_stop"}`) {
		t.Fatalf("stream envelope = %s", encoded)
	}
	// A reader holding the raw SSE recomputes the hash from the decoded
	// events by the documented framing.
	digest := sha256.New()
	digest.Write([]byte("llmapi-logger/sse-events/v1\x00"))
	for _, event := range base.DecodeSSE([]byte(streamFixture)) {
		for _, field := range [][]byte{[]byte(event.Event), event.Data} {
			var length [8]byte
			binary.BigEndian.PutUint64(length[:], uint64(len(field)))
			digest.Write(length[:])
			digest.Write(field)
		}
	}
	if want := hex.EncodeToString(digest.Sum(nil)); envelope.Events.SHA256 != want {
		t.Fatalf("events sha256 = %s, recomputed %s", envelope.Events.SHA256, want)
	}
	usage := envelope.Summary.Normalized
	if envelope.Summary.StopReason != "max_tokens" {
		t.Fatalf("stream stop reason = %q", envelope.Summary.StopReason)
	}
	if envelope.Summary.ResponseID != "msg_stream" || usage.UncachedInput == nil || *usage.UncachedInput != 7 ||
		usage.CacheRead == nil || *usage.CacheRead != 500 || usage.CacheWrite == nil || *usage.CacheWrite != 40 ||
		usage.Output == nil || *usage.Output != 9 {
		t.Fatalf("stream summary = %s", encoded)
	}
	if bytes.Contains(encoded, []byte("hello")) {
		t.Fatal("the envelope repeats response text")
	}
	rebuiltRequest, err := auditmodel.Assemble(turn.RequestLayout, turn.RequestEnvelope, turn.RequestItems)
	if err != nil {
		t.Fatal(err)
	}
	rebuiltResponse, err := auditmodel.Assemble(turn.ResponseLayout, turn.ResponseEnvelope, turn.ResponseItems)
	if err != nil {
		t.Fatal(err)
	}
	assertSameConversation(t, rebuiltRequest, rebuiltResponse, turn.ResponseLayout, result)

	if _, err := New().NormalizeAudit(context.Background(), messagesInput("audit-empty", request, ": keep-alive\n\n", "text/event-stream"), base.Result{}); err == nil {
		t.Fatal("a stream without events was normalized")
	}
}

// assertSameConversation checks that the conversation projected from the
// rebuilt values is the one the parser produced from the raw bodies.
func assertSameConversation(t *testing.T, request, response any, responseLayout string, result base.Result) {
	t.Helper()
	view, err := ReconstructedConversation(request, response, responseLayout)
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(result.Conversation)
	if err != nil {
		t.Fatal(err)
	}
	if view == nil || len(view.Messages) < 2 || !bytes.Equal(got, want) {
		t.Fatalf("reconstructed conversation = %s\nparsed conversation = %s", got, want)
	}
}

// A session id the client declares is the conversation key; a bare user id
// is not, or every session of that user would share one conversation.
func TestConversationKeyIsTheDeclaredSessionOnly(t *testing.T) {
	t.Parallel()
	key := func(metadata string) string {
		body := `{"model":"model-example","max_tokens":8,` + metadata + `"messages":[{"role":"user","content":"hi"}]}`
		turn, _, _ := normalize(t, messagesInput("audit-key", body, "", ""))
		return turn.ConversationKey
	}
	object := key(`"metadata":{"user_id":"{\"device_id\":\"device-example\",\"session_id\":\"session-one\"}"},`)
	legacy := key(`"metadata":{"user_id":"user_example_account_example_session_session-one"},`)
	other := key(`"metadata":{"user_id":"{\"device_id\":\"device-example\",\"session_id\":\"session-two\"}"},`)
	direct := key(`"metadata":{"session_id":"session-one"},`)
	if object == "" || object != legacy || object != direct || object == other || !strings.HasSuffix(object, "session-one") {
		t.Fatalf("keys = %q / %q / %q / %q", object, legacy, direct, other)
	}
	for name, metadata := range map[string]string{
		"no metadata":  "",
		"bare user id": `"metadata":{"user_id":"user-example"},`,
	} {
		if got := key(metadata); got != "" {
			t.Fatalf("%s: key = %q", name, got)
		}
	}
}

// Tool arguments are caller-defined JSON. A key that happens to be named like
// an inline file must not be decoded as base64 and re-encoded on rebuild.
func TestToolArgumentsNamedLikeInlineFilesStayText(t *testing.T) {
	t.Parallel()
	const body = `{"model":"model-example","max_tokens":8,"messages":[{"role":"user","content":"write it"},` +
		`{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"create_file","input":{"path":"a.go","file_content":"ab","file_data":"package main\\n","attachment_data":"QQ"}}]}]}`
	turn, prepared, _ := normalize(t, messagesInput("audit-tool-input", body, "", ""))
	if len(prepared.Binaries) != 0 {
		t.Fatalf("tool arguments produced %d binary objects", len(prepared.Binaries))
	}
	rebuilt, err := auditmodel.Assemble(turn.RequestLayout, turn.RequestEnvelope, turn.RequestItems)
	if err != nil {
		t.Fatal(err)
	}
	if canonical(t, rebuilt) != canonical(t, decoded(t, body)) {
		t.Fatalf("rebuilt request = %s", canonical(t, rebuilt))
	}

	// The same holds for the arguments of a tool call in the response.
	const response = `{"id":"msg_tool","type":"message","role":"assistant","model":"model-example",` +
		`"content":[{"type":"tool_use","id":"toolu_2","name":"create_file","input":{"file_content":"ab"}}],"stop_reason":"tool_use"}`
	answered, prepared, _ := normalize(t, messagesInput("audit-tool-output", body, response, "application/json"))
	rebuiltResponse, err := auditmodel.Assemble(answered.ResponseLayout, answered.ResponseEnvelope, answered.ResponseItems)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.Binaries) != 0 || canonical(t, rebuiltResponse) != canonical(t, decoded(t, response)) {
		t.Fatalf("rebuilt response = %s", canonical(t, rebuiltResponse))
	}
}

// Data URLs follow the shared rule of module 18, wherever the string sits: a
// base64 data URL is addressed by its decoded bytes, and a string that starts
// like one but cannot be read as one fails the turn, which keeps the raw body.
func TestDataURLStringsFollowTheSharedRule(t *testing.T) {
	t.Parallel()
	body := func(text string) base.Input {
		encoded, err := json.Marshal(text)
		if err != nil {
			t.Fatal(err)
		}
		return messagesInput("audit-data-url", `{"model":"model-example","max_tokens":8,"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":`+string(encoded)+`}]}]}`, "", "")
	}
	_, prepared, _ := normalize(t, body("data:text/plain;base64,aGVsbG8="))
	if len(prepared.Binaries) != 1 {
		t.Fatalf("data URL produced %d binary objects", len(prepared.Binaries))
	}
	if _, prepared, _ = normalize(t, body(`data: {"a":1,"b":2}`)); len(prepared.Binaries) != 0 {
		t.Fatal("a data: prefix without base64 was extracted")
	}
	for _, text := range []string{"data: [DONE]", "data:text/plain;base64,not base64, just text"} {
		input := body(text)
		turn, err := New().NormalizeAudit(context.Background(), input, base.Result{})
		if err != nil {
			t.Fatal(err)
		}
		turn.CreatedAtNS = 1
		if _, err := auditmodel.Prepare(turn, normalizerCipher(t)); !errors.Is(err, auditmodel.ErrInvalidModel) {
			t.Fatalf("%q: prepare error = %v", text, err)
		}
	}
}
