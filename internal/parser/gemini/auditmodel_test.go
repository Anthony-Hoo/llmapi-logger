package gemini

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"llmapi-logger/internal/auditmodel"
	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/security"
)

func testCipher(t *testing.T) security.Cipher {
	t.Helper()
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

func requestBody(text string) base.BodySource {
	return base.BodySource{Present: true, Complete: true, ContentType: "application/json", Data: []byte(text)}
}

func sseResponse(chunks ...string) base.BodySource {
	var body strings.Builder
	for _, chunk := range chunks {
		body.WriteString("data: " + chunk + "\r\n\r\n")
	}
	return base.BodySource{Present: true, Complete: true, ContentType: "text/event-stream", Data: []byte(body.String())}
}

// normalize parses, normalizes and prepares one exchange.
func normalize(t *testing.T, name string, request, response base.BodySource) (base.Result, auditmodel.Turn, auditmodel.PreparedTurn) {
	t.Helper()
	implementation, err := New(name)
	if err != nil {
		t.Fatal(err)
	}
	input := base.Input{AuditID: "apx_gemini", Protocol: "gemini", Endpoint: "/v1beta/models/model-example:generateContent", Request: request, Response: response}
	result := implementation.Parse(context.Background(), input)
	if result.Status != base.StatusOK {
		t.Fatalf("parse status %s (%s)", result.Status, result.ErrorCode)
	}
	turn, err := implementation.NormalizeAudit(context.Background(), input, result)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	turn.AuditID, turn.Protocol, turn.ParserName, turn.CreatedAtNS = "apx_gemini", "gemini", name, 1
	prepared, err := auditmodel.Prepare(turn, testCipher(t))
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	return result, turn, prepared
}

func hashes(refs []auditmodel.ObjectRef) map[string]bool {
	result := map[string]bool{}
	for _, ref := range refs {
		result[hex.EncodeToString(ref.ObjectHash)] = true
	}
	return result
}

// TestResentAnswerIsTheSameObject: the content of a candidate is stored as
// the object the client sends back as a contents entry when it resends the
// history as it came, for a non-stream and a streamed answer alike. Two turns
// share the first turn's user content, its answer and the system
// instruction; the second turn stores only its new user content, its own
// answer and the response envelope.
func TestResentAnswerIsTheSameObject(t *testing.T) {
	t.Parallel()
	system := `{"parts":[{"text":"Be brief."}]}`
	user1 := `{"role":"user","parts":[{"text":"look up x"}]}`
	answer1 := `{"role":"model","parts":[{"text":"Looking it up."},{"functionCall":{"name":"lookup","args":{"q":"x"}},"thoughtSignature":"c2lnbmF0dXJl"}]}`
	result1 := `{"role":"user","parts":[{"functionResponse":{"name":"lookup","response":{"output":"found"}}}]}`
	answer2 := `{"role":"model","parts":[{"text":"Found it."}]}`
	request := func(contents ...string) base.BodySource {
		return requestBody(`{"systemInstruction":` + system + `,"contents":[` + strings.Join(contents, ",") + `],"generationConfig":{"temperature":0}}`)
	}
	usage := `"usageMetadata":{"promptTokenCount":9,"candidatesTokenCount":3,"totalTokenCount":12},"modelVersion":"model-example"`
	plain := func(content string) base.BodySource {
		return requestBody(`{"candidates":[{"content":` + content + `,"finishReason":"STOP","index":0}],` + usage +
			fmt.Sprintf(`,"responseId":"resp-%d"}`, len(content)))
	}
	streams := map[string]base.BodySource{
		answer1: sseResponse(
			`{"candidates":[{"content":{"role":"model","parts":[{"text":"Looking "}]},"index":0}],"usageMetadata":{"promptTokenCount":9,"candidatesTokenCount":1,"totalTokenCount":10},"modelVersion":"model-example"}`,
			`{"candidates":[{"content":{"role":"model","parts":[{"text":"it up."}]},"index":0}],"usageMetadata":{"promptTokenCount":9,"candidatesTokenCount":2,"totalTokenCount":11},"modelVersion":"model-example"}`,
			`{"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"lookup","args":{"q":"x"}},"thoughtSignature":"c2lnbmF0dXJl"}]},"finishReason":"STOP","index":0}],`+usage+`}`),
		answer2: sseResponse(
			`{"candidates":[{"content":{"role":"model","parts":[{"text":"Found"}]},"index":0}],"usageMetadata":{"promptTokenCount":9,"candidatesTokenCount":1,"totalTokenCount":10},"modelVersion":"model-example"}`,
			`{"candidates":[{"content":{"role":"model","parts":[{"text":" it."}]},"finishReason":"STOP","index":0}],`+usage+`}`),
	}
	for _, mode := range []string{"json", "sse"} {
		response := func(content string) base.BodySource {
			if mode == "sse" {
				return streams[content]
			}
			return plain(content)
		}
		store := map[string]bool{}
		insert := func(prepared auditmodel.PreparedTurn) (inserted []string) {
			for _, object := range prepared.Objects {
				if key := hex.EncodeToString(object.Hash); !store[key] {
					store[key] = true
					inserted = append(inserted, object.Kind)
				}
			}
			return inserted
		}
		_, firstTurn, first := normalize(t, StreamGenerateContent, request(user1), response(answer1))
		_, _, second := normalize(t, StreamGenerateContent, request(user1, answer1, result1), response(answer2))
		firstInserted, secondInserted := insert(first), insert(second)
		if len(first.ResponseRefs) != 1 || !hashes(second.RequestRefs)[hex.EncodeToString(first.ResponseRefs[0].ObjectHash)] {
			t.Fatalf("%s: the second request does not refer to the first answer's object", mode)
		}
		if firstTurn.RequestLayout != auditmodel.LayoutGeminiRequestSystemSingle || firstTurn.ConversationKey != "" {
			t.Fatalf("%s: request layout %q, key %q", mode, firstTurn.RequestLayout, firstTurn.ConversationKey)
		}
		// Turn 1: request envelope, user content, system instruction, answer
		// and response envelope. Turn 2: the tool result, the new answer and
		// the response envelope; its request envelope is turn 1's.
		if len(firstInserted) != 5 || len(secondInserted) != 3 {
			t.Fatalf("%s: objects inserted %q then %q", mode, firstInserted, secondInserted)
		}
		t.Logf("%s: turn 1 inserts %d objects %q; turn 2 refers to %d request items and inserts %d objects %q",
			mode, len(firstInserted), firstInserted, len(second.RequestRefs), len(secondInserted), secondInserted)
	}
}

// TestRequestLayouts covers the request shapes: no, null and one
// systemInstruction, and the refusals.
func TestRequestLayouts(t *testing.T) {
	t.Parallel()
	answer := requestBody(`{"candidates":[{"content":{"role":"model","parts":[{"text":"ok"}]},"finishReason":"STOP"}]}`)
	for _, test := range []struct {
		request, layout string
		items           int
	}{
		{`{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`, auditmodel.LayoutGeminiRequestSystemNone, 1},
		{`{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"systemInstruction":null}`, auditmodel.LayoutGeminiRequestSystemNone, 1},
		{`{"contents":[],"systemInstruction":{"parts":[{"text":"x"}]}}`, auditmodel.LayoutGeminiRequestSystemSingle, 1},
		{`{"contents":[{"parts":[{"text":"a"}]},{"role":"model","parts":[{"text":"b"}]}],"systemInstruction":{"parts":[{"text":"x"}]},"cachedContent":"cachedContents/example"}`,
			auditmodel.LayoutGeminiRequestSystemSingle, 3},
	} {
		_, turn, _ := normalize(t, GenerateContent, requestBody(test.request), answer)
		if turn.RequestLayout != test.layout || len(turn.RequestItems) != test.items || turn.ResponseLayout != auditmodel.LayoutMarkerEnvelope {
			t.Errorf("%s: layout %q with %d items, response %q", test.request, turn.RequestLayout, len(turn.RequestItems), turn.ResponseLayout)
		}
		if last := turn.RequestItems[len(turn.RequestItems)-1]; test.layout == auditmodel.LayoutGeminiRequestSystemSingle &&
			(last.Slot != auditmodel.SlotSystemInstruction || last.Kind != "system_instruction") {
			t.Errorf("%s: the system instruction is not the last item: %+v", test.request, last)
		}
	}
	implementation, _ := New(GenerateContent)
	for _, request := range []string{`{"systemInstruction":{"parts":[]}}`, `{"contents":{"parts":[]}}`, `{"contents":[{"$llmapi_logger_item_v1":0}]}`} {
		input := base.Input{Request: requestBody(request)}
		if _, err := implementation.NormalizeAudit(context.Background(), input, base.Result{}); err == nil {
			t.Errorf("%s: normalized", request)
		}
	}
}

// TestInlineDataIsABinaryObject: an inlineData part's base64 data is stored
// once as a binary object by its decoded bytes, shared by every request that
// resends it, and comes back as the same string. A string that is not the
// canonical encoding, and a function argument named file_data, stay text.
func TestInlineDataIsABinaryObject(t *testing.T) {
	t.Parallel()
	image := bytes.Repeat([]byte{0x89, 'P', 'N', 'G', 7}, 40)
	data := base64.StdEncoding.EncodeToString(image)
	request := `{"contents":[{"role":"user","parts":[{"text":"look"},{"inlineData":{"mimeType":"image/png","data":"` + data + `"}},` +
		`{"inline_data":{"mime_type":"image/png","data":"` + strings.TrimRight(data, "=") + `"}}]},` +
		`{"role":"model","parts":[{"functionCall":{"name":"save","args":{"file_data":"not base64!"}}}]}]}`
	answer := requestBody(`{"candidates":[{"content":{"role":"model","parts":[{"text":"ok"}]},"finishReason":"STOP"}]}`)
	_, _, prepared := normalize(t, GenerateContent, requestBody(request), answer)
	if len(prepared.Binaries) != 1 || prepared.Binaries[0].PlaintextLength != int64(len(image)) {
		t.Fatalf("binaries = %+v", prepared.Binaries)
	}
	for _, object := range prepared.Objects {
		if object.Kind == "user_content" && (len(object.BinaryRefs) != 1 || object.BinaryRefs[0].JSONPointer != "/parts/1/inlineData/data") {
			t.Fatalf("user content binary refs = %+v", object.BinaryRefs)
		}
	}
	// Without the Gemini rule, as for every other protocol, nothing is
	// extracted.
	implementation, _ := New(GenerateContent)
	input := base.Input{Request: requestBody(request), Response: answer}
	turn, err := implementation.NormalizeAudit(context.Background(), input, implementation.Parse(context.Background(), input))
	if err != nil {
		t.Fatal(err)
	}
	turn.AuditID, turn.Protocol, turn.ParserName, turn.CreatedAtNS, turn.InlineDataParts = "apx", "gemini", GenerateContent, 1, false
	if plain, err := auditmodel.Prepare(turn, testCipher(t)); err != nil || len(plain.Binaries) != 0 {
		t.Fatalf("without the rule: %d binaries, %v", len(plain.Binaries), err)
	}
}

// TestStreamEndings: what ends a Gemini stream, and what it is stored as.
// Every candidate the stream starts must report a finish reason, or the
// prompt must be blocked; a function call ends with STOP. A stream ended by
// an error object, or cut between two chunks, is partial.
func TestStreamEndings(t *testing.T) {
	t.Parallel()
	text := `{"candidates":[{"content":{"role":"model","parts":[{"text":"Hel"}]},"index":0}]}`
	usage := `"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":2,"totalTokenCount":7}`
	for _, test := range []struct {
		name   string
		chunks []string
		status string
		code   string
		stop   string
	}{
		{"stop", []string{text, `{"candidates":[{"content":{"role":"model","parts":[{"text":"lo"}]},"finishReason":"STOP","index":0}],` + usage + `}`}, base.StatusOK, "", "STOP"},
		{"max tokens", []string{text, `{"candidates":[{"content":{"role":"model","parts":[{"text":"l"}]},"finishReason":"MAX_TOKENS","index":0}],` + usage + `}`}, base.StatusOK, "", "MAX_TOKENS"},
		{"safety", []string{text, `{"candidates":[{"finishReason":"SAFETY","index":0,"safetyRatings":[{"category":"HARM_CATEGORY_HARASSMENT","probability":"HIGH","blocked":true}]}],` + usage + `}`}, base.StatusOK, "", "SAFETY"},
		{"function call", []string{`{"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"f","args":{}}}]},"finishReason":"STOP","index":0}],` + usage + `}`}, base.StatusOK, "", "STOP"},
		{"malformed call", []string{`{"candidates":[{"finishReason":"MALFORMED_FUNCTION_CALL","finishMessage":"bad call","index":0}],` + usage + `}`}, base.StatusOK, "", "MALFORMED_FUNCTION_CALL"},
		{"prompt blocked", []string{`{"promptFeedback":{"blockReason":"PROHIBITED_CONTENT"},` + usage + `}`}, base.StatusOK, "", ""},
		{"two candidates", []string{`{"candidates":[{"content":{"role":"model","parts":[{"text":"a"}]},"index":0},{"content":{"role":"model","parts":[{"text":"b"}]},"index":1}]}`,
			`{"candidates":[{"finishReason":"STOP","index":0},{"finishReason":"MAX_TOKENS","index":1}],` + usage + `}`}, base.StatusOK, "", "STOP"},
		{"cut between chunks", []string{text, text}, base.StatusPartial, "missing_finish_reason", ""},
		{"one candidate unfinished", []string{`{"candidates":[{"content":{"role":"model","parts":[{"text":"a"}]},"index":0},{"content":{"role":"model","parts":[{"text":"b"}]},"index":1}]}`,
			`{"candidates":[{"finishReason":"STOP","index":0}]}`}, base.StatusPartial, "missing_finish_reason", ""},
		{"unspecified reason", []string{`{"candidates":[{"content":{"role":"model","parts":[{"text":"a"}]},"finishReason":"FINISH_REASON_UNSPECIFIED","index":0}]}`}, base.StatusPartial, "missing_finish_reason", ""},
		{"unspecified block", []string{`{"promptFeedback":{"blockReason":"BLOCK_REASON_UNSPECIFIED"}}`}, base.StatusPartial, "missing_finish_reason", ""},
		{"error chunk", []string{text, `{"error":{"code":500,"status":"INTERNAL","message":"failed"}}`}, base.StatusPartial, "500", ""},
	} {
		for _, form := range []string{"sse", "array"} {
			response := sseResponse(test.chunks...)
			if form == "array" {
				response = requestBody("[" + strings.Join(test.chunks, ",") + "]")
			}
			implementation, _ := New(StreamGenerateContent)
			input := base.Input{Protocol: "gemini", Request: requestBody(`{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`), Response: response}
			result := implementation.Parse(context.Background(), input)
			if result.Status != test.status || (test.code != "" && result.ErrorCode != test.code) {
				t.Errorf("%s/%s: status %q (%s), want %q (%s)", test.name, form, result.Status, result.ErrorCode, test.status, test.code)
				continue
			}
			turn, err := implementation.NormalizeAudit(context.Background(), input, result)
			if test.status != base.StatusOK {
				if err == nil {
					t.Errorf("%s/%s: an incomplete stream normalized", test.name, form)
				}
				continue
			}
			if err != nil {
				t.Errorf("%s/%s: normalize: %v", test.name, form, err)
				continue
			}
			if form == "sse" {
				summary := turn.ResponseEnvelope.(map[string]any)["summary"].(map[string]any)
				if summary["stop_reason"] != test.stop || turn.ResponseLayout != auditmodel.LayoutGeminiStreamResponse {
					t.Errorf("%s: stop reason %v, layout %q", test.name, summary["stop_reason"], turn.ResponseLayout)
				}
			} else if turn.ResponseLayout != auditmodel.LayoutMarkerEnvelope || len(turn.ResponseItems) != 0 {
				t.Errorf("%s/array: layout %q with %d items", test.name, turn.ResponseLayout, len(turn.ResponseItems))
			}
		}
	}
}

// TestFoldJoinsTextAndKeepsTheRest pins the fold of one candidate's parts
// and the residue a typical stream leaves: the earlier usage snapshots.
func TestFoldJoinsTextAndKeepsTheRest(t *testing.T) {
	t.Parallel()
	usage := func(candidates int) string {
		return fmt.Sprintf(`"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":%d,"totalTokenCount":%d}`, candidates, 5+candidates)
	}
	response := sseResponse(
		`{"candidates":[{"content":{"role":"model","parts":[{"text":"Thin","thought":true}]},"index":0}],`+usage(1)+`,"responseId":"r"}`,
		`{"candidates":[{"content":{"role":"model","parts":[{"text":"king","thought":true},{"text":"Hel"}]},"index":0}],`+usage(2)+`,"responseId":"r"}`,
		`{"candidates":[{"content":{"role":"model","parts":[{"text":"lo"},{"functionCall":{"name":"f","args":{"a":1}}},{"functionCall":{"name":"f","args":{"a":1}}}]},"index":0}],`+usage(3)+`,"responseId":"r"}`,
		`{"candidates":[{"content":{"role":"model","parts":[{"text":"","thoughtSignature":"c2ln"}]},"finishReason":"STOP","index":0}],`+usage(4)+`,"responseId":"r"}`)
	result, turn, _ := normalize(t, StreamGenerateContent, requestBody(`{"contents":[]}`), response)
	content, _ := auditmodel.CanonicalJSON(turn.ResponseItems[0].Value)
	want := `{"parts":[{"text":"Thinking","thought":true},{"text":"Hello"},{"functionCall":{"args":{"a":1},"name":"f"}},{"functionCall":{"args":{"a":1},"name":"f"}},{"text":"","thoughtSignature":"c2ln"}],"role":"model"}`
	if string(content) != want {
		t.Fatalf("folded content = %s\nwant            %s", content, want)
	}
	if *result.ToolCallCount != 2 {
		t.Fatalf("tool calls = %d", *result.ToolCallCount)
	}
	residue, _ := auditmodel.CanonicalJSON(turn.ResponseEnvelope.(map[string]any)["residue"])
	wantResidue := `[{"data":{"usageMetadata":{"candidatesTokenCount":1,"totalTokenCount":6}},"index":0},{"data":{"usageMetadata":{"candidatesTokenCount":2,"totalTokenCount":7}},"index":1},` +
		`{"data":{"usageMetadata":{"candidatesTokenCount":3,"totalTokenCount":8}},"index":2}]`
	if string(residue) != wantResidue {
		t.Fatalf("residue = %s", residue)
	}
}

// TestStoredSize reports what a long text stream and a tool-call stream
// take as raw SSE and as stored objects (canonical JSON before compression
// and encryption, then sealed). The numbers are in the test log.
func TestStoredSize(t *testing.T) {
	t.Parallel()
	usage := func(candidates int) string {
		return fmt.Sprintf(`"usageMetadata":{"promptTokenCount":1200,"candidatesTokenCount":%d,"totalTokenCount":%d},"modelVersion":"gemini-example","responseId":"resp-size-0123456789"`, candidates, 1200+candidates)
	}
	var long []string
	words := strings.Fields(strings.Repeat("the quick brown fox jumps over the lazy dog and keeps running across the field ", 60))
	for index := 0; index < len(words); index += 4 {
		end := min(index+4, len(words))
		finish := ""
		if end == len(words) {
			finish = `,"finishReason":"STOP"`
		}
		piece, _ := json.Marshal(strings.Join(words[index:end], " ") + " ")
		long = append(long, `{"candidates":[{"content":{"role":"model","parts":[{"text":`+string(piece)+`}]},"index":0`+finish+`}],`+usage(index/4+1)+`}`)
	}
	tool := []string{
		`{"candidates":[{"content":{"role":"model","parts":[{"text":"Let me check both files.","thoughtSignature":"` + strings.Repeat("QUJD", 120) + `"}]},"index":0}],` + usage(6) + `}`,
		`{"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"read_file","args":{"path":"src/main.go"}}}]},"index":0}],` + usage(14) + `}`,
		`{"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"read_file","args":{"path":"src/util.go"}}}]},"finishReason":"STOP","index":0}],` + usage(22) + `}`,
	}
	for name, chunks := range map[string][]string{"long text": long, "tool calls": tool} {
		response := sseResponse(chunks...)
		_, _, prepared := normalize(t, StreamGenerateContent, requestBody(`{"contents":[{"role":"user","parts":[{"text":"go"}]}]}`), response)
		var plain, sealed int64
		for _, object := range prepared.Objects {
			if object.Kind == "request_envelope" || object.Kind == "user_content" {
				continue
			}
			plain += object.PlaintextLength
			sealed += int64(len(object.DataEnc))
		}
		var compressed bytes.Buffer
		writer := gzip.NewWriter(&compressed)
		_, _ = writer.Write(response.Data)
		_ = writer.Close()
		t.Logf("%s: %d chunks, raw SSE %d bytes (%d gzip); stored response objects %d bytes canonical, %d bytes sealed",
			name, len(chunks), len(response.Data), compressed.Len(), plain, sealed)
	}
}
