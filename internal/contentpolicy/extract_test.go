package contentpolicy

import (
	"strings"
	"testing"
)

func TestExtractOpenAIChatScopes(t *testing.T) {
	body := []byte(`{
		"model":"gpt-test",
		"messages":[
			{"role":"system","content":"system words"},
			{"role":"user","content":"old user words"},
			{"role":"assistant","content":"assistant words","reasoning_content":"reasoning words","tool_calls":[{"id":"c1","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"/tmp/secret.txt\"}"}}]},
			{"role":"tool","tool_call_id":"c1","name":"read_file","content":"tool result words"},
			{"role":"user","content":[{"type":"text","text":"latest user words"},{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}}]}
		],
		"tools":[{"type":"function","function":{"name":"read_file","description":"read a file","parameters":{"type":"object","properties":{"path":{"type":"string"}}}}}]
	}`)
	segments, err := extractRequest("openai.chat_completions", body)
	if err != nil {
		t.Fatal(err)
	}
	assertScopeText(t, segments, ScopeSystem, "system words")
	assertScopeText(t, segments, ScopeLatestUser, "latest user words")
	assertScopeText(t, segments, ScopeUserHistory, "old user words")
	assertScopeText(t, segments, ScopeAssistant, "assistant words")
	assertScopeText(t, segments, ScopeAssistant, "reasoning words")
	assertScopeText(t, segments, ScopeToolCalls, "/tmp/secret.txt")
	assertScopeText(t, segments, ScopeToolResults, "tool result words")
	assertScopeText(t, segments, ScopeToolDefinitions, "read a file")
	for _, segment := range segments {
		if segment.Text == "user" || segment.Text == "system" || segment.Text == "assistant" {
			t.Fatalf("role string was scanned: %+v", segment)
		}
		if strings.Contains(segment.Text, "AAAA") {
			t.Fatalf("media data was scanned: %+v", segment)
		}
	}
}

func TestExtractOpenAIResponsesScopes(t *testing.T) {
	body := []byte(`{
		"model":"gpt-test",
		"instructions":"response system",
		"input":[
			{"type":"message","role":"user","content":[{"type":"input_text","text":"first ask"}]},
			{"type":"function_call","name":"shell","arguments":"{\"cmd\":\"ls\"}","call_id":"c1"},
			{"type":"function_call_output","call_id":"c1","output":"output words"},
			{"type":"reasoning","summary":[{"type":"summary_text","text":"reasoning words"}]},
			{"type":"message","role":"user","content":[{"type":"input_text","text":"latest ask"}]}
		],
		"tools":[{"type":"function","name":"shell","description":"run shell","parameters":{"type":"object"}}]
	}`)
	segments, err := extractRequest("openai.responses", body)
	if err != nil {
		t.Fatal(err)
	}
	assertScopeText(t, segments, ScopeSystem, "response system")
	assertScopeText(t, segments, ScopeLatestUser, "latest ask")
	assertScopeText(t, segments, ScopeUserHistory, "first ask")
	assertScopeText(t, segments, ScopeAssistant, "reasoning words")
	assertScopeText(t, segments, ScopeToolCalls, "ls")
	assertScopeText(t, segments, ScopeToolResults, "output words")
	assertScopeText(t, segments, ScopeToolDefinitions, "run shell")
}

func TestExtractAnthropicScopes(t *testing.T) {
	body := []byte(`{
		"model":"claude-test",
		"system":[{"type":"text","text":"claude system"}],
		"messages":[
			{"role":"user","content":[{"type":"text","text":"first anthropic"}]},
			{"role":"assistant","content":[{"type":"thinking","thinking":"think words"},{"type":"tool_use","id":"t1","name":"read","input":{"path":"/secret"}}]},
			{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":[{"type":"text","text":"tool output anthropic"}]}]},
			{"role":"user","content":"latest anthropic"}
		],
		"tools":[{"name":"read","description":"read a file","input_schema":{"type":"object"}}]
	}`)
	segments, err := extractRequest("anthropic.messages", body)
	if err != nil {
		t.Fatal(err)
	}
	assertScopeText(t, segments, ScopeSystem, "claude system")
	assertScopeText(t, segments, ScopeLatestUser, "latest anthropic")
	assertScopeText(t, segments, ScopeUserHistory, "first anthropic")
	assertScopeText(t, segments, ScopeAssistant, "think words")
	assertScopeText(t, segments, ScopeToolCalls, "/secret")
	assertScopeText(t, segments, ScopeToolResults, "tool output anthropic")
	assertScopeText(t, segments, ScopeToolDefinitions, "read a file")
}

func TestExtractGeminiScopes(t *testing.T) {
	body := []byte(`{
		"systemInstruction":{"parts":[{"text":"gem system"}]},
		"contents":[
			{"role":"user","parts":[{"text":"gem first"}]},
			{"role":"model","parts":[{"text":"gem answer"},{"thought":true,"text":"gem thought"},{"functionCall":{"name":"gread","args":{"path":"/g"}}}]},
			{"role":"user","parts":[{"functionResponse":{"name":"gread","response":{"data":"gem tool result"}}},{"text":"gem latest"},{"inlineData":{"mimeType":"image/png","data":"AAAA"}}]}
		],
		"tools":[{"functionDeclarations":[{"name":"gread","description":"gem read","parameters":{"type":"object"}}]}]
	}`)
	segments, err := extractRequest("gemini.generate_content", body)
	if err != nil {
		t.Fatal(err)
	}
	assertScopeText(t, segments, ScopeSystem, "gem system")
	assertScopeText(t, segments, ScopeLatestUser, "gem latest")
	assertScopeText(t, segments, ScopeUserHistory, "gem first")
	assertScopeText(t, segments, ScopeAssistant, "gem answer")
	assertScopeText(t, segments, ScopeAssistant, "gem thought")
	assertScopeText(t, segments, ScopeToolCalls, "/g")
	assertScopeText(t, segments, ScopeToolResults, "gem tool result")
	assertScopeText(t, segments, ScopeToolDefinitions, "gem read")
	for _, segment := range segments {
		if strings.Contains(segment.Text, "AAAA") {
			t.Fatalf("gemini media data was scanned: %+v", segment)
		}
	}
}

func TestExtractCompletionsScopes(t *testing.T) {
	segments, err := extractRequest("openai.completions", []byte(`{"model":"x","prompt":["one","two"]}`))
	if err != nil {
		t.Fatal(err)
	}
	assertScopeText(t, segments, ScopeLatestUser, "two")
	assertScopeText(t, segments, ScopeLatestUser, "one")
	assertNoScopeText(t, segments, ScopeUserHistory, "")
}

func TestExtractRejectsUnknownParserAndMalformedJSON(t *testing.T) {
	if _, err := extractRequest("unknown.parser", []byte(`{}`)); err != errUnsupportedParser {
		t.Fatalf("unknown parser error = %v", err)
	}
	if _, err := extractRequest("openai.chat_completions", []byte(`{"messages": [`)); err != errUnparseableRequest {
		t.Fatalf("malformed body error = %v", err)
	}
}

func assertScopeText(t *testing.T, segments []segment, scope, want string) {
	t.Helper()
	for _, item := range segments {
		if item.Scope == scope && strings.Contains(item.Text, want) {
			return
		}
	}
	t.Fatalf("scope %q does not contain %q in %+v", scope, want, segments)
}

// Regression coverage for protocol fields that were omitted or mistaken for
// message text. Every positive assertion is paired with a scope/media control.
func TestExtractProtocolRegressions(t *testing.T) {
	tests := []struct {
		name, parser, body string
		want               []segment
		absent             []segment
	}{
		{
			name:   "chat custom calls and definitions",
			parser: "openai.chat_completions",
			body:   `{"messages":[{"role":"assistant","tool_calls":[{"id":"metadata_canary","type":"custom","custom":{"name":"custom_name","input":"custom_input"}}]}],"tools":[{"type":"custom","custom":{"name":"defined_name","description":"custom_description","format":{"type":"grammar","syntax":"lark","definition":"grammar_text"}}}]}`,
			want:   []segment{{ScopeToolCalls, "custom_name"}, {ScopeToolCalls, "custom_input"}, {ScopeToolDefinitions, "defined_name"}, {ScopeToolDefinitions, "custom_description"}, {ScopeToolDefinitions, "grammar_text"}},
			absent: []segment{{"", "metadata_canary"}, {ScopeAssistant, "custom_input"}, {ScopeToolCalls, "custom_description"}},
		},
		{
			name:   "tool correlation ID is not body",
			parser: "openai.chat_completions",
			body:   `{"messages":[{"role":"user","content":"hello"},{"role":"assistant","tool_calls":[{"id":"metadata_canary","type":"function","function":{"name":"lookup","arguments":"{}"}}]},{"role":"tool","tool_call_id":"metadata_canary","content":"safe result"},{"role":"function","name":"legacy_name","content":"legacy result"},{"role":"user","content":"continue"}]}`,
			want:   []segment{{ScopeToolResults, "safe result"}, {ScopeToolResults, "legacy_name"}, {ScopeToolResults, "legacy result"}},
			absent: []segment{{"", "metadata_canary"}, {ScopeLatestUser, "safe result"}},
		},
		{
			name:   "assistant refusal",
			parser: "openai.chat_completions",
			body:   `{"messages":[{"role":"assistant","content":null,"refusal":"top_refusal"},{"role":"assistant","content":[{"type":"refusal","refusal":"block_refusal"}]},{"role":"user","content":"continue","refusal":"not_assistant_refusal"}]}`,
			want:   []segment{{ScopeAssistant, "top_refusal"}, {ScopeAssistant, "block_refusal"}},
			absent: []segment{{ScopeLatestUser, "top_refusal"}, {"", "not_assistant_refusal"}},
		},
		{
			name:   "gemini omitted role and alternative schema",
			parser: "gemini.generate_content",
			body:   `{"contents":[{"parts":[{"text":"old_text"}]},{"role":"model","parts":[{"text":"model_text"}]},{"parts":[{"text":"current_text"}]}],"tools":[{"functionDeclarations":[{"name":"new_schema","parametersJsonSchema":{"type":"object","description":"schema_canary"}},{"name":"old_schema","parameters":{"type":"object","description":"legacy_schema"}}]}]}`,
			want:   []segment{{ScopeUserHistory, "old_text"}, {ScopeLatestUser, "current_text"}, {ScopeAssistant, "model_text"}, {ScopeToolDefinitions, "schema_canary"}, {ScopeToolDefinitions, "legacy_schema"}},
			absent: []segment{{ScopeAssistant, "current_text"}, {ScopeLatestUser, "old_text"}, {ScopeToolCalls, "schema_canary"}},
		},
		{
			name:   "responses multimodal tool output",
			parser: "openai.responses",
			body:   `{"input":[{"type":"function_call_output","call_id":"metadata_canary","output":[{"type":"input_text","text":"result_text"},{"type":"input_image","image_url":"https://example.com/media_canary"},{"type":"input_file","file_data":"base64_canary","filename":"filename_canary"}]},{"type":"custom_tool_call_output","call_id":"metadata_canary","output":"plain_result"}]}`,
			want:   []segment{{ScopeToolResults, "result_text"}, {ScopeToolResults, "plain_result"}},
			absent: []segment{{"", "metadata_canary"}, {"", "media_canary"}, {"", "base64_canary"}, {"", "filename_canary"}, {ScopeAssistant, "result_text"}},
		},
		{
			name:   "anthropic server and ordinary calls",
			parser: "anthropic.messages",
			body:   `{"tools":[{"type":"web_search_20250305","name":"web_search"}],"messages":[{"role":"user","content":"hello"},{"role":"assistant","content":[{"type":"server_tool_use","id":"metadata_canary","name":"web_search","input":{"query":"server_input"}},{"type":"web_search_tool_result","tool_use_id":"metadata_canary","content":[]},{"type":"tool_use","id":"ordinary_id","name":"ordinary_name","input":{"query":"ordinary_input"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"ordinary_id","content":"ordinary_result"},{"type":"text","text":"continue"}]}]}`,
			want:   []segment{{ScopeToolCalls, "web_search"}, {ScopeToolCalls, "server_input"}, {ScopeToolCalls, "ordinary_name"}, {ScopeToolCalls, "ordinary_input"}, {ScopeToolResults, "ordinary_result"}},
			absent: []segment{{"", "metadata_canary"}, {ScopeAssistant, "server_input"}, {ScopeLatestUser, "ordinary_result"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			segments, err := extractRequest(tt.parser, []byte(tt.body))
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range tt.want {
				assertScopeText(t, segments, want.Scope, want.Text)
			}
			for _, absent := range tt.absent {
				assertNoScopeText(t, segments, absent.Scope, absent.Text)
			}
		})
	}
}

func TestExtractMediaOnlyLatestUser(t *testing.T) {
	tests := []struct{ parser, body string }{
		{"openai.chat_completions", `{"messages":[{"role":"user","content":"old_text"},{"role":"user","content":[{"type":"image_url","image_url":{"url":"media_canary"}}]},{"role":"assistant","content":"answer"}]}`},
		{"openai.responses", `{"input":[{"role":"user","content":"old_text"},{"role":"user","content":[{"type":"input_image","image_url":"media_canary"}]}]}`},
		{"openai.responses_compact", `{"input":[{"role":"user","content":"old_text"},{"role":"user","content":[{"type":"input_file","file_data":"media_canary"}]}]}`},
		{"anthropic.messages", `{"messages":[{"role":"user","content":"old_text"},{"role":"user","content":[{"type":"image","source":{"type":"base64","data":"media_canary"}}]}]}`},
		{"gemini.generate_content", `{"contents":[{"role":"user","parts":[{"text":"old_text"}]},{"role":"user","parts":[{"inlineData":{"data":"media_canary","mimeType":"image/png"}}]}]}`},
		{"gemini.stream_generate_content", `{"contents":[{"parts":[{"text":"old_text"}]},{"parts":[{"fileData":{"fileUri":"media_canary"}}]}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.parser, func(t *testing.T) {
			segments, err := extractRequest(tt.parser, []byte(tt.body))
			if err != nil {
				t.Fatal(err)
			}
			assertScopeText(t, segments, ScopeUserHistory, "old_text")
			assertNoScopeText(t, segments, ScopeLatestUser, "")
			assertNoScopeText(t, segments, "", "media_canary")
		})
	}
}

func TestExtractCompletionBatchAndTokens(t *testing.T) {
	for _, body := range []string{`{"prompt":["first","second",""]}`, `{"prompt":["first","second"]}`} {
		segments, err := extractRequest("openai.completions", []byte(body))
		if err != nil {
			t.Fatal(err)
		}
		assertScopeText(t, segments, ScopeLatestUser, "first")
		assertScopeText(t, segments, ScopeLatestUser, "second")
		assertNoScopeText(t, segments, ScopeUserHistory, "")
	}
	for _, body := range []string{`{"prompt":[1,2,3]}`, `{"prompt":[[1,2],[3,4]]}`} {
		segments, err := extractRequest("openai.completions", []byte(body))
		if err != nil {
			t.Fatal(err)
		}
		if len(segments) != 0 {
			t.Fatalf("token IDs scanned: %+v", segments)
		}
	}
}

func assertNoScopeText(t *testing.T, segments []segment, scope, unwanted string) {
	t.Helper()
	for _, item := range segments {
		if (scope == "" || item.Scope == scope) && strings.Contains(item.Text, unwanted) {
			t.Fatalf("unexpected text %q in scope %q: %+v", unwanted, scope, item)
		}
	}
}

func TestExtractResponsesStructuredShellOutput(t *testing.T) {
	segments, err := extractRequest("openai.responses", []byte(`{"input":[{"type":"shell_call_output","call_id":"metadata_canary","output":[{"stdout":"standard_output","stderr":"error_output","outcome":{"type":"exit","exit_code":17}}]},{"type":"function_call_output","output":[{"type":"input_image","image_url":"media_canary"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	assertScopeText(t, segments, ScopeToolResults, "standard_output")
	assertScopeText(t, segments, ScopeToolResults, "error_output")
	assertNoScopeText(t, segments, "", "metadata_canary")
	assertNoScopeText(t, segments, "", "media_canary")
	assertNoScopeText(t, segments, "", "exit_code")
}
