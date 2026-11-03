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
	assertScopeText(t, segments, ScopeUserHistory, "one")
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
