package insights

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"llmapi-logger/internal/conversation"
)

type testFingerprinter struct{}

func (testFingerprinter) Fingerprint(domain string, value []byte) []byte {
	mac := hmac.New(sha256.New, []byte("insights-test-key"))
	mac.Write([]byte(domain))
	mac.Write([]byte{0})
	mac.Write(value)
	return mac.Sum(nil)
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func analyze(t *testing.T, input Input) Analysis {
	t.Helper()
	analysis, err := Analyze(input, nil, testFingerprinter{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	return analysis
}

func itemSum(analysis Analysis) int64 {
	var total int64
	for _, item := range analysis.Detail.Items {
		total += item.Tokens
	}
	return total
}

func categories(analysis Analysis) []string {
	out := make([]string, len(analysis.Detail.Items))
	for index, item := range analysis.Detail.Items {
		out[index] = item.Category + "/" + item.Kind
	}
	return out
}

func equalStrings(left, right []string) bool {
	return strings.Join(left, ",") == strings.Join(right, ",")
}

func testPNG(t *testing.T, width, height int) string {
	t.Helper()
	var buffer bytes.Buffer
	if err := png.Encode(&buffer, image.NewGray(image.Rect(0, 0, width, height))); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(buffer.Bytes())
}

func TestAnalyzeOpenAIChat(t *testing.T) {
	analysis := analyze(t, Input{
		Protocol: "openai", Endpoint: "chat_completions",
		Request: fixture(t, "openai_chat.json"), RequestModel: "gpt-test",
	})
	want := []string{
		"system/system", "injected/text", "tools/tool_def", "tools/tool_def", "tools/tool_def",
		"user/text", "media/image", "assistant/tool_call", "tool_result/tool_result", "user/text",
	}
	if got := categories(analysis); !equalStrings(got, want) {
		t.Fatalf("categories = %v, want %v", got, want)
	}
	if got := analysis.Detail.Items[1].Label; got != "<environment_context>" {
		t.Errorf("injected label = %q", got)
	}
	// "You are helpful." is 16 bytes: 4 + 4 block + 4 message overhead.
	if got := analysis.Detail.Items[0].Tokens; got != 12 {
		t.Errorf("system tokens = %d, want 12", got)
	}
	if got := analysis.Detail.Items[6].Tokens; got != 85 {
		t.Errorf("low detail image tokens = %d, want 85", got)
	}
	if analysis.Estimate.Sum() != itemSum(analysis) {
		t.Errorf("estimate sum %d != item sum %d", analysis.Estimate.Sum(), itemSum(analysis))
	}
	if analysis.Estimate.Media != 85 || analysis.Estimate.Injected == 0 || analysis.Estimate.Tools == 0 {
		t.Errorf("estimate = %+v", analysis.Estimate)
	}
	wantCounts := ItemCounts{Items: 10, ToolDefs: 3, ToolResults: 1, Media: 1}
	if analysis.Counts != wantCounts {
		t.Errorf("counts = %+v, want %+v", analysis.Counts, wantCounts)
	}
	sources := map[string]string{}
	for _, tool := range analysis.Detail.Tools {
		sources[tool.Name] = tool.Source
	}
	wantSources := map[string]string{"shell": "builtin", "mcp__github__create_issue": "mcp:github", "lookup_customer": "custom"}
	for name, source := range wantSources {
		if sources[name] != source {
			t.Errorf("source of %s = %q, want %q", name, sources[name], source)
		}
	}
	if analysis.MaxOutputTokens == nil || *analysis.MaxOutputTokens != 4096 {
		t.Errorf("max output = %v", analysis.MaxOutputTokens)
	}
	if analysis.Model != "gpt-test" || analysis.Version != AnalysisVersion {
		t.Errorf("model/version = %q/%d", analysis.Model, analysis.Version)
	}
	if !analysis.TurnStart {
		t.Error("turn start should be true: last item is user text")
	}
	if analysis.SessionKeySource != SessionLinkExplicit || analysis.SessionKeyFPR == nil {
		t.Errorf("session key = %q %x", analysis.SessionKeySource, analysis.SessionKeyFPR)
	}
	if analysis.SystemFPR == nil || analysis.ToolsFPR == nil {
		t.Error("system and tools fingerprints should be set")
	}
	if len(analysis.Detail.ItemFPRs) != 10 || len(analysis.Detail.ItemFPRs[0]) != 64 {
		t.Errorf("item fprs = %v", analysis.Detail.ItemFPRs)
	}
	if analysis.Agent != (AgentIdentity{}) || analysis.SpawnHintFPRs != nil || analysis.ChildHintFPRs != nil {
		t.Error("identity fields must stay zero")
	}
}

func TestAnalyzeResponses(t *testing.T) {
	analysis := analyze(t, Input{
		Protocol: "openai", Endpoint: "responses",
		Request: fixture(t, "openai_responses.json"), ResponseModel: "gpt-resp",
	})
	want := []string{
		"system/system", "injected/text", "tools/tool_def", "tools/tool_def",
		"user/text", "reasoning/thinking", "assistant/tool_call", "tool_result/tool_result", "user/text",
	}
	if got := categories(analysis); !equalStrings(got, want) {
		t.Fatalf("categories = %v, want %v", got, want)
	}
	if analysis.Model != "gpt-resp" {
		t.Errorf("model = %q", analysis.Model)
	}
	if analysis.Detail.Tools[1].Name != "web_search" || analysis.Detail.Tools[0].Source != "builtin" {
		t.Errorf("tools = %+v", analysis.Detail.Tools)
	}
	if analysis.MaxOutputTokens == nil || *analysis.MaxOutputTokens != 2000 {
		t.Errorf("max output = %v", analysis.MaxOutputTokens)
	}
	if analysis.SessionKeySource != SessionLinkInferred || analysis.SessionKeyFPR == nil {
		t.Errorf("session key source = %q", analysis.SessionKeySource)
	}
	if analysis.Estimate.Reasoning == 0 {
		t.Error("reasoning estimate missing")
	}
}

func TestAnalyzeCompletions(t *testing.T) {
	analysis := analyze(t, Input{Protocol: "openai", Endpoint: "completions", Request: fixture(t, "openai_completions.json")})
	if got := categories(analysis); !equalStrings(got, []string{"user/text", "user/text"}) {
		t.Fatalf("categories = %v", got)
	}
	if analysis.Detail.Items[1].Tokens != 4+4 {
		t.Errorf("pre-tokenized prompt tokens = %d", analysis.Detail.Items[1].Tokens)
	}
	if analysis.MaxOutputTokens == nil || *analysis.MaxOutputTokens != 64 {
		t.Errorf("max output = %v", analysis.MaxOutputTokens)
	}
}

func TestAnalyzeAnthropicClaudeCode(t *testing.T) {
	analysis := analyze(t, Input{
		Protocol: "anthropic", Endpoint: "messages",
		Request: fixture(t, "anthropic_claude_code.json"), RequestModel: "claude-test",
	})
	want := []string{
		"system/system", "system/system", "tools/tool_def", "tools/tool_def", "tools/tool_def",
		"injected/text", "user/text", "reasoning/thinking", "assistant/text", "assistant/tool_call",
		"tool_result/tool_result",
	}
	if got := categories(analysis); !equalStrings(got, want) {
		t.Fatalf("categories = %v, want %v", got, want)
	}
	if analysis.SessionKeySource != SessionLinkExplicit {
		t.Errorf("session key source = %q", analysis.SessionKeySource)
	}
	explicit := testFingerprinter{}.Fingerprint(DomainSession, []byte("anthropic\x00cc-session-1"))
	if !bytes.Equal(analysis.SessionKeyFPR, explicit) {
		t.Error("explicit session key should hash protocol and the user_id session_id")
	}
	if analysis.TurnStart {
		t.Error("turn start must be false when the last item is a tool result")
	}
	if got := analysis.Detail.Items[8+1].Label; got != "Read" {
		t.Errorf("tool call label = %q", got)
	}
	if got := analysis.Detail.Items[10].Label; got != "Read" {
		t.Errorf("tool result label should come from its call: %q", got)
	}
	sources := []string{}
	for _, tool := range analysis.Detail.Tools {
		sources = append(sources, tool.Source)
	}
	if !equalStrings(sources, []string{"builtin", "builtin", "mcp:my__server"}) {
		t.Errorf("sources = %v", sources)
	}
	if got := analysis.Detail.Items[6].Summary; got != "Fix the bug in main.go" {
		t.Errorf("summary = %q", got)
	}
	if analysis.Counts.ToolResults != 1 || analysis.Counts.ToolDefs != 3 {
		t.Errorf("counts = %+v", analysis.Counts)
	}
}

func TestAnalyzeAnthropicTurnStartAndInferredKey(t *testing.T) {
	request := func(text string) []byte {
		return []byte(`{"model":"m","system":"sys","messages":[{"role":"user","content":"` + text + `"}]}`)
	}
	first := analyze(t, Input{Protocol: "anthropic", Endpoint: "messages", Request: request("hello")})
	again := analyze(t, Input{Protocol: "anthropic", Endpoint: "messages", Request: request("hello")})
	other := analyze(t, Input{Protocol: "anthropic", Endpoint: "messages", Request: request("different opener")})
	if !first.TurnStart || first.SessionKeySource != SessionLinkInferred {
		t.Fatalf("turn start/source = %v/%q", first.TurnStart, first.SessionKeySource)
	}
	if !bytes.Equal(first.SessionKeyFPR, again.SessionKeyFPR) {
		t.Error("same system and opener must give the same inferred key")
	}
	if bytes.Equal(first.SessionKeyFPR, other.SessionKeyFPR) {
		t.Error("different opener must give a different inferred key")
	}
	injectedLast := analyze(t, Input{Protocol: "anthropic", Endpoint: "messages",
		Request: []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"},{"type":"text","text":"  <system-reminder>x</system-reminder>"}]}]}`)})
	if injectedLast.TurnStart {
		t.Error("an injected last item is not a turn start")
	}
}

func TestAnalyzeMediaOnlyOpenerIsUserInput(t *testing.T) {
	png := testPNG(t, 8, 8)
	cases := []struct {
		name     string
		protocol string
		endpoint string
		opener   func(media string) string
		result   string
	}{
		{"anthropic image", "anthropic", "messages", func(p string) string {
			return `{"system":"sys","messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"` + p + `"}}]}]}`
		}, `{"system":"sys","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"x"}]}]}`},
		{"anthropic document", "anthropic", "messages", func(p string) string {
			return `{"system":"sys","messages":[{"role":"user","content":[{"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"` + p + `"}}]}]}`
		}, `{"system":"sys","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"x"}]}]}`},
		{"gemini image", "gemini", "generateContent", func(p string) string {
			return `{"systemInstruction":{"parts":[{"text":"sys"}]},"contents":[{"role":"user","parts":[{"inlineData":{"mimeType":"image/png","data":"` + p + `"}}]}]}`
		}, `{"systemInstruction":{"parts":[{"text":"sys"}]},"contents":[{"role":"function","parts":[{"inlineData":{"mimeType":"image/png","data":"` + png + `"}}]}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first := analyze(t, Input{Protocol: tc.protocol, Endpoint: tc.endpoint, Request: []byte(tc.opener(png))})
			if !first.TurnStart {
				t.Error("a user-role media opener is a turn start")
			}
			if first.SessionKeySource != SessionLinkInferred || first.SessionKeyFPR == nil {
				t.Fatalf("session key = %q %x", first.SessionKeySource, first.SessionKeyFPR)
			}
			again := analyze(t, Input{Protocol: tc.protocol, Endpoint: tc.endpoint, Request: []byte(tc.opener(png))})
			if !bytes.Equal(first.SessionKeyFPR, again.SessionKeyFPR) {
				t.Error("same media opener must give the same inferred key")
			}
			other := analyze(t, Input{Protocol: tc.protocol, Endpoint: tc.endpoint, Request: []byte(tc.opener(testPNG(t, 16, 16)))})
			if bytes.Equal(first.SessionKeyFPR, other.SessionKeyFPR) {
				t.Error("different media opener must give a different inferred key")
			}
			if tc.protocol == "anthropic" {
				result := analyze(t, Input{Protocol: tc.protocol, Endpoint: tc.endpoint, Request: []byte(tc.result)})
				if result.TurnStart {
					t.Error("a tool result is not a turn start")
				}
			}
		})
	}
	toolMedia := analyze(t, Input{Protocol: "gemini", Endpoint: "generateContent", Request: []byte(cases[2].result)})
	if toolMedia.TurnStart || toolMedia.SessionKeyFPR != nil {
		t.Errorf("tool-role media must not count as user input: %v %x", toolMedia.TurnStart, toolMedia.SessionKeyFPR)
	}
}

func TestAnalyzeGemini(t *testing.T) {
	analysis := analyze(t, Input{
		Protocol: "gemini", Endpoint: "generateContent",
		Request: fixture(t, "gemini_generate.json"), RequestModel: "gemini-test",
	})
	want := []string{
		"system/system", "tools/tool_def", "tools/tool_def", "user/text", "media/image",
		"reasoning/thinking", "assistant/tool_call", "tool_result/tool_result",
	}
	if got := categories(analysis); !equalStrings(got, want) {
		t.Fatalf("categories = %v, want %v", got, want)
	}
	if analysis.Detail.Items[4].Tokens != geminiImageTokens {
		t.Errorf("gemini image tokens = %d", analysis.Detail.Items[4].Tokens)
	}
	if analysis.Detail.Tools[1].Name != "googleSearch" {
		t.Errorf("tools = %+v", analysis.Detail.Tools)
	}
	if analysis.MaxOutputTokens == nil || *analysis.MaxOutputTokens != 1024 {
		t.Errorf("max output = %v", analysis.MaxOutputTokens)
	}
	if analysis.Detail.Items[7].Label != "get_weather" {
		t.Errorf("function response label = %q", analysis.Detail.Items[7].Label)
	}
}

func TestImageTokenEstimates(t *testing.T) {
	cases := []struct {
		name     string
		protocol string
		endpoint string
		build    func(png string) string
		want     int64
	}{
		{"openai high 2048x1024 tiles", "openai", "chat_completions", func(p string) string {
			return `{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,` + p + `"}}]}]}`
		}, messageOverheadTokens + 85 + 170*6},
		{"openai low detail", "openai", "chat_completions", func(p string) string {
			return `{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,` + p + `","detail":"low"}}]}]}`
		}, messageOverheadTokens + 85},
		{"openai unknown size", "openai", "chat_completions", func(string) string {
			return `{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.invalid/x.png"}}]}]}`
		}, messageOverheadTokens + 85 + 170*4},
		{"anthropic w*h/750", "anthropic", "messages", func(p string) string {
			return `{"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"` + p + `"}}]}]}`
		}, messageOverheadTokens + 1000*500/750},
		{"anthropic url unknown", "anthropic", "messages", func(string) string {
			return `{"messages":[{"role":"user","content":[{"type":"image","source":{"type":"url","url":"https://example.invalid/x.png"}}]}]}`
		}, messageOverheadTokens + 1600},
	}
	large, medium := testPNG(t, 2048, 1024), testPNG(t, 1000, 500)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encoded := large
			if tc.protocol == "anthropic" {
				encoded = medium
			}
			analysis := analyze(t, Input{Protocol: tc.protocol, Endpoint: tc.endpoint, Request: []byte(tc.build(encoded))})
			if got := analysis.Estimate.Media; got != tc.want {
				t.Errorf("media tokens = %d, want %d", got, tc.want)
			}
		})
	}
	huge := testPNG(t, 4000, 3000)
	analysis := analyze(t, Input{Protocol: "anthropic", Endpoint: "messages", Request: []byte(
		`{"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"` + huge + `"}}]}]}`)})
	if analysis.Estimate.Media != messageOverheadTokens+1600 {
		t.Errorf("anthropic cap = %d, want 1604", analysis.Estimate.Media)
	}
}

func TestDocumentAndFileTokens(t *testing.T) {
	data := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("a"), 4000))
	analysis := analyze(t, Input{Protocol: "anthropic", Endpoint: "messages", Request: []byte(
		`{"messages":[{"role":"user","content":[{"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"` + data + `"}}]}]}`)})
	if analysis.Estimate.Media != messageOverheadTokens+1000 || analysis.Detail.Items[0].Kind != "file" {
		t.Errorf("document = %+v", analysis.Detail.Items[0])
	}
	gemini := analyze(t, Input{Protocol: "gemini", Endpoint: "generateContent", Request: []byte(
		`{"contents":[{"role":"user","parts":[{"inlineData":{"mimeType":"application/pdf","data":"` + data + `"}}]}]}`)})
	if gemini.Estimate.Media != messageOverheadTokens+1000 {
		t.Errorf("gemini file tokens = %d", gemini.Estimate.Media)
	}
}

func TestMalformedRequests(t *testing.T) {
	cases := []struct {
		name    string
		input   Input
		wantErr bool
	}{
		{"empty", Input{Protocol: "openai", Endpoint: "chat_completions"}, true},
		{"not json", Input{Protocol: "openai", Endpoint: "chat_completions", Request: []byte("{\"messages\": [")}, true},
		{"array root", Input{Protocol: "openai", Endpoint: "chat_completions", Request: []byte("[1]")}, true},
		{"unknown protocol", Input{Protocol: "other", Request: []byte("{}")}, true},
		{"empty object", Input{Protocol: "anthropic", Endpoint: "messages", Request: []byte("{}")}, false},
		{"garbage fields", Input{Protocol: "openai", Endpoint: "chat_completions", Request: []byte(`{"messages":[1,null,{"role":5,"content":{"x":1}},"s"],"tools":"nope"}`)}, false},
		{"garbage gemini", Input{Protocol: "gemini", Endpoint: "generateContent", Request: []byte(`{"contents":[null,{"parts":"x"}],"tools":[1]}`)}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			analysis, err := Analyze(tc.input, nil, testFingerprinter{})
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && analysis.Detail.Items == nil {
				t.Error("best-effort analysis should have non-nil items")
			}
		})
	}
	if _, err := Analyze(Input{Protocol: "openai", Request: []byte("{}")}, nil, nil); err == nil {
		t.Error("nil fingerprinter should be an error")
	}
}

func TestItemTruncationKeepsTotals(t *testing.T) {
	var builder strings.Builder
	builder.WriteString(`{"messages":[`)
	for index := 0; index < 2100; index++ {
		if index > 0 {
			builder.WriteString(",")
		}
		fmt.Fprintf(&builder, `{"role":"user","content":"message %d"}`, index)
	}
	builder.WriteString(`]}`)
	analysis := analyze(t, Input{Protocol: "openai", Endpoint: "chat_completions", Request: []byte(builder.String())})
	if len(analysis.Detail.Items) != maxDetailItems || !analysis.Detail.Truncated {
		t.Fatalf("items = %d truncated = %v", len(analysis.Detail.Items), analysis.Detail.Truncated)
	}
	if analysis.Counts.Items != 2100 || len(analysis.Detail.ItemFPRs) != 2100 {
		t.Errorf("counts = %+v fprs = %d", analysis.Counts, len(analysis.Detail.ItemFPRs))
	}
	if analysis.Estimate.User <= itemSum(analysis) {
		t.Errorf("totals must cover truncated items: estimate %d, kept %d", analysis.Estimate.User, itemSum(analysis))
	}
}

func TestSummaryCollapsesWhitespaceAndTruncates(t *testing.T) {
	long := strings.Repeat("word  \n\t", 100)
	request, _ := json.Marshal(map[string]any{"messages": []any{map[string]any{"role": "user", "content": long}}})
	analysis := analyze(t, Input{Protocol: "openai", Endpoint: "chat_completions", Request: request})
	summary := analysis.Detail.Items[0].Summary
	if len([]rune(summary)) != 160 || strings.ContainsAny(summary, "\n\t") || strings.Contains(summary, "  ") {
		t.Errorf("summary = %q", summary)
	}
}

func TestItemFingerprintsAreDeterministicAcrossSharedPrefix(t *testing.T) {
	base := func(billing, tail string) []byte {
		return []byte(`{"system":[{"type":"text","text":"x-anthropic-billing-header: cch=` + billing + `;"},{"type":"text","text":"sys"}],` +
			`"tools":[{"name":"Read","input_schema":{"type":"object","properties":{"b":1,"a":2}}}],` +
			`"messages":[{"role":"user","content":"open"},{"role":"assistant","content":[{"type":"text","text":"ok"}]}` + tail + `]}`)
	}
	first := analyze(t, Input{Protocol: "anthropic", Endpoint: "messages", Request: base("aaa", "")})
	second := analyze(t, Input{Protocol: "anthropic", Endpoint: "messages", Request: base("bbb", `,{"role":"user","content":"more"}`)})
	if len(second.Detail.ItemFPRs) != len(first.Detail.ItemFPRs)+1 {
		t.Fatalf("fpr counts %d vs %d", len(first.Detail.ItemFPRs), len(second.Detail.ItemFPRs))
	}
	for index, value := range first.Detail.ItemFPRs {
		if second.Detail.ItemFPRs[index] != value {
			t.Errorf("item %d fingerprint changed across a shared prefix", index)
		}
	}
	if !bytes.Equal(first.SystemFPR, second.SystemFPR) || !bytes.Equal(first.ToolsFPR, second.ToolsFPR) {
		t.Error("system and tools fingerprints should ignore the volatile billing header")
	}
	if !bytes.Equal(first.SessionKeyFPR, second.SessionKeyFPR) {
		t.Error("inferred session key should be stable across steps")
	}
	reordered := analyze(t, Input{Protocol: "anthropic", Endpoint: "messages", Request: []byte(
		`{"system":[{"text":"x-anthropic-billing-header: cch=zzz;","type":"text"},{"text":"sys","type":"text"}],` +
			`"tools":[{"input_schema":{"properties":{"a":2,"b":1},"type":"object"},"name":"Read"}],"messages":[]}`)})
	if !bytes.Equal(first.ToolsFPR, reordered.ToolsFPR) || !bytes.Equal(first.SystemFPR, reordered.SystemFPR) {
		t.Error("fingerprints must be independent of JSON key order")
	}
	changed := analyze(t, Input{Protocol: "anthropic", Endpoint: "messages", Request: []byte(
		`{"system":"other","messages":[{"role":"user","content":"open"}]}`)})
	if bytes.Equal(first.SystemFPR, changed.SystemFPR) {
		t.Error("different system content must change the system fingerprint")
	}
}

func TestResponseAnalysis(t *testing.T) {
	text := func(value string) conversation.Part { return conversation.Text(value) }
	call := func(name, args string) conversation.Part {
		return conversation.Part{Type: conversation.PartToolCall, Name: name, Arguments: args}
	}
	respond := func(parts ...conversation.Part) *conversation.Conversation {
		conv := conversation.New()
		conv.Append(conversation.Message{
			Role: conversation.RoleUser, Phase: conversation.PhaseRequest,
			Content: []conversation.Part{conversation.Part{Type: conversation.PartToolCall, Name: "Read", Arguments: "{}"}},
		})
		conv.Append(conversation.Message{Role: conversation.RoleAssistant, Phase: conversation.PhaseResponse, Content: parts})
		return conv
	}
	cases := []struct {
		name      string
		protocol  string
		endpoint  string
		response  []byte
		conv      *conversation.Conversation
		stop      string
		kinds     int
		toolCalls int
		kindCount map[string]int
	}{
		{"openai chat stream", "openai", "chat_completions", fixture(t, "openai_chat_stream.sse"),
			respond(text("Hello")), StopEndTurn, KindText, 0, map[string]int{}},
		{"openai chat tool_calls", "openai", "chat_completions", []byte(`{"choices":[{"finish_reason":"tool_calls"}]}`),
			respond(call("shell", `{"cmd":"ls"}`), call("mcp__a__b", "{}")), StopToolUse, KindToolCall, 2,
			map[string]int{ToolKindShell: 1, ToolKindMCP: 1}},
		{"openai chat length", "openai", "chat_completions", []byte(`{"choices":[{"finish_reason":"length"}]}`),
			respond(text("x")), StopLength, KindText, 0, map[string]int{}},
		{"openai chat content_filter", "openai", "chat_completions", []byte(`{"choices":[{"finish_reason":"content_filter"}]}`),
			nil, StopContentFilter, 0, 0, map[string]int{}},
		{"openai chat unknown reason", "openai", "chat_completions", []byte(`{"choices":[{"finish_reason":"weird"}]}`),
			nil, StopOther, 0, 0, map[string]int{}},
		{"anthropic stream tool_use", "anthropic", "messages", fixture(t, "anthropic_stream.sse"),
			respond(conversation.Reasoning("hm"), call("Edit", `{"file_path":"a.go"}`)), StopToolUse, KindThinking | KindToolCall, 1,
			map[string]int{ToolKindFileWrite: 1}},
		{"anthropic end_turn", "anthropic", "messages", []byte(`{"type":"message","stop_reason":"end_turn"}`),
			respond(text("done")), StopEndTurn, KindText, 0, map[string]int{}},
		{"anthropic max_tokens", "anthropic", "messages", []byte(`{"stop_reason":"max_tokens"}`),
			nil, StopLength, 0, 0, map[string]int{}},
		{"responses stream", "openai", "responses", fixture(t, "responses_stream.sse"),
			respond(call("shell", "{}")), StopToolUse, KindToolCall, 1, map[string]int{ToolKindShell: 1}},
		{"responses completed text", "openai", "responses", []byte(`{"status":"completed"}`),
			respond(text("done")), StopEndTurn, KindText, 0, map[string]int{}},
		{"responses incomplete", "openai", "responses", []byte(`{"status":"incomplete","incomplete_details":{"reason":"max_output_tokens"}}`),
			nil, StopLength, 0, 0, map[string]int{}},
		{"responses incomplete filter", "openai", "responses", []byte(`{"status":"incomplete","incomplete_details":{"reason":"content_filter"}}`),
			nil, StopContentFilter, 0, 0, map[string]int{}},
		{"responses failed", "openai", "responses", []byte(`{"status":"failed"}`), nil, StopOther, 0, 0, map[string]int{}},
		{"gemini array stream", "gemini", "streamGenerateContent", fixture(t, "gemini_stream.json"),
			nil, StopLength, 0, 0, map[string]int{}},
		{"gemini STOP with function call", "gemini", "generateContent", []byte(`{"candidates":[{"finishReason":"STOP"}]}`),
			respond(call("get_weather", "{}")), StopToolUse, KindToolCall, 1, map[string]int{ToolKindOther: 1}},
		{"gemini SAFETY", "gemini", "generateContent", []byte(`{"candidates":[{"finishReason":"SAFETY"}]}`),
			nil, StopContentFilter, 0, 0, map[string]int{}},
		{"unknown stop is empty", "gemini", "generateContent", []byte(`{"candidates":[{"content":{}}]}`),
			nil, "", 0, 0, map[string]int{}},
		{"no response", "openai", "chat_completions", nil, nil, "", 0, 0, map[string]int{}},
		{"unparseable response", "openai", "chat_completions", []byte("not json at all"), nil, "", 0, 0, map[string]int{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			analysis := analyze(t, Input{
				Protocol: tc.protocol, Endpoint: tc.endpoint, Request: []byte(`{"messages":[]}`),
				Response: tc.response, Conversation: tc.conv,
			})
			if analysis.StopReason != tc.stop {
				t.Errorf("stop = %q, want %q", analysis.StopReason, tc.stop)
			}
			if analysis.ResponseKinds != tc.kinds || analysis.ResponseToolCalls != tc.toolCalls {
				t.Errorf("kinds/calls = %d/%d, want %d/%d", analysis.ResponseKinds, analysis.ResponseToolCalls, tc.kinds, tc.toolCalls)
			}
			if fmt.Sprint(analysis.ToolKindCounts) != fmt.Sprint(tc.kindCount) {
				t.Errorf("kind counts = %v, want %v", analysis.ToolKindCounts, tc.kindCount)
			}
		})
	}
}

func TestResponseCountsOnlyResponsePhase(t *testing.T) {
	conv := conversation.New()
	conv.Append(conversation.Message{Role: "assistant", Phase: conversation.PhaseRequest,
		Content: []conversation.Part{{Type: conversation.PartToolCall, Name: "Bash", Arguments: "{}"}}})
	analysis := analyze(t, Input{Protocol: "openai", Endpoint: "chat_completions", Request: []byte(`{}`), Conversation: conv})
	if analysis.ResponseToolCalls != 0 || analysis.ResponseKinds != 0 || len(analysis.Detail.FileOps) != 0 {
		t.Errorf("request-phase tool calls leaked into the response: %+v", analysis)
	}
}

func TestTimingModelAndUsage(t *testing.T) {
	first, last := int64(1_000), int64(5_000)
	one := int64(7)
	analysis := analyze(t, Input{
		Protocol: "openai", Endpoint: "chat_completions", Request: []byte(`{"max_tokens":9}`),
		ResponseModel: "resp-model", FirstEventNS: &first, LastEventNS: &last,
		Usage: Usage{Output: &one},
	})
	if analysis.GenerationNS == nil || *analysis.GenerationNS != 4_000 || analysis.FirstEventNS == nil || *analysis.FirstEventNS != 1_000 {
		t.Errorf("timing = %v %v", analysis.FirstEventNS, analysis.GenerationNS)
	}
	if analysis.Model != "resp-model" || analysis.Usage.Output == nil || *analysis.Usage.Output != 7 {
		t.Errorf("model/usage = %q %+v", analysis.Model, analysis.Usage)
	}
	if analysis.MaxOutputTokens == nil || *analysis.MaxOutputTokens != 9 {
		t.Errorf("max output = %v", analysis.MaxOutputTokens)
	}
	earlier := int64(10)
	reversed := analyze(t, Input{Protocol: "openai", Request: []byte(`{}`), FirstEventNS: &first, LastEventNS: &earlier})
	if reversed.GenerationNS != nil {
		t.Error("negative generation time should be omitted")
	}
	gemini := analyze(t, Input{Protocol: "gemini", Request: []byte(`{"generationConfig":{"maxOutputTokens":55}}`)})
	if gemini.MaxOutputTokens == nil || *gemini.MaxOutputTokens != 55 {
		t.Errorf("gemini max output = %v", gemini.MaxOutputTokens)
	}
}

func TestFileOps(t *testing.T) {
	codexPatch := "*** Begin Patch\n*** Update File: src/a.go\n@@\n context\n-old1\n-old2\n+new1\n*** Add File: b.txt\n+x\n+y\n+z\n*** Delete File: c.txt\n*** End Patch\n"
	unified := "diff --git a/f.go b/f.go\n--- a/f.go\n+++ b/f.go\n@@ -1,2 +1,2 @@\n-a\n+b\n+c\n--- a/g.go\n+++ /dev/null\n-gone\n"
	mustJSON := func(value any) string {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded)
	}
	cases := []struct {
		name string
		tool string
		args string
		want []FileOp
		kind string
	}{
		{"read", "Read", `{"file_path":"/w/a.go"}`, []FileOp{{Tool: "Read", Op: "read", Path: "/w/a.go"}}, ToolKindFileRead},
		{"read_file camel path", "read_file", `{"filePath":"/w/b.go"}`, []FileOp{{Tool: "read_file", Op: "read", Path: "/w/b.go"}}, ToolKindFileRead},
		{"write", "Write", `{"file_path":"/w/n.go","content":"a\nb\nc\n"}`, []FileOp{{Tool: "Write", Op: "write", Path: "/w/n.go", AddedLines: 3}}, ToolKindFileWrite},
		{"write file_text", "write", `{"path":"x","file_text":"one"}`, []FileOp{{Tool: "write", Op: "write", Path: "x", AddedLines: 1}}, ToolKindFileWrite},
		{"edit", "Edit", `{"file_path":"/w/a.go","old_string":"a\nb","new_string":"c"}`, []FileOp{{Tool: "Edit", Op: "write", Path: "/w/a.go", AddedLines: 1, RemovedLines: 2}}, ToolKindFileWrite},
		{"edit old_str", "edit", `{"path":"p","old_str":"a","new_str":"b\nc\n"}`, []FileOp{{Tool: "edit", Op: "write", Path: "p", AddedLines: 2, RemovedLines: 1}}, ToolKindFileWrite},
		{"multiedit", "MultiEdit", `{"file_path":"m","edits":[{"old_string":"a","new_string":"b\nc"},{"old_string":"x\ny","new_string":"z"}]}`,
			[]FileOp{{Tool: "MultiEdit", Op: "write", Path: "m", AddedLines: 3, RemovedLines: 3}}, ToolKindFileWrite},
		{"grep", "Grep", `{"pattern":"secret","path":"/w"}`, []FileOp{{Tool: "Grep", Op: "search", Path: "/w"}}, ToolKindSearch},
		{"bash", "Bash", `{"command":"ls"}`, []FileOp{{Tool: "Bash", Op: "shell"}}, ToolKindShell},
		{"apply_patch codex", "apply_patch", mustJSON(map[string]string{"input": codexPatch}), []FileOp{
			{Tool: "apply_patch", Op: "write", Path: "src/a.go", AddedLines: 1, RemovedLines: 2},
			{Tool: "apply_patch", Op: "write", Path: "b.txt", AddedLines: 3},
			{Tool: "apply_patch", Op: "write", Path: "c.txt"},
		}, ToolKindFileWrite},
		{"apply_patch unified", "apply_patch", mustJSON(map[string]string{"patch": unified}), []FileOp{
			{Tool: "apply_patch", Op: "write", Path: "f.go", AddedLines: 2, RemovedLines: 1},
			{Tool: "apply_patch", Op: "write", Path: "g.go", RemovedLines: 1},
		}, ToolKindFileWrite},
		{"apply_patch raw text", "apply_patch", codexPatch, []FileOp{
			{Tool: "apply_patch", Op: "write", Path: "src/a.go", AddedLines: 1, RemovedLines: 2},
			{Tool: "apply_patch", Op: "write", Path: "b.txt", AddedLines: 3},
			{Tool: "apply_patch", Op: "write", Path: "c.txt"},
		}, ToolKindFileWrite},
		{"apply_patch argv command", "apply_patch", mustJSON(map[string]any{"command": []string{"apply_patch", codexPatch}}), []FileOp{
			{Tool: "apply_patch", Op: "write", Path: "src/a.go", AddedLines: 1, RemovedLines: 2},
			{Tool: "apply_patch", Op: "write", Path: "b.txt", AddedLines: 3},
			{Tool: "apply_patch", Op: "write", Path: "c.txt"},
		}, ToolKindFileWrite},
		{"shell heredoc patch", "exec_command", mustJSON(map[string]string{"cmd": "apply_patch <<'EOF'\n" + codexPatch + "EOF"}), []FileOp{
			{Tool: "exec_command", Op: "write", Path: "src/a.go", AddedLines: 1, RemovedLines: 2},
			{Tool: "exec_command", Op: "write", Path: "b.txt", AddedLines: 3},
			{Tool: "exec_command", Op: "write", Path: "c.txt"},
		}, ToolKindShell},
		{"editor view", "str_replace_editor", `{"command":"view","path":"/w/a.go"}`, []FileOp{{Tool: "str_replace_editor", Op: "read", Path: "/w/a.go"}}, ToolKindFileRead},
		{"editor create", "str_replace_editor", `{"command":"create","path":"n","file_text":"a\nb"}`, []FileOp{{Tool: "str_replace_editor", Op: "write", Path: "n", AddedLines: 2}}, ToolKindFileWrite},
		{"editor str_replace", "str_replace_editor", `{"command":"str_replace","path":"p","old_str":"a\nb","new_str":"c"}`, []FileOp{{Tool: "str_replace_editor", Op: "write", Path: "p", AddedLines: 1, RemovedLines: 2}}, ToolKindFileWrite},
		{"editor insert", "str_replace_editor", `{"command":"insert","path":"p","insert_line":1,"new_str":"x\ny\nz"}`, []FileOp{{Tool: "str_replace_editor", Op: "write", Path: "p", AddedLines: 3}}, ToolKindFileWrite},
		{"bad json args", "Read", `{"file_path":`, []FileOp{{Tool: "Read", Op: "read"}}, ToolKindFileRead},
		{"unknown tool", "lookup_customer", `{"path":"x"}`, nil, ToolKindOther},
		{"mcp tool", "mcp__srv__do", `{}`, nil, ToolKindMCP},
		{"spawn", "Task", `{"prompt":"p"}`, nil, ToolKindSpawn},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conv := conversation.New()
			conv.Append(conversation.Message{Role: "assistant", Phase: conversation.PhaseResponse,
				Content: []conversation.Part{{Type: conversation.PartToolCall, Name: tc.tool, Arguments: tc.args}}})
			analysis := analyze(t, Input{Protocol: "openai", Endpoint: "chat_completions", Request: []byte(`{}`), Conversation: conv})
			if len(analysis.Detail.FileOps) != len(tc.want) {
				t.Fatalf("file ops = %+v, want %+v", analysis.Detail.FileOps, tc.want)
			}
			for index, want := range tc.want {
				if analysis.Detail.FileOps[index] != want {
					t.Errorf("op %d = %+v, want %+v", index, analysis.Detail.FileOps[index], want)
				}
			}
			if analysis.ToolKindCounts[tc.kind] != 1 {
				t.Errorf("kind counts = %v, want %s", analysis.ToolKindCounts, tc.kind)
			}
		})
	}
}

func TestAnchor(t *testing.T) {
	cases := []struct {
		name     string
		estimate CategoryValues
		total    int64
		want     CategoryValues
	}{
		{"zero estimate", CategoryValues{}, 100, CategoryValues{}},
		{"zero total", CategoryValues{System: 5}, 0, CategoryValues{}},
		{"negative total", CategoryValues{System: 5}, -3, CategoryValues{}},
		{"exact scale", CategoryValues{System: 10, User: 30}, 80, CategoryValues{System: 20, User: 60}},
		{"largest remainder", CategoryValues{System: 1, Tools: 1, User: 1}, 100, CategoryValues{System: 34, Tools: 33, User: 33}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Anchor(tc.estimate, tc.total); got != tc.want {
				t.Errorf("Anchor = %+v, want %+v", got, tc.want)
			}
		})
	}
	// Sum invariant over a deterministic sweep.
	seed := uint64(12345)
	next := func(limit uint64) int64 {
		seed = seed*6364136223846793005 + 1442695040888963407
		return int64((seed >> 33) % limit)
	}
	for round := 0; round < 2000; round++ {
		estimate := CategoryValues{
			System: next(5000), Tools: next(20000), User: next(300), Injected: next(50),
			Assistant: next(9000), Reasoning: next(100), ToolResult: next(500000), Media: next(2000),
		}
		total := next(2_000_000) + 1
		anchored := Anchor(estimate, total)
		if estimate.Sum() == 0 {
			if anchored.Sum() != 0 {
				t.Fatalf("zero estimate anchored to %+v", anchored)
			}
			continue
		}
		if anchored.Sum() != total {
			t.Fatalf("sum %d != total %d for %+v", anchored.Sum(), total, estimate)
		}
		for name, pair := range map[string][2]int64{
			"system": {estimate.System, anchored.System}, "tool_result": {estimate.ToolResult, anchored.ToolResult},
			"injected": {estimate.Injected, anchored.Injected},
		} {
			if pair[0] == 0 && pair[1] != 0 {
				t.Fatalf("%s: zero estimate received %d", name, pair[1])
			}
		}
	}
	big := Anchor(CategoryValues{System: 3_000_000_000, User: 1_000_000_000}, 9_000_000_000_000)
	if big.Sum() != 9_000_000_000_000 {
		t.Errorf("large values: %+v", big)
	}
}

func TestHintHelpers(t *testing.T) {
	conv := conversation.New()
	conv.Append(conversation.Message{Role: "assistant", Phase: conversation.PhaseResponse, Content: []conversation.Part{
		{Type: conversation.PartToolCall, Name: "Task", Arguments: `{"description":"d","prompt":"  Research the cache layer  "}`},
		{Type: conversation.PartToolCall, Name: "spawn_agent", Arguments: `{"message":"Review the diff"}`},
		{Type: conversation.PartToolCall, Name: "Read", Arguments: `{"prompt":"ignored"}`},
	}})
	prompts := SpawnPrompts(Input{Conversation: conv}, nil)
	if !equalStrings(prompts, []string{"Research the cache layer", "Review the diff"}) {
		t.Errorf("spawn prompts = %q", prompts)
	}

	request := []byte(`{"messages":[{"role":"system","content":"s"},{"role":"user","content":[` +
		`{"type":"text","text":"<system-reminder>r</system-reminder>"},` +
		`{"type":"text","text":"You are a subagent spawned by another session.\nResearch the cache layer"}]},` +
		`{"role":"assistant","content":"later"}]}`)
	opening := OpeningUserTexts(Input{Protocol: "openai", Endpoint: "chat_completions", Request: request}, nil)
	want := []string{
		"<system-reminder>r</system-reminder>",
		"You are a subagent spawned by another session.\nResearch the cache layer",
		"Research the cache layer",
	}
	if !equalStrings(opening, want) {
		t.Errorf("opening = %q", opening)
	}
	fp := testFingerprinter{}
	if !bytes.Equal(HintFPR(fp, prompts[0]), HintFPR(fp, opening[2])) {
		t.Error("hint fingerprints should match after trimming and prefix stripping")
	}
	if OpeningUserTexts(Input{Protocol: "openai", Request: []byte("nope")}, nil) != nil {
		t.Error("unparseable request has no opening texts")
	}
}

func TestSideRequestRole(t *testing.T) {
	cases := []struct {
		name    string
		request string
		want    string
	}{
		{"title", `{"messages":[{"role":"system","content":"You are a title generator. Output a title."},{"role":"user","content":"hello"}]}`, RoleTitle},
		{"compaction trailer", `{"messages":[{"role":"system","content":"agent"},{"role":"user","content":"work"},{"role":"user","content":"Summarize. You MUST use this format for your response: ..."}]}`, RoleCompaction},
		{"ordinary", `{"messages":[{"role":"system","content":"agent"},{"role":"user","content":"work"}]}`, ""},
		{"invalid", `nope`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SideRequestRole(Input{Protocol: "openai", Endpoint: "chat_completions", Request: []byte(tc.request)}, nil)
			if got != tc.want {
				t.Errorf("role = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFingerprintHexLooksLikeHex(t *testing.T) {
	analysis := analyze(t, Input{Protocol: "openai", Endpoint: "chat_completions", Request: []byte(`{"messages":[{"role":"user","content":"x"}]}`)})
	if _, err := hex.DecodeString(analysis.Detail.ItemFPRs[0]); err != nil {
		t.Error(err)
	}
}

func TestAnalyzeRejectsTrailingDataAfterRequestJSON(t *testing.T) {
	t.Parallel()
	valid := `{"model":"claude-test","messages":[{"role":"user","content":"hello"}]}`
	if _, err := Analyze(Input{Protocol: "anthropic", Endpoint: "messages", Request: []byte(valid + " \n")}, nil, testFingerprinter{}); err != nil {
		t.Fatalf("trailing whitespace must be accepted: %v", err)
	}
	for name, body := range map[string]string{
		"second object": valid + `{"model":"other"}`,
		"garbage":       valid + ` trailing`,
		"second value":  valid + ` 1`,
	} {
		if _, err := Analyze(Input{Protocol: "anthropic", Endpoint: "messages", Request: []byte(body)}, nil, testFingerprinter{}); err == nil {
			t.Fatalf("%s: request with trailing data was accepted", name)
		}
	}
}
