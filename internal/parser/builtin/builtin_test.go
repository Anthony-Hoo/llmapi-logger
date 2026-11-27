package builtin_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"testing"

	"llmapi-logger/internal/auditmodel"
	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/builtin"
	"llmapi-logger/internal/protofixture"
	"llmapi-logger/internal/security"
)

// TestParserNamesAndVersionsArePinned lists every built-in parser name with
// its version. Both are stored with every parsed audit and select how a turn
// is rebuilt, so a rename or an unplanned version change fails here.
func TestParserNamesAndVersionsArePinned(t *testing.T) {
	t.Parallel()
	want := []string{
		"openai.chat_completions@3",
		"openai.completions@3",
		"openai.responses@3",
		"openai.responses_compact@3",
		"anthropic.messages@3",
		"gemini.generate_content@2",
		"gemini.stream_generate_content@2",
	}
	var got []string
	for _, implementation := range builtin.All() {
		got = append(got, implementation.Name()+"@"+implementation.Version())
	}
	if !slices.Equal(got, want) {
		t.Fatalf("parsers = %q, want %q", got, want)
	}
	if names := builtin.Registry().Names(); len(names) != len(want) {
		t.Fatalf("registry names = %q", names)
	}
	var normalizers []string
	for _, adapter := range builtin.Registry().Adapters() {
		if adapter.Normalizer() != nil {
			normalizers = append(normalizers, adapter.Name())
		}
	}
	if wantNormalizers := []string{"openai.chat_completions", "openai.completions", "openai.responses", "openai.responses_compact", "anthropic.messages"}; !slices.Equal(normalizers, wantNormalizers) {
		t.Fatalf("normalizers = %q, want %q", normalizers, wantNormalizers)
	}
}

// retiredLayouts are layouts no normalizer writes any more. Rows stored with
// them still assemble from the auditmodel table and are projected by the
// adapter of their parser name; a layout moves here when a new layout version
// replaces it.
var retiredLayouts = []string{
	// OpenAI parser version 2 streams: per-event descriptors and display
	// messages, replaced by openai.stream.response.v2 in version 3.
	"openai.stream.response",
}

// TestEveryLayoutHasAnOwner keeps the auditmodel layout table and the adapters
// in step: every layout in the table is written by some adapter today or is
// listed as retired.
func TestEveryLayoutHasAnOwner(t *testing.T) {
	t.Parallel()
	owned := map[string]bool{}
	for _, layout := range retiredLayouts {
		owned[layout] = true
	}
	for _, adapter := range builtin.Registry().Adapters() {
		for _, layout := range adapter.Layouts {
			owned[layout] = true
		}
	}
	for _, layout := range auditmodel.LayoutNames() {
		if !owned[layout] {
			t.Errorf("layout %q is in the auditmodel table but no adapter emits it", layout)
		}
	}
}

func TestRebuildConversationRejectsAParserWithoutRebuild(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"gemini.generate_content", "openai.unknown", ""} {
		if _, err := builtin.Registry().RebuildConversation(name, map[string]any{}, nil, auditmodel.LayoutNone); !errors.Is(err, base.ErrUnknownParser) {
			t.Errorf("%q: error = %v, want ErrUnknownParser", name, err)
		}
	}
}

func TestNewRegistryRejectsInconsistentAdapters(t *testing.T) {
	t.Parallel()
	chat := builtin.Registry().Adapters()[0]
	gemini := builtin.Registry().Adapters()[5]
	cases := map[string][]base.Adapter{
		"duplicate":              {chat, chat},
		"no parser":              {{}},
		"normalizer no rebuild":  {{Parser: chat.Parser, Layouts: chat.Layouts}},
		"normalizer no layouts":  {{Parser: chat.Parser, Conversation: chat.Conversation}},
		"rebuild w/o normalizer": {{Parser: gemini.Parser, Conversation: chat.Conversation}},
		"unknown layout":         {{Parser: chat.Parser, Conversation: chat.Conversation, Layouts: []string{"openai.unknown"}}},
	}
	for name, adapters := range cases {
		if _, err := base.NewRegistry(adapters...); err == nil {
			t.Errorf("%s: registry accepted", name)
		}
	}
}

type normalizeCase struct {
	label  string
	parser string
	input  base.Input
}

func jsonBody(text string) base.BodySource {
	return base.BodySource{Present: true, Complete: true, ContentType: "application/json", Data: []byte(text)}
}

func sseBody(text string) base.BodySource {
	return base.BodySource{Present: true, Complete: true, ContentType: "text/event-stream", Data: []byte(text)}
}

// handCases reach the layouts the fixture corpus does not: single and absent
// request shapes, the Completions and Compact parsers, and a request without
// a response.
func handCases() []normalizeCase {
	status := 200
	input := func(protocol, path string, request, response base.BodySource) base.Input {
		return base.Input{AuditID: "apx_adapter", Protocol: protocol, Endpoint: path, Request: request, Response: response, StatusCode: &status}
	}
	completionsJSON := jsonBody(`{"id":"cmpl-example","model":"model-example","choices":[{"index":0,"text":"answer"}]}`)
	completionsSSE := sseBody("data: {\"id\":\"cmpl-example\",\"model\":\"model-example\",\"choices\":[{\"index\":0,\"text\":\"answer\"}]}\n\ndata: [DONE]\n\n")
	responsesJSON := jsonBody(`{"id":"resp-example","model":"model-example","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"answer"}]}]}`)
	responsesSSE := sseBody("event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-example\",\"model\":\"model-example\",\"output\":[]}}\n\n")
	var cases []normalizeCase
	for _, name := range []string{"openai.responses", "openai.responses_compact"} {
		path := "/v1/responses"
		if name == "openai.responses_compact" {
			path = "/v1/responses/compact"
		}
		cases = append(cases,
			normalizeCase{name + "/input array", name, input("openai", path, jsonBody(`{"model":"model-example","instructions":"be brief","input":[{"role":"user","content":"hello"}]}`), responsesJSON)},
			normalizeCase{name + "/input single", name, input("openai", path, jsonBody(`{"model":"model-example","input":"hello"}`), responsesSSE)},
			normalizeCase{name + "/input none", name, input("openai", path, jsonBody(`{"model":"model-example","previous_response_id":"resp-example"}`), base.BodySource{})},
		)
	}
	cases = append(cases,
		normalizeCase{"completions/prompt single", "openai.completions", input("openai", "/v1/completions", jsonBody(`{"model":"model-example","prompt":"hello"}`), completionsJSON)},
		normalizeCase{"completions/prompt array", "openai.completions", input("openai", "/v1/completions", jsonBody(`{"model":"model-example","prompt":["hello","again"],"stream":true}`), completionsSSE)},
		normalizeCase{"completions/no response", "openai.completions", input("openai", "/v1/completions", jsonBody(`{"model":"model-example","prompt":"hello"}`), base.BodySource{})},
		normalizeCase{"chat/no response", "openai.chat_completions", input("openai", "/v1/chat/completions", jsonBody(`{"model":"model-example","messages":[{"role":"user","content":"hello"}]}`), base.BodySource{})},
		normalizeCase{"anthropic/system none", "anthropic.messages", input("anthropic", "/v1/messages", jsonBody(`{"model":"model-example","max_tokens":16,"messages":[{"role":"user","content":"hello"}]}`), base.BodySource{})},
		normalizeCase{"anthropic/system single", "anthropic.messages", input("anthropic", "/v1/messages", jsonBody(`{"model":"model-example","max_tokens":16,"system":"be brief","messages":[{"role":"user","content":"hello"}]}`), base.BodySource{})},
		normalizeCase{"anthropic/system array", "anthropic.messages", input("anthropic", "/v1/messages", jsonBody(`{"model":"model-example","max_tokens":16,"system":[{"type":"text","text":"be brief"}],"messages":[{"role":"user","content":"hello"}]}`), base.BodySource{})},
	)
	return cases
}

// fixtureCases are the complete exchanges of the protocol fixture corpus.
func fixtureCases(t *testing.T) []normalizeCase {
	t.Helper()
	var cases []normalizeCase
	for _, value := range protofixture.Catalog() {
		exchanges, err := protofixture.Build(value, protofixture.Options{Seed: 42})
		if err != nil {
			t.Fatalf("%s: %v", value, err)
		}
		for index, exchange := range exchanges {
			path := exchange.Path
			if parsed, err := url.Parse(path); err == nil {
				path = parsed.Path
			}
			status := exchange.Response.Status
			if exchange.Response.CutAt > 0 {
				continue
			}
			cases = append(cases, normalizeCase{
				label:  fmt.Sprintf("%s#%d", value, index),
				parser: exchange.ParserName,
				input: base.Input{
					AuditID: "apx_fixture", Protocol: exchange.Protocol.Family(), Endpoint: path, StatusCode: &status,
					Request:  base.BodySource{Present: true, Complete: true, ContentType: exchange.RequestHeader.Get("Content-Type"), Data: exchange.RequestBody},
					Response: base.BodySource{Present: true, Complete: true, ContentType: exchange.Response.Header.Get("Content-Type"), Data: exchange.Response.Seen()},
				},
			})
		}
	}
	return cases
}

// TestEveryNormalizingAdapterIsWired drives every adapter with a normalizer
// over the fixture corpus and hand-made requests. Each normalized turn must
// use only layouts its adapter declares, prepare (which assembles both sides
// and checks them against the original), and project back to a conversation
// through the registry; and every declared layout must be reached, so the
// declaration is the set the normalizer really emits.
func TestEveryNormalizingAdapterIsWired(t *testing.T) {
	t.Parallel()
	registry := builtin.Registry()
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	emitted := map[string]map[string]bool{}
	for _, test := range append(fixtureCases(t), handCases()...) {
		adapter, ok := registry.Lookup(test.parser)
		if !ok {
			t.Fatalf("%s: no adapter %q", test.label, test.parser)
		}
		normalizer := adapter.Normalizer()
		if normalizer == nil {
			continue
		}
		result := adapter.Parser.Parse(context.Background(), test.input)
		if result.Status != base.StatusOK {
			continue
		}
		turn, err := normalizer.NormalizeAudit(context.Background(), test.input, result)
		if err != nil {
			t.Errorf("%s: normalize: %v", test.label, err)
			continue
		}
		if emitted[test.parser] == nil {
			emitted[test.parser] = map[string]bool{}
		}
		for _, layout := range []string{turn.RequestLayout, turn.ResponseLayout} {
			emitted[test.parser][layout] = true
			if !slices.Contains(adapter.Layouts, layout) {
				t.Errorf("%s: emitted layout %q is not declared by adapter %q", test.label, layout, test.parser)
			}
		}
		turn.AuditID, turn.Protocol, turn.ParserName, turn.CreatedAtNS = test.input.AuditID, test.input.Protocol, test.parser, 1
		if _, err := auditmodel.Prepare(turn, cipher); err != nil {
			t.Errorf("%s: prepare: %v", test.label, err)
			continue
		}
		request, err := auditmodel.Assemble(turn.RequestLayout, turn.RequestEnvelope, turn.RequestItems)
		if err != nil {
			t.Errorf("%s: assemble request: %v", test.label, err)
			continue
		}
		response, err := auditmodel.Assemble(turn.ResponseLayout, turn.ResponseEnvelope, turn.ResponseItems)
		if err != nil {
			t.Errorf("%s: assemble response: %v", test.label, err)
			continue
		}
		view, err := registry.RebuildConversation(test.parser, request, response, turn.ResponseLayout)
		hasItems := len(turn.RequestItems)+len(turn.ResponseItems) > 0
		if err != nil || (hasItems && (view == nil || len(view.Messages) == 0)) {
			t.Errorf("%s: conversation rebuild = %v, %v", test.label, view, err)
		}
	}
	for _, adapter := range registry.Adapters() {
		if adapter.Normalizer() == nil {
			continue
		}
		var missing []string
		for _, layout := range adapter.Layouts {
			if !emitted[adapter.Name()][layout] {
				missing = append(missing, layout)
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			t.Errorf("adapter %q declares layouts no case emitted: %q", adapter.Name(), missing)
		}
	}
}
