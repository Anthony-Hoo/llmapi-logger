package protofixture

import (
	"fmt"
	"net/http"
)

type itemKind uint8

const (
	kindUser itemKind = iota
	kindAssistant
	kindReasoning
	kindToolCall
	kindToolResult
)

// item is one protocol-neutral piece of conversation. Items of one assistant
// answer, or one batch of tool results, share a group so renderers can fold
// them into a single provider message where the protocol requires it.
type item struct {
	kind  itemKind
	group int
	id    string
	text  string
	image []byte
	// Tool calls and results.
	callID    string
	name      string
	args      string
	argsValue object
	// signature is the opaque reasoning signature or encrypted content.
	signature string
	// citation marks assistant text that quotes a document.
	citation bool
}

type toolDefinition struct {
	name        string
	description string
	parameter   string
}

// answer is the generated assistant output of one turn.
type answer struct {
	id      string
	created int64
	items   []item
	usage   usageNumbers
}

type usageNumbers struct {
	input      int64
	cached     int64
	cacheWrite int64
	output     int64
	reasoning  int64
	toolPrompt int64
}

func (usage usageNumbers) total() int64 { return usage.input + usage.output }

// Conversation generates the successive requests of one synthetic client
// session. Each request resends the whole history, the way agent clients do.
// A Conversation is not safe for concurrent use.
type Conversation struct {
	protocol Protocol
	stream   bool
	options  Options
	text     *textSource
	index    int
	branch   int

	id            string
	key           string
	apiKey        string
	user          int
	model         string
	responseModel string
	system        string
	tools         []toolDefinition
	image         []byte
	headers       http.Header

	history   []item
	nextGroup int
	turn      int
	// pending holds the new input items of the next request once prepared,
	// so a failed attempt and its retry send identical bytes.
	pending []item
	// openCalls are the tool calls of the last answer, which the next
	// request answers with tool results.
	openCalls []item
	clock     int64
}

// NewConversation starts conversation index of a seeded workload.
func NewConversation(protocol Protocol, stream bool, options Options, index int) *Conversation {
	options = options.WithDefaults()
	text := newTextSource(options.Seed, uint64(index)<<8|1)
	conversation := &Conversation{
		protocol: protocol,
		stream:   stream,
		options:  options,
		text:     text,
		index:    index,
		clock:    1_760_000_000 + int64(index)*7,
	}
	conversation.id = "conv-" + text.hex(6)
	conversation.key = text.uuid()
	conversation.user = 1 + index%8
	conversation.apiKey = fmt.Sprintf("sk-bench%02d%s", conversation.user, newTextSource(options.Seed, uint64(conversation.user)).alnum(40))
	conversation.model, conversation.responseModel = protocolModels(protocol)
	// One client sends the same system prompt and tool definitions in every
	// session, so they derive from the seed and the protocol only and are
	// shared across conversations, as in a real deployment.
	shared := newTextSource(options.Seed, protocolStream(protocol))
	conversation.system = shared.paragraphs(options.SystemBytes)
	conversation.image = TinyPNG(options.Seed^uint64(index), 4)
	for range options.ToolDefinitions {
		conversation.tools = append(conversation.tools, toolDefinition{
			name:        fmt.Sprintf("%s_%s", shared.word(), shared.word()),
			description: shared.sentence(120 + options.ItemBytes/4),
			parameter:   shared.word(),
		})
	}
	conversation.headers = clientHeaders(protocol, conversation)
	conversation.seedHistory()
	return conversation
}

// protocolStream is the generator stream of the per-protocol shared text,
// far above the streams of any realistic conversation index.
func protocolStream(protocol Protocol) uint64 {
	for index, candidate := range Protocols() {
		if candidate == protocol {
			return 0xc11e47<<8 | uint64(index)
		}
	}
	return 0xc11e47 << 8
}

func protocolModels(protocol Protocol) (string, string) {
	switch protocol {
	case OpenAIResponses:
		return "gpt-5", "gpt-5-2025-08-07"
	case OpenAIChat:
		// Not a gpt model: the default user-agent rule would reject a gpt
		// model from a generic SDK client before it reaches the upstream.
		return "o4-mini", "o4-mini-2025-04-16"
	case AnthropicMessages:
		return "claude-sonnet-4-5", "claude-sonnet-4-5-20250929"
	default:
		return "gemini-2.5-pro", "gemini-2.5-pro"
	}
}

// seedHistory fills the configured amount of prior context: rounds of a user
// message and an answer, every third round going through one tool call.
func (conversation *Conversation) seedHistory() {
	for round := 0; len(conversation.history) < conversation.options.HistoryItems; round++ {
		conversation.history = append(conversation.history, conversation.userItem(false))
		if round%3 == 2 {
			call := conversation.toolCall(conversation.group())
			conversation.history = append(conversation.history, call)
			conversation.history = append(conversation.history, conversation.toolResults([]item{call})...)
		}
		group := conversation.group()
		conversation.history = append(conversation.history, item{
			kind: kindAssistant, group: group, id: conversation.itemID("msg"),
			text: conversation.text.paragraphs(conversation.options.ItemBytes),
		})
	}
}

func (conversation *Conversation) group() int {
	conversation.nextGroup++
	return conversation.nextGroup
}

func (conversation *Conversation) itemID(prefix string) string {
	return prefix + "_" + conversation.text.hex(12)
}

func (conversation *Conversation) userItem(image bool) item {
	value := item{kind: kindUser, group: conversation.group(), text: conversation.text.paragraphs(conversation.options.ItemBytes)}
	if image {
		value.image = conversation.image
	}
	return value
}

func (conversation *Conversation) toolCall(group int) item {
	definition := toolDefinition{name: "read_file", parameter: "path"}
	if len(conversation.tools) > 0 {
		definition = conversation.tools[conversation.text.intn(len(conversation.tools))]
	}
	arguments := obj(definition.parameter, conversation.text.sentence(max(24, conversation.options.ItemBytes/8)),
		"limit", 20+conversation.text.intn(200))
	return item{
		kind: kindToolCall, group: group, id: conversation.itemID("fc"),
		callID: conversation.text.alnum(24), name: definition.name, args: jsonString(arguments), argsValue: arguments,
	}
}

func (conversation *Conversation) toolResults(calls []item) []item {
	group := conversation.group()
	results := make([]item, 0, len(calls))
	for _, call := range calls {
		results = append(results, item{
			kind: kindToolResult, group: group, callID: call.callID, name: call.name,
			text: conversation.text.paragraphs(conversation.options.ItemBytes),
		})
	}
	return results
}

// Fork returns an independent copy that shares the history so far and then
// diverges: the two continuations of one prefix form a branch.
func (conversation *Conversation) Fork() *Conversation {
	forked := *conversation
	forked.branch = conversation.branch + 1
	forked.text = newTextSource(conversation.options.Seed, uint64(conversation.index)<<8|uint64(2+forked.branch))
	forked.history = append([]item(nil), conversation.history...)
	forked.openCalls = append([]item(nil), conversation.openCalls...)
	forked.pending = nil
	forked.headers = conversation.headers.Clone()
	return &forked
}

// Turn returns the number of committed turns.
func (conversation *Conversation) Turn() int { return conversation.turn }

// Protocol returns the conversation's protocol.
func (conversation *Conversation) Protocol() Protocol { return conversation.protocol }

// Stream reports whether the conversation streams its answers.
func (conversation *Conversation) Stream() bool { return conversation.stream }

// CanBranch reports whether the next request can diverge: a pending tool
// result would make both continuations send the same bytes.
func (conversation *Conversation) CanBranch() bool { return len(conversation.openCalls) == 0 }

// ID returns the synthetic conversation id.
func (conversation *Conversation) ID() string { return conversation.id }

func (conversation *Conversation) prepare(features Features) []item {
	if conversation.pending != nil {
		return conversation.pending
	}
	if len(conversation.openCalls) > 0 {
		conversation.pending = conversation.toolResults(conversation.openCalls)
	} else {
		conversation.pending = []item{conversation.userItem(features.Image)}
	}
	return conversation.pending
}

// Next builds the next normal turn and commits it to the history.
func (conversation *Conversation) Next(scenario Scenario, features Features) Exchange {
	inputs := conversation.prepare(features)
	reply := conversation.answer(features)
	exchange := conversation.exchange(scenario, inputs, features)
	render := rendererFor(conversation.protocol)
	exchange.Response, exchange.Expect = finish(conversation.protocol, render.answer(conversation, reply, features), http.StatusOK, exchange.Expect)

	conversation.history = append(conversation.history, inputs...)
	conversation.history = append(conversation.history, reply.items...)
	conversation.openCalls = conversation.openCalls[:0]
	for _, value := range reply.items {
		if value.kind == kindToolCall {
			conversation.openCalls = append(conversation.openCalls, value)
		}
	}
	conversation.pending = nil
	conversation.turn++
	return exchange
}

// Abnormal builds the next request with a failed answer. It does not commit:
// the following Next sends the same request again, like a client retry.
func (conversation *Conversation) Abnormal(scenario Scenario) (Exchange, error) {
	if scenario.ErrorStatus() == 0 && !scenario.StreamOnly() {
		return Exchange{}, fmt.Errorf("protofixture: %s is not an abnormal scenario", scenario)
	}
	if scenario.StreamOnly() && !conversation.stream {
		return Exchange{}, fmt.Errorf("protofixture: %s needs a streaming conversation", scenario)
	}
	inputs := conversation.prepare(Features{})
	exchange := conversation.exchange(scenario, inputs, Features{})
	render := rendererFor(conversation.protocol)
	if status := scenario.ErrorStatus(); status != 0 {
		exchange.Response, exchange.Expect = errorAnswer(render, conversation, status, exchange.Expect)
		return exchange, nil
	}
	// A broken stream carries a plain text answer so the cut lands in text.
	reply := conversation.answer(Features{})
	exchange.Response, exchange.Expect = breakStream(conversation.protocol, scenario, render.answer(conversation, reply, Features{}), exchange.Expect)
	return exchange, nil
}

func (conversation *Conversation) exchange(scenario Scenario, inputs []item, features Features) Exchange {
	render := rendererFor(conversation.protocol)
	all := make([]item, 0, len(conversation.history)+len(inputs))
	all = append(all, conversation.history...)
	all = append(all, inputs...)
	body, messages, tools := render.request(conversation, all, features)
	header := conversation.headers.Clone()
	return Exchange{
		Protocol:      conversation.protocol,
		Scenario:      scenario,
		Stream:        conversation.stream,
		Turn:          conversation.turn + 1,
		Conversation:  conversation.id,
		Branch:        conversation.branch,
		User:          conversation.user,
		Method:        http.MethodPost,
		Path:          render.path(conversation),
		ParserName:    conversation.protocol.ParserName(conversation.stream),
		RequestHeader: header,
		RequestBody:   body,
		Expect: Expectation{
			Status:         "ok",
			RequestModel:   conversation.model,
			ObservedStream: conversation.stream,
			MessageCount:   messages,
			ToolCallCount:  tools,
		},
	}
}

func (conversation *Conversation) answer(features Features) answer {
	conversation.clock += 3 + int64(conversation.text.intn(40))
	group := conversation.group()
	reply := answer{id: conversation.text.alnum(24), created: conversation.clock}
	reasoningBytes := 0
	if features.Reasoning {
		text := conversation.text.paragraphs(max(80, conversation.options.ItemBytes/2))
		reasoningBytes = len(text)
		reply.items = append(reply.items, item{
			kind: kindReasoning, group: group, id: conversation.itemID("rs"), text: text,
			signature: base64PNG([]byte(conversation.text.hex(48))),
		})
	}
	calls := 0
	if features.Tools {
		calls = 1
		if features.ParallelTools {
			calls = 2
		}
	}
	if calls == 0 || conversation.text.chance(0.5) {
		length := conversation.options.ItemBytes
		if calls > 0 {
			length = max(40, length/6)
		}
		reply.items = append(reply.items, item{
			kind: kindAssistant, group: group, id: conversation.itemID("msg"),
			text: conversation.text.paragraphs(length), citation: features.Citations,
		})
	}
	for range calls {
		reply.items = append(reply.items, conversation.toolCall(group))
	}
	outputBytes := 0
	for _, value := range reply.items {
		outputBytes += len(value.text) + len(value.args)
	}
	contextBytes := 0
	for _, value := range conversation.history {
		contextBytes += len(value.text) + len(value.args)
	}
	reply.usage = usageNumbers{
		input:     int64(len(conversation.system)+contextBytes)/4 + 40 + int64(conversation.options.ItemBytes/4),
		output:    int64(outputBytes/4) + 3,
		reasoning: int64(reasoningBytes / 4),
	}
	if conversation.turn > 0 || conversation.options.HistoryItems > 0 {
		reply.usage.cached = reply.usage.input * 7 / 10 / 64 * 64
	}
	if features.UsageShapes {
		reply.usage.cacheWrite = 128
		reply.usage.toolPrompt = 17
	}
	return reply
}

// MixedFeatures draws the features of one normal turn the way an agent
// session mixes them: mostly reasoning, frequent tool calls, rare images.
func (conversation *Conversation) MixedFeatures() Features {
	text := conversation.text
	features := Features{
		Reasoning:  text.chance(0.7),
		Tools:      text.chance(0.45),
		Extensions: text.chance(0.3),
	}
	features.ParallelTools = features.Tools && text.chance(0.3)
	features.Image = text.chance(0.08) || (conversation.turn == 0 && text.chance(0.25))
	features.Citations = conversation.protocol == AnthropicMessages && text.chance(0.1)
	features.UsageShapes = text.chance(0.2)
	return features
}

func clientHeaders(protocol Protocol, conversation *Conversation) http.Header {
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	switch protocol {
	case OpenAIResponses:
		header.Set("Authorization", "Bearer "+conversation.apiKey)
		// The default user-agent rule admits gpt models only from Codex
		// clients; the originator header lets insights recognise the client.
		header.Set("User-Agent", "Codex Desktop/0.0.0 (Synthetic 1.0; x86_64)")
		header.Set("Accept", "text/event-stream")
		header.Set("Originator", "Codex Desktop")
		header.Set("Session-Id", conversation.key)
		header.Set("Thread-Id", conversation.key)
		header.Set("Version", "0.0.0")
		header.Set("Openai-Beta", "responses=experimental")
		header.Set("X-Codex-Turn-Metadata", jsonString(obj("workspace", "bench-"+conversation.text.word())))
	case OpenAIChat:
		header.Set("Authorization", "Bearer "+conversation.apiKey)
		header.Set("User-Agent", "OpenAI/Python 0.0.0")
		header.Set("Accept", "application/json")
		header.Set("X-Stainless-Lang", "python")
		header.Set("X-Stainless-Package-Version", "0.0.0")
		header.Set("X-Stainless-Os", "Linux")
		header.Set("X-Stainless-Arch", "x64")
		header.Set("X-Stainless-Runtime", "CPython")
		header.Set("X-Stainless-Runtime-Version", "3.12.0")
		header.Set("X-Stainless-Retry-Count", "0")
		header.Set("X-Stainless-Read-Timeout", "600")
	case AnthropicMessages:
		header.Set("X-Api-Key", conversation.apiKey)
		header.Set("User-Agent", "claude-cli/0.0.0 (external, cli)")
		header.Set("Accept", "application/json")
		header.Set("Anthropic-Version", "2023-06-01")
		header.Set("Anthropic-Beta", "interleaved-thinking-2025-05-14,fine-grained-tool-streaming-2025-05-14")
		header.Set("Anthropic-Dangerous-Direct-Browser-Access", "true")
		header.Set("X-App", "cli")
		header.Set("X-Claude-Code-Session-Id", conversation.key)
		header.Set("X-Stainless-Lang", "js")
		header.Set("X-Stainless-Package-Version", "0.0.0")
		header.Set("X-Stainless-Os", "Linux")
		header.Set("X-Stainless-Arch", "x64")
		header.Set("X-Stainless-Runtime", "node")
		header.Set("X-Stainless-Runtime-Version", "v22.0.0")
		header.Set("X-Stainless-Retry-Count", "0")
		header.Set("X-Stainless-Timeout", "600")
	default:
		header.Set("X-Goog-Api-Key", conversation.apiKey)
		header.Set("User-Agent", "GeminiCLI/0.0.0 (linux; x64)")
		header.Set("Accept", "*/*")
		header.Set("X-Goog-Api-Client", "google-genai-sdk/0.0.0 gl-node/v22.0.0")
	}
	return header
}
