// Package protofixture generates deterministic, fully synthetic provider
// traffic for the four audited protocols, in both streaming and non-streaming
// form, and serves it from a fake upstream.
//
// Every byte is derived from a seed: prose is built from a fixed syllable
// list, identifiers come from the same generator, and the only image is a
// tiny PNG drawn from the seed. The wire shapes follow the providers closely
// enough that the repository's parsers accept them, so the same fixtures feed
// parser tests, the A/B load tool (cmd/audit-bench) and later fidelity tests.
package protofixture

import (
	"bytes"
	"net/http"
)

// Protocol names one audited provider API. The value is the parser name used
// in the route configuration, except for Gemini, whose two operations share a
// protocol here and differ only by the stream flag.
type Protocol string

const (
	OpenAIResponses   Protocol = "openai.responses"
	OpenAIChat        Protocol = "openai.chat_completions"
	AnthropicMessages Protocol = "anthropic.messages"
	Gemini            Protocol = "gemini"
)

// Protocols lists every protocol in a stable order.
func Protocols() []Protocol {
	return []Protocol{OpenAIResponses, OpenAIChat, AnthropicMessages, Gemini}
}

// ParseProtocol accepts the protocol names above.
func ParseProtocol(value string) (Protocol, bool) {
	for _, protocol := range Protocols() {
		if string(protocol) == value {
			return protocol, true
		}
	}
	return "", false
}

// Family is the audit_records.protocol value of the protocol.
func (protocol Protocol) Family() string {
	switch protocol {
	case OpenAIResponses, OpenAIChat:
		return "openai"
	case AnthropicMessages:
		return "anthropic"
	default:
		return "gemini"
	}
}

// ParserName is the configured parser of the route the request goes to.
func (protocol Protocol) ParserName(stream bool) string {
	if protocol == Gemini {
		if stream {
			return "gemini.stream_generate_content"
		}
		return "gemini.generate_content"
	}
	return string(protocol)
}

// Scenario names one kind of exchange. Normal scenarios advance a
// conversation; abnormal ones replay the next request with a failed answer.
type Scenario string

const (
	ScenarioBasic        Scenario = "basic"
	ScenarioMultiTurn    Scenario = "multi_turn"
	ScenarioBranch       Scenario = "branch"
	ScenarioToolCalls    Scenario = "tool_calls"
	ScenarioMultimodal   Scenario = "multimodal"
	ScenarioReasoning    Scenario = "reasoning"
	ScenarioUsageShapes  Scenario = "usage_shapes"
	ScenarioExtensions   Scenario = "extensions"
	ScenarioError400     Scenario = "error_400"
	ScenarioError401     Scenario = "error_401"
	ScenarioError422     Scenario = "error_422"
	ScenarioError429     Scenario = "error_429"
	ScenarioError500     Scenario = "error_500"
	ScenarioError503     Scenario = "error_503"
	ScenarioNoTerminal   Scenario = "stream_missing_terminal"
	ScenarioClientCancel Scenario = "stream_client_cancel"
	ScenarioUpstreamCut  Scenario = "stream_upstream_abort"

	// ScenarioMixed is what the load tool sends for a normal turn: features
	// drawn from the seed in realistic proportions.
	ScenarioMixed Scenario = "mixed"
)

// NormalScenarios advance a conversation.
func NormalScenarios() []Scenario {
	return []Scenario{ScenarioBasic, ScenarioMultiTurn, ScenarioBranch, ScenarioToolCalls,
		ScenarioMultimodal, ScenarioReasoning, ScenarioUsageShapes, ScenarioExtensions}
}

// AbnormalScenarios produce an error answer or a broken stream.
func AbnormalScenarios() []Scenario {
	return []Scenario{ScenarioError400, ScenarioError401, ScenarioError422, ScenarioError429,
		ScenarioError500, ScenarioError503, ScenarioNoTerminal, ScenarioClientCancel, ScenarioUpstreamCut}
}

// StreamOnly reports whether the scenario needs a streamed answer.
func (scenario Scenario) StreamOnly() bool {
	return scenario == ScenarioNoTerminal || scenario == ScenarioClientCancel || scenario == ScenarioUpstreamCut
}

// ErrorStatus returns the HTTP status of an error scenario, or 0.
func (scenario Scenario) ErrorStatus() int {
	switch scenario {
	case ScenarioError400:
		return http.StatusBadRequest
	case ScenarioError401:
		return http.StatusUnauthorized
	case ScenarioError422:
		return http.StatusUnprocessableEntity
	case ScenarioError429:
		return http.StatusTooManyRequests
	case ScenarioError500:
		return http.StatusInternalServerError
	case ScenarioError503:
		return http.StatusServiceUnavailable
	default:
		return 0
	}
}

// Features select the optional content of one normal turn.
type Features struct {
	// Tools makes the answer call tools; ParallelTools makes it call two at once.
	Tools         bool
	ParallelTools bool
	// Image attaches a tiny PNG to the new user message.
	Image bool
	// Reasoning adds reasoning or thinking content (with Anthropic signatures).
	Reasoning bool
	// Citations adds an Anthropic citation to the answer text.
	Citations bool
	// UsageShapes reports usage in the protocol's less common shapes.
	UsageShapes bool
	// Extensions adds events and fields the parsers do not consume.
	Extensions bool
}

// Options size and seed the generated traffic.
type Options struct {
	Seed uint64
	// HistoryItems is the number of prior context items already present in the
	// first request of a conversation, which makes a long-running session
	// without replaying all of it.
	HistoryItems int
	// ItemBytes is the approximate prose length of one message, tool argument
	// or tool output.
	ItemBytes int
	// DeltaBytes is the size of one streamed text delta.
	DeltaBytes int
	// ToolDefinitions is the number of tool definitions sent with each request.
	ToolDefinitions int
	// SystemBytes is the length of the system prompt or instructions.
	SystemBytes int
}

// WithDefaults fills zero fields with the small profile.
func (options Options) WithDefaults() Options {
	if options.ItemBytes <= 0 {
		options.ItemBytes = 400
	}
	if options.DeltaBytes <= 0 {
		options.DeltaBytes = 24
	}
	if options.ToolDefinitions <= 0 {
		options.ToolDefinitions = 4
	}
	if options.SystemBytes <= 0 {
		options.SystemBytes = 1200
	}
	if options.HistoryItems < 0 {
		options.HistoryItems = 0
	}
	return options
}

// Usage is the expected parser usage; nil means the parser reports none.
type Usage struct {
	Input  *int64
	Output *int64
	Total  *int64
}

// Expectation is what the repository's parser must extract from an exchange.
// It is computed from the generated content, independently of the parser.
type Expectation struct {
	Status         string
	ErrorType      string
	ErrorCode      string
	RequestModel   string
	ResponseModel  string
	ResponseID     string
	ObservedStream bool
	Usage          Usage
	MessageCount   int
	ToolCallCount  int
}

// Response is the upstream answer of one exchange.
type Response struct {
	Status int
	Header http.Header
	// Chunks are written and flushed one at a time: one per SSE event, or
	// the whole JSON body as a single chunk.
	Chunks [][]byte
	// CutAt, when positive, is the byte offset at which the answer breaks.
	// For a client cancel the client stops reading there; for an upstream
	// abort the upstream writes exactly CutAt bytes and drops the connection.
	CutAt int
	// Abort marks an upstream that drops the connection at CutAt.
	Abort bool
	// ClientCancel marks an answer the client abandons at CutAt.
	ClientCancel bool
}

// Body returns the complete answer bytes.
func (response Response) Body() []byte {
	return bytes.Join(response.Chunks, nil)
}

// Seen returns the bytes a proxy observes: the prefix up to CutAt when the
// answer breaks, otherwise the whole body.
func (response Response) Seen() []byte {
	body := response.Body()
	if response.CutAt > 0 && response.CutAt < len(body) {
		return body[:response.CutAt]
	}
	return body
}

// Exchange is one request and its upstream answer.
type Exchange struct {
	Protocol Protocol
	Scenario Scenario
	Stream   bool
	// Turn counts the requests of the conversation, starting at 1; abnormal
	// exchanges carry the number of the turn they replay.
	Turn int
	// Conversation is the synthetic conversation id the exchange belongs to.
	Conversation string
	// Branch is non-zero for exchanges sent on a fork of the conversation.
	Branch int
	// User is the synthetic gateway user (1-8) whose API key the request
	// carries, for a fake NewAPI log to report.
	User int

	Method        string
	Path          string
	ParserName    string
	RequestHeader http.Header
	RequestBody   []byte
	Response      Response
	Expect        Expectation
}

// IsAbnormal reports whether the exchange is an error or a broken stream.
func (exchange Exchange) IsAbnormal() bool {
	return exchange.Scenario.ErrorStatus() != 0 || exchange.Scenario.StreamOnly()
}
