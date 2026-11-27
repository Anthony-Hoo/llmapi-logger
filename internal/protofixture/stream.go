package protofixture

import (
	"bytes"
	"net/http"
)

// renderer turns the neutral conversation into one provider's wire format.
type renderer interface {
	path(*Conversation) string
	// request returns the body plus the message and tool-call counts the
	// parser derives from it.
	request(*Conversation, []item, Features) (body []byte, messages, toolCalls int)
	// answer renders a successful answer, streamed or not.
	answer(*Conversation, answer, Features) rendered
	// errorBody renders the provider's JSON error for an HTTP status.
	errorBody(*Conversation, int) (body []byte, errorType, errorCode string)
}

func rendererFor(protocol Protocol) renderer {
	switch protocol {
	case OpenAIResponses:
		return responsesRenderer{}
	case OpenAIChat:
		return chatRenderer{}
	case AnthropicMessages:
		return anthropicRenderer{}
	default:
		return geminiRenderer{}
	}
}

// rendered is an answer split into the pieces the upstream writes, each with
// the effect a parser takes from it.
type rendered struct {
	header http.Header
	chunks []chunk
	json   bool
}

type chunk struct {
	data   []byte
	effect effect
}

// effect is what one chunk contributes to the parse result.
type effect struct {
	model string
	id    string
	usage *usageEffect
	// toolKeys identify tool calls; repeated keys count once.
	toolKeys []string
	terminal bool
	// closing marks the chunks that end a stream; a stream that stops
	// without its terminal event drops all of them.
	closing bool
}

// usageEffect replaces the reported usage. perField replaces only the fields
// present, which is how the Anthropic parser folds message_start and
// message_delta; otherwise all three fields are replaced together.
type usageEffect struct {
	perField bool
	input    *int64
	output   *int64
	total    *int64
}

func int64Pointer(value int64) *int64 { return &value }

func sseEvent(name string, payload any) []byte {
	var buffer bytes.Buffer
	if name != "" {
		buffer.WriteString("event: ")
		buffer.WriteString(name)
		buffer.WriteByte('\n')
	}
	buffer.WriteString("data: ")
	buffer.Write(mustJSON(payload))
	buffer.WriteString("\n\n")
	return buffer.Bytes()
}

func sseHeader() http.Header {
	header := make(http.Header)
	header.Set("Content-Type", "text/event-stream; charset=utf-8")
	header.Set("Cache-Control", "no-cache")
	return header
}

func jsonHeader() http.Header {
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	return header
}

// finish folds a complete answer into the response and its expectation.
func finish(protocol Protocol, answer rendered, status int, expect Expectation) (Response, Expectation) {
	response := Response{Status: status, Header: answer.header}
	for _, piece := range answer.chunks {
		response.Chunks = append(response.Chunks, piece.data)
	}
	return response, fold(protocol, answer.chunks, !answer.json, true, false, expect)
}

func errorAnswer(render renderer, conversation *Conversation, status int, expect Expectation) (Response, Expectation) {
	body, errorType, errorCode := render.errorBody(conversation, status)
	response := Response{Status: status, Header: jsonHeader(), Chunks: [][]byte{body}}
	expect.ObservedStream = false
	expect.ErrorType = errorType
	expect.ErrorCode = errorCode
	return response, expect
}

// breakStream turns a complete streamed answer into an abnormal one: without
// its closing events, abandoned by the client midway, or cut by the upstream.
func breakStream(protocol Protocol, scenario Scenario, answer rendered, expect Expectation) (Response, Expectation) {
	response := Response{Status: http.StatusOK, Header: answer.header}
	if scenario == ScenarioNoTerminal {
		kept := make([]chunk, 0, len(answer.chunks))
		for _, piece := range answer.chunks {
			if !piece.effect.closing {
				kept = append(kept, piece)
				response.Chunks = append(response.Chunks, piece.data)
			}
		}
		return response, fold(protocol, kept, true, true, false, expect)
	}
	// Cut inside the data payload of a content event in the middle of the
	// stream, so the parser sees an unterminated, unparsable last event.
	candidates := make([]int, 0, len(answer.chunks))
	for index := 1; index < len(answer.chunks); index++ {
		if !answer.chunks[index].effect.closing {
			candidates = append(candidates, index)
		}
	}
	cut := len(answer.chunks) - 1
	if len(candidates) > 0 {
		cut = candidates[len(candidates)/2]
	}
	offset := 0
	for _, piece := range answer.chunks[:cut] {
		offset += len(piece.data)
	}
	offset += cutInsideData(answer.chunks[cut].data)
	for _, piece := range answer.chunks {
		response.Chunks = append(response.Chunks, piece.data)
	}
	response.CutAt = offset
	response.Abort = scenario == ScenarioUpstreamCut
	response.ClientCancel = scenario == ScenarioClientCancel
	return response, fold(protocol, answer.chunks[:cut], true, false, true, expect)
}

// cutInsideData returns an offset in the middle of the event's data payload.
func cutInsideData(event []byte) int {
	start := bytes.Index(event, []byte("data: "))
	if start < 0 {
		return len(event) / 2
	}
	start += len("data: ")
	end := bytes.IndexAny(event[start:], "\r\n")
	if end < 0 {
		end = len(event) - start
	}
	return start + max(1, end/2)
}

func fold(protocol Protocol, chunks []chunk, stream, tailClosed, malformed bool, expect Expectation) Expectation {
	expect.ObservedStream = stream
	keys := make(map[string]struct{})
	terminal := false
	for _, piece := range chunks {
		value := piece.effect
		if value.model != "" {
			expect.ResponseModel = value.model
		}
		if value.id != "" {
			expect.ResponseID = value.id
		}
		if usage := value.usage; usage != nil {
			if usage.perField {
				if usage.input != nil {
					expect.Usage.Input = usage.input
				}
				if usage.output != nil {
					expect.Usage.Output = usage.output
				}
				if usage.total != nil {
					expect.Usage.Total = usage.total
				}
			} else {
				expect.Usage = Usage{Input: usage.input, Output: usage.output, Total: usage.total}
			}
		}
		for _, key := range value.toolKeys {
			keys[key] = struct{}{}
		}
		terminal = terminal || value.terminal
	}
	expect.ToolCallCount += len(keys)
	if !stream {
		return expect
	}
	switch {
	case malformed:
		expect.Status, expect.ErrorCode = "partial", "invalid_sse_event"
	case !tailClosed:
		expect.Status, expect.ErrorCode = "partial", "unterminated_sse_event"
	case !terminal:
		expect.Status = "partial"
		switch protocol {
		case AnthropicMessages:
			expect.ErrorCode = "missing_message_stop"
		case Gemini:
			// A Gemini stream ends with the chunk that carries the
			// candidate's finishReason.
			expect.ErrorCode = "missing_finish_reason"
		default:
			expect.ErrorCode = "missing_terminal_event"
		}
	}
	return expect
}
