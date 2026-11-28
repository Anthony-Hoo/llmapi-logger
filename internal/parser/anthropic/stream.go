package anthropic

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"llmapi-logger/internal/auditmodel"
	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/protocolutil"
	"llmapi-logger/internal/parser/streamevidence"
)

// ConsumedStreamEvents lists the Messages SSE event types the stream fold
// consumes and, for each, the top-level fields it reads. Any other event type
// is kept whole in the residue, and any other field of a listed event is kept
// there too. content_block_delta reads its delta by delta type, see
// ConsumedDeltaTypes.
var ConsumedStreamEvents = map[string][]string{
	"message_start":       {"type", "message"},
	"content_block_start": {"type", "index", "content_block"},
	"content_block_delta": {"type", "index", "delta"},
	"content_block_stop":  {"type", "index"},
	"message_delta":       {"type", "delta", "usage"},
	"message_stop":        {"type"},
	"ping":                {"type"},
}

// ConsumedDeltaTypes lists the content_block_delta delta types the fold
// consumes and the delta fields each reads. An unknown delta type keeps its
// whole event in the residue.
var ConsumedDeltaTypes = map[string][]string{
	"text_delta":       {"type", "text"},
	"thinking_delta":   {"type", "thinking"},
	"signature_delta":  {"type", "signature"},
	"input_json_delta": {"type", "partial_json"},
	"citations_delta":  {"type", "citation"},
}

// consumedMessageDelta lists the message_delta delta fields the fold sets on
// the message.
var consumedMessageDelta = []string{"stop_reason", "stop_sequence"}

// streamFold is a Messages stream folded into the non-stream Message body.
type streamFold struct {
	// message is the aggregate: the message_start message with its content
	// rebuilt from the content blocks and the message_delta fields applied.
	message map[string]any
	residue *streamevidence.Residue
	// problem is why the stream cannot be stored without its raw body; the
	// aggregate is still usable for display.
	problem error
}

// foldStream folds decoded Messages events. Text, thinking and signature
// deltas append to their block's field, input_json_delta text becomes the
// block's input (the parsed object, or the text itself when it is not a JSON
// object), and citations_delta appends to the block's citations, so the
// aggregate is the body the same answer has without streaming.
func foldStream(events []base.SSEEvent) streamFold {
	decoded, markerErr := streamevidence.DecodeEvents(events)
	fold := streamFold{message: map[string]any{}, residue: streamevidence.NewResidue(), problem: markerErr}
	blocks := make(map[int]map[string]any)
	blockStart := make(map[int]int)
	partial := make(map[int]*strings.Builder)
	started := false
	type deltaSet struct {
		event int
		path  []string
		value any
	}
	var deltaSets []deltaSet

	for _, event := range decoded {
		root := event.Object
		if root == nil {
			fold.residue.KeepEvent(event)
			continue
		}
		eventType := protocolutil.String(root["type"])
		if eventType == "" {
			eventType = event.Name
		}
		known, consumed := ConsumedStreamEvents[eventType]
		if !consumed {
			fold.residue.KeepEvent(event)
			continue
		}
		switch eventType {
		case "message_start":
			message := protocolutil.Map(root["message"])
			if message == nil || started {
				fold.residue.KeepEvent(event)
				continue
			}
			started = true
			for key, value := range message {
				if key != "content" {
					fold.message[key] = streamevidence.Clone(value)
				}
			}
			for position, block := range protocolutil.Slice(message["content"]) {
				if object := protocolutil.Map(block); object != nil {
					blocks[position] = streamevidence.Clone(object).(map[string]any)
					blockStart[position] = event.Index
				}
			}
		case "content_block_start":
			index, ok := blockIndex(root)
			block := protocolutil.Map(root["content_block"])
			if !ok || block == nil || blocks[index] != nil {
				fold.residue.KeepEvent(event)
				continue
			}
			blocks[index] = streamevidence.Clone(block).(map[string]any)
			blockStart[index] = event.Index
		case "content_block_delta":
			index, ok := blockIndex(root)
			delta := protocolutil.Map(root["delta"])
			block := blocks[index]
			deltaType := protocolutil.String(delta["type"])
			deltaKnown, deltaConsumed := ConsumedDeltaTypes[deltaType]
			if !ok || block == nil || !deltaConsumed || !applyDelta(block, partial, index, deltaType, delta) {
				fold.residue.KeepEvent(event)
				continue
			}
			fold.residue.KeepUnknownKeys(event.Index, []string{"delta"}, delta, deltaKnown...)
		case "content_block_stop":
			if _, ok := blockIndex(root); !ok {
				fold.residue.KeepEvent(event)
				continue
			}
		case "message_delta":
			delta := protocolutil.Map(root["delta"])
			if root["delta"] != nil && delta == nil {
				fold.residue.KeepEvent(event)
				continue
			}
			usage := protocolutil.Map(root["usage"])
			if root["usage"] != nil && usage == nil {
				fold.residue.KeepEvent(event)
				continue
			}
			for _, key := range consumedMessageDelta {
				if value, exists := delta[key]; exists {
					setReported(fold.message, key, value)
					deltaSets = append(deltaSets, deltaSet{event.Index, []string{"delta", key}, value})
				}
			}
			fold.residue.KeepUnknownKeys(event.Index, []string{"delta"}, delta, consumedMessageDelta...)
			if usage != nil {
				merged := protocolutil.Map(fold.message["usage"])
				if merged == nil {
					merged = map[string]any{}
					fold.message["usage"] = merged
				}
				for key, value := range usage {
					setReported(merged, key, value)
					deltaSets = append(deltaSets, deltaSet{event.Index, []string{"usage", key}, value})
				}
			}
		}
		fold.residue.KeepUnknownKeys(event.Index, nil, root, known...)
	}

	for index, text := range partial {
		block := blocks[index]
		start := block["input"]
		if text.Len() == 0 {
			// Empty input deltas add nothing: the start value stands.
			delete(partial, index)
			continue
		}
		// The input is the parsed object, as in the non-stream body. Its key
		// order and spacing are not kept, the same as for every JSON body
		// stored as canonical JSON. Text that is not a JSON object (a
		// truncated answer) stays the text itself.
		var input any = text.String()
		var parsed map[string]any
		if err := auditmodel.DecodeJSON([]byte(text.String()), &parsed); err == nil && parsed != nil {
			input = parsed
		}
		block["input"] = input
		if _, exists := blockStart[index]; exists && start != nil && !streamevidence.Equal(start, input) {
			// The streamed input replaces the start value; keep a start
			// value that was not the empty object.
			if leftover, keep := streamevidence.Leftover(start, input, true); keep {
				fold.residue.Keep(blockStart[index], startPath(decoded[blockStart[index]], index, "input"), leftover)
			}
		}
	}

	indexes := make([]int, 0, len(blocks))
	for index := range blocks {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	content := make([]any, 0, len(indexes))
	for position, index := range indexes {
		if index != position && fold.problem == nil {
			fold.problem = fmt.Errorf("anthropic normalizer: content block indexes are not dense (missing %d)", position)
		}
		content = append(content, blocks[index])
	}
	fold.message["content"] = content

	// Values a later event replaced are kept with the event that sent them.
	for _, event := range decoded {
		root := event.Object
		if root == nil {
			continue
		}
		eventType := protocolutil.String(root["type"])
		if eventType == "" {
			eventType = event.Name
		}
		switch eventType {
		case "message_start":
			message := protocolutil.Map(root["message"])
			if message == nil || !startedBy(decoded, event.Index) {
				continue
			}
			for key, value := range message {
				if key == "content" {
					fold.residue.KeepLeftover(event.Index, []string{"message", "content"}, value, initialContent(content, value), true)
					continue
				}
				held, exists := fold.message[key]
				fold.residue.KeepLeftover(event.Index, []string{"message", key}, value, held, exists)
			}
		case "content_block_start":
			index, ok := blockIndex(root)
			block := protocolutil.Map(root["content_block"])
			if !ok || block == nil || blockStart[index] != event.Index {
				continue
			}
			for key, value := range block {
				if key == "input" && partial[index] != nil {
					continue
				}
				held, exists := blocks[index][key]
				fold.residue.KeepLeftover(event.Index, []string{"content_block", key}, value, held, exists)
			}
		}
	}
	for _, set := range deltaSets {
		holder := fold.message
		if set.path[0] == "usage" {
			holder = protocolutil.Map(fold.message["usage"])
		}
		held, exists := holder[set.path[1]]
		fold.residue.KeepLeftover(set.event, set.path, set.value, held, exists)
	}
	return fold
}

// applyDelta folds one consumed delta into its block. It reports false when
// the delta does not fit the block, so the whole event is kept instead.
func applyDelta(block map[string]any, partial map[int]*strings.Builder, index int, deltaType string, delta map[string]any) bool {
	switch deltaType {
	case "text_delta":
		return appendText(block, "text", delta["text"])
	case "thinking_delta":
		return appendText(block, "thinking", delta["thinking"])
	case "signature_delta":
		return appendText(block, "signature", delta["signature"])
	case "input_json_delta":
		text, ok := delta["partial_json"].(string)
		if !ok {
			return false
		}
		if partial[index] == nil {
			partial[index] = &strings.Builder{}
		}
		partial[index].WriteString(text)
		return true
	case "citations_delta":
		citation, exists := delta["citation"]
		if !exists {
			return false
		}
		citations, ok := block["citations"].([]any)
		if block["citations"] != nil && !ok {
			return false
		}
		block["citations"] = append(citations, streamevidence.Clone(citation))
		return true
	}
	return false
}

func appendText(block map[string]any, key string, value any) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	current, ok := block[key].(string)
	if block[key] != nil && !ok {
		return false
	}
	block[key] = current + text
	return true
}

// setReported sets a later reported value; null does not replace one.
func setReported(target map[string]any, key string, value any) {
	if value == nil {
		if _, exists := target[key]; exists {
			return
		}
	}
	target[key] = streamevidence.Clone(value)
}

func blockIndex(root map[string]any) (int, bool) {
	if root["index"] == nil {
		return 0, false
	}
	return streamevidence.Int(root["index"])
}

func startedBy(decoded []streamevidence.Event, index int) bool {
	for _, event := range decoded {
		if event.Object == nil {
			continue
		}
		eventType := protocolutil.String(event.Object["type"])
		if eventType == "" {
			eventType = event.Name
		}
		if eventType == "message_start" && protocolutil.Map(event.Object["message"]) != nil {
			return event.Index == index
		}
	}
	return false
}

// initialContent is the aggregate's view of the message_start content: the
// first len(value) blocks, which that content started.
func initialContent(content []any, value any) any {
	initial := protocolutil.Slice(value)
	if len(initial) > len(content) {
		return content
	}
	return content[:len(initial)]
}

func startPath(event streamevidence.Event, index int, key string) []string {
	if protocolutil.String(event.Object["type"]) == "message_start" || (event.Object["type"] == nil && event.Name == "message_start") {
		return []string{"message", "content", streamevidence.Position(index), key}
	}
	return []string{"content_block", key}
}

// streamStopReason is the stop reason of a folded stream.
func (fold streamFold) stopReason() string {
	return protocolutil.String(fold.message["stop_reason"])
}

var errEmptyStream = errors.New("anthropic normalizer: empty SSE")
