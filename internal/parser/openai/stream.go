package openai

import (
	"fmt"
	"sort"
	"strings"

	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/protocolutil"
	"llmapi-logger/internal/parser/streamevidence"
)

// The Chat Completions and Completions stream fold consumes one event type,
// the chunk, plus the "[DONE]" terminator. These lists name the fields it
// reads at each level of a chunk; any other field is kept in the residue. A
// choice's logprobs object is read field by field: every array is appended
// to the same field of the body's logprobs (Chat content and refusal,
// Completions tokens, token_logprobs, top_logprobs and text_offset), null
// fills an absent field, and any other value is kept in the residue.
var (
	ConsumedChatChunkFields    = []string{"id", "object", "created", "model", "service_tier", "system_fingerprint", "choices", "usage"}
	ConsumedChatChoiceFields   = []string{"index", "delta", "message", "text", "logprobs", "finish_reason"}
	ConsumedChatDeltaFields    = []string{"role", "name", "content", "refusal", "reasoning_content", "reasoning", "thinking", "tool_calls", "function_call"}
	ConsumedChatToolCallFields = []string{"index", "id", "type", "function"}
	ConsumedChatFunctionFields = []string{"name", "arguments"}
)

// chatSnapshotFields are chunk fields every chunk repeats; the body keeps the
// last reported value.
var chatSnapshotFields = []string{"id", "object", "created", "model", "service_tier", "system_fingerprint"}

// chatTextFields are delta fields whose pieces are concatenated.
var chatTextFields = []string{"content", "refusal", "reasoning_content", "reasoning", "thinking"}

// streamFold is a stream folded into the provider's non-stream body.
type streamFold struct {
	body    map[string]any
	residue *streamevidence.Residue
	// stopReason is the provider stop reason, in a form the insights stop
	// mapping reads the same way it reads the raw stream.
	stopReason string
	// problem is why the stream cannot be stored without its raw body; the
	// body is still usable for display.
	problem error
}

type chatChoice struct {
	value     map[string]any
	message   map[string]any
	tools     map[int]map[string]any
	toolOrder []int
	snapshot  map[string]any
}

func isDone(event streamevidence.Event) bool {
	return event.Object == nil && strings.TrimSpace(string(event.Data)) == "[DONE]"
}

// foldChatStream folds Chat Completions or Completions chunks into the
// non-stream body: chunk fields keep their last reported value, choices are
// keyed by index, delta text and tool-call names and arguments are
// concatenated, and a choice that sends a whole message keeps that message.
// The body's object stays the chunk's.
func foldChatStream(events []base.SSEEvent) streamFold {
	decoded, markerErr := streamevidence.DecodeEvents(events)
	fold := streamFold{body: map[string]any{}, residue: streamevidence.NewResidue(), problem: markerErr}
	choices := make(map[int]*chatChoice)
	choice := func(index int) *chatChoice {
		if choices[index] == nil {
			choices[index] = &chatChoice{value: map[string]any{"index": index}, message: map[string]any{}, tools: map[int]map[string]any{}}
		}
		return choices[index]
	}
	choiceIndex := func(value map[string]any, position int) int {
		if index, ok := streamevidence.Int(value["index"]); ok && value["index"] != nil {
			return index
		}
		return position
	}
	// A choice that sends a whole message keeps it; its deltas stay in the
	// residue.
	for _, event := range decoded {
		for position, value := range protocolutil.Slice(event.Object["choices"]) {
			object := protocolutil.Map(value)
			if message := protocolutil.Map(object["message"]); message != nil {
				choice(choiceIndex(object, position)).snapshot = message
			}
		}
	}

	for _, event := range decoded {
		root := event.Object
		if root == nil {
			if !isDone(event) {
				fold.residue.KeepEvent(event)
			}
			continue
		}
		fold.residue.KeepUnknownKeys(event.Index, nil, root, ConsumedChatChunkFields...)
		for _, key := range chatSnapshotFields {
			if value, exists := root[key]; exists {
				setReported(fold.body, key, value)
			}
		}
		if value, exists := root["usage"]; exists {
			setReported(fold.body, "usage", value)
		}
		values, isArray := root["choices"].([]any)
		if root["choices"] != nil && !isArray {
			fold.residue.Keep(event.Index, []string{"choices"}, root["choices"])
			continue
		}
		candidate := ""
		for position, value := range values {
			path := []string{"choices", streamevidence.Position(position)}
			object := protocolutil.Map(value)
			if object == nil {
				fold.residue.Keep(event.Index, path, value)
				continue
			}
			if reason := protocolutil.String(object["finish_reason"]); reason != "" && candidate == "" {
				candidate = reason
			}
			target := choice(choiceIndex(object, position))
			fold.residue.KeepUnknownKeys(event.Index, path, object, ConsumedChatChoiceFields...)
			if value, exists := object["finish_reason"]; exists {
				setReported(target.value, "finish_reason", value)
			}
			if value, exists := object["text"]; exists && !appendString(target.value, "text", value) {
				fold.residue.Keep(event.Index, append(path, "text"), value)
			}
			if value, exists := object["logprobs"]; exists {
				foldLogprobs(fold.residue, event.Index, append(path, "logprobs"), target.value, value)
			}
			if value, exists := object["message"]; exists && protocolutil.Map(value) == nil {
				fold.residue.Keep(event.Index, append(path, "message"), value)
			}
			if value, exists := object["delta"]; exists {
				delta := protocolutil.Map(value)
				if delta == nil || target.snapshot != nil {
					fold.residue.Keep(event.Index, append(path, "delta"), value)
					continue
				}
				foldChatDelta(fold.residue, event.Index, append(path, "delta"), target, delta)
			}
		}
		if candidate != "" {
			fold.stopReason = candidate
		}
	}

	indexes := make([]int, 0, len(choices))
	for index := range choices {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	built := make([]any, 0, len(indexes))
	for _, index := range indexes {
		target := choices[index]
		if target.snapshot != nil {
			target.value["message"] = streamevidence.Clone(target.snapshot)
		} else {
			if len(target.toolOrder) > 0 {
				tools := make([]any, 0, len(target.toolOrder))
				for _, toolIndex := range target.toolOrder {
					tools = append(tools, target.tools[toolIndex])
				}
				target.message["tool_calls"] = tools
			}
			if len(target.message) > 0 {
				target.value["message"] = target.message
			}
		}
		built = append(built, target.value)
	}
	fold.body["choices"] = built

	// Values a later chunk replaced are kept with the chunk that sent them.
	for _, event := range decoded {
		root := event.Object
		if root == nil {
			continue
		}
		for _, key := range append(append([]string(nil), chatSnapshotFields...), "usage") {
			if value, exists := root[key]; exists {
				held, present := fold.body[key]
				fold.residue.KeepLeftover(event.Index, []string{key}, value, held, present)
			}
		}
		for position, value := range protocolutil.Slice(root["choices"]) {
			object := protocolutil.Map(value)
			if object == nil {
				continue
			}
			path := []string{"choices", streamevidence.Position(position)}
			target := choices[choiceIndex(object, position)]
			if value, exists := object["finish_reason"]; exists {
				held, present := target.value["finish_reason"]
				fold.residue.KeepLeftover(event.Index, append(path, "finish_reason"), value, held, present)
			}
			if message := protocolutil.Map(object["message"]); message != nil {
				fold.residue.KeepLeftover(event.Index, append(path, "message"), message, target.value["message"], true)
			}
			delta := protocolutil.Map(object["delta"])
			if delta == nil || target.snapshot != nil {
				continue
			}
			for _, key := range []string{"role", "name"} {
				if value, exists := delta[key]; exists {
					held, present := target.message[key]
					fold.residue.KeepLeftover(event.Index, append(path, "delta", key), value, held, present)
				}
			}
			for toolPosition, toolValue := range protocolutil.Slice(delta["tool_calls"]) {
				tool := protocolutil.Map(toolValue)
				if tool == nil {
					continue
				}
				held := target.tools[toolIndex(tool, toolPosition)]
				for _, key := range []string{"id", "type"} {
					if value, exists := tool[key]; exists {
						heldValue, present := held[key]
						fold.residue.KeepLeftover(event.Index, append(path, "delta", "tool_calls", streamevidence.Position(toolPosition), key), value, heldValue, present)
					}
				}
			}
		}
	}
	return fold
}

func toolIndex(tool map[string]any, position int) int {
	if index, ok := streamevidence.Int(tool["index"]); ok && tool["index"] != nil {
		return index
	}
	return position
}

func foldChatDelta(residue *streamevidence.Residue, event int, path []string, target *chatChoice, delta map[string]any) {
	residue.KeepUnknownKeys(event, path, delta, ConsumedChatDeltaFields...)
	for _, key := range []string{"role", "name"} {
		if value, exists := delta[key]; exists {
			setReported(target.message, key, value)
		}
	}
	for _, key := range chatTextFields {
		if value, exists := delta[key]; exists && !appendString(target.message, key, value) {
			residue.Keep(event, append(path, key), value)
		}
	}
	if value, exists := delta["tool_calls"]; exists {
		tools, ok := value.([]any)
		if !ok && value != nil {
			residue.Keep(event, append(path, "tool_calls"), value)
		}
		for position, toolValue := range tools {
			toolPath := append(append([]string(nil), path...), "tool_calls", streamevidence.Position(position))
			tool := protocolutil.Map(toolValue)
			if tool == nil {
				residue.Keep(event, toolPath, toolValue)
				continue
			}
			index := toolIndex(tool, position)
			aggregate := target.tools[index]
			if aggregate == nil {
				aggregate = map[string]any{"index": index}
				target.tools[index] = aggregate
				target.toolOrder = append(target.toolOrder, index)
			}
			residue.KeepUnknownKeys(event, toolPath, tool, ConsumedChatToolCallFields...)
			for _, key := range []string{"id", "type"} {
				if value, exists := tool[key]; exists {
					setReported(aggregate, key, value)
				}
			}
			if value, exists := tool["function"]; exists {
				foldFunction(residue, event, append(toolPath, "function"), aggregate, value)
			}
		}
	}
	if value, exists := delta["function_call"]; exists {
		foldFunction(residue, event, append(path, "function_call"), target.message, value)
	}
}

// foldFunction concatenates the name and arguments pieces of a function
// object into holder[key], where key is the last element of path.
func foldFunction(residue *streamevidence.Residue, event int, path []string, holder map[string]any, value any) {
	key := path[len(path)-1]
	function := protocolutil.Map(value)
	if function == nil {
		residue.Keep(event, path, value)
		return
	}
	aggregate := protocolutil.Map(holder[key])
	if aggregate == nil {
		aggregate = map[string]any{}
		holder[key] = aggregate
	}
	residue.KeepUnknownKeys(event, path, function, ConsumedChatFunctionFields...)
	for _, field := range ConsumedChatFunctionFields {
		if piece, exists := function[field]; exists && !appendString(aggregate, field, piece) {
			residue.Keep(event, append(append([]string(nil), path...), field), piece)
		}
	}
}

func foldLogprobs(residue *streamevidence.Residue, event int, path []string, holder map[string]any, value any) {
	if value == nil {
		setReported(holder, "logprobs", nil)
		return
	}
	logprobs := protocolutil.Map(value)
	if logprobs == nil {
		residue.Keep(event, path, value)
		return
	}
	aggregate := protocolutil.Map(holder["logprobs"])
	if aggregate == nil {
		aggregate = map[string]any{}
		holder["logprobs"] = aggregate
	}
	for key, piece := range logprobs {
		if piece == nil {
			setReported(aggregate, key, nil)
			continue
		}
		entries, ok := piece.([]any)
		current, currentOK := aggregate[key].([]any)
		if !ok || (aggregate[key] != nil && !currentOK) {
			residue.Keep(event, append(append([]string(nil), path...), key), piece)
			continue
		}
		aggregate[key] = append(current, streamevidence.Clone(entries).([]any)...)
	}
}

// appendString concatenates a string piece onto holder[key]. null sets the
// key when it is absent. It reports false for a piece it cannot fold.
func appendString(holder map[string]any, key string, value any) bool {
	if value == nil {
		setReported(holder, key, nil)
		return true
	}
	text, ok := value.(string)
	if !ok {
		return false
	}
	current, currentOK := holder[key].(string)
	if holder[key] != nil && !currentOK {
		return false
	}
	holder[key] = current + text
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

// ConsumedResponsesEvents lists the Responses SSE event types the stream fold
// consumes and the top-level fields it reads from each. Any other event type
// is kept whole in the residue, and any other field of a listed event too.
var ConsumedResponsesEvents = map[string][]string{
	"response.created":                       {"type", "sequence_number", "response"},
	"response.queued":                        {"type", "sequence_number", "response"},
	"response.in_progress":                   {"type", "sequence_number", "response"},
	"response.completed":                     {"type", "sequence_number", "response"},
	"response.failed":                        {"type", "sequence_number", "response"},
	"response.incomplete":                    {"type", "sequence_number", "response"},
	"response.output_item.added":             {"type", "sequence_number", "output_index", "item"},
	"response.output_item.done":              {"type", "sequence_number", "output_index", "item"},
	"response.content_part.added":            {"type", "sequence_number", "item_id", "output_index", "content_index", "part"},
	"response.content_part.done":             {"type", "sequence_number", "item_id", "output_index", "content_index", "part"},
	"response.output_text.delta":             {"type", "sequence_number", "item_id", "output_index", "content_index", "delta", "logprobs"},
	"response.output_text.done":              {"type", "sequence_number", "item_id", "output_index", "content_index", "text", "logprobs"},
	"response.refusal.delta":                 {"type", "sequence_number", "item_id", "output_index", "content_index", "delta"},
	"response.refusal.done":                  {"type", "sequence_number", "item_id", "output_index", "content_index", "refusal"},
	"response.function_call_arguments.delta": {"type", "sequence_number", "item_id", "output_index", "delta"},
	"response.function_call_arguments.done":  {"type", "sequence_number", "item_id", "output_index", "arguments"},
	"response.reasoning_summary_part.added":  {"type", "sequence_number", "item_id", "output_index", "summary_index", "part"},
	"response.reasoning_summary_part.done":   {"type", "sequence_number", "item_id", "output_index", "summary_index", "part"},
	"response.reasoning_summary_text.delta":  {"type", "sequence_number", "item_id", "output_index", "summary_index", "delta"},
	"response.reasoning_summary_text.done":   {"type", "sequence_number", "item_id", "output_index", "summary_index", "text"},
	"response.reasoning_text.delta":          {"type", "sequence_number", "item_id", "output_index", "content_index", "delta"},
	"response.reasoning_text.done":           {"type", "sequence_number", "item_id", "output_index", "content_index", "text"},
}

// responsesPiece is one event's contribution to a place in the body.
type responsesPiece struct {
	event int
	value any
}

func values(pieces []responsesPiece) []any {
	result := make([]any, len(pieces))
	for index, piece := range pieces {
		result[index] = piece.value
	}
	return result
}

// responsesTarget names where a Responses event lands in the body: output
// item item, its content or summary part part, and the part's (or for
// function arguments, the item's) field.
type responsesTarget struct {
	item      int
	container string
	part      int
	field     string
	// partType is the part type a delta or done event implies, used when no
	// part event created the part.
	partType string
}

// responsesEvent classifies one consumed event type.
type responsesEvent struct {
	kind      string // lifecycle, item, part, delta, done
	container string // content or summary, for part, delta and done
	field     string // the field a delta or done event fills
	value     string // the event key holding the piece or final value
	partType  string // the part type a delta creates when no part event came
}

var responsesEventKinds = map[string]responsesEvent{
	"response.output_item.added":             {kind: "item"},
	"response.output_item.done":              {kind: "item"},
	"response.content_part.added":            {kind: "part", container: "content"},
	"response.content_part.done":             {kind: "part", container: "content"},
	"response.output_text.delta":             {kind: "delta", container: "content", field: "text", value: "delta", partType: "output_text"},
	"response.output_text.done":              {kind: "done", container: "content", field: "text", value: "text", partType: "output_text"},
	"response.refusal.delta":                 {kind: "delta", container: "content", field: "refusal", value: "delta", partType: "refusal"},
	"response.refusal.done":                  {kind: "done", container: "content", field: "refusal", value: "refusal", partType: "refusal"},
	"response.function_call_arguments.delta": {kind: "delta", field: "arguments", value: "delta"},
	"response.function_call_arguments.done":  {kind: "done", field: "arguments", value: "arguments"},
	"response.reasoning_summary_part.added":  {kind: "part", container: "summary"},
	"response.reasoning_summary_part.done":   {kind: "part", container: "summary"},
	"response.reasoning_summary_text.delta":  {kind: "delta", container: "summary", field: "text", value: "delta", partType: "summary_text"},
	"response.reasoning_summary_text.done":   {kind: "done", container: "summary", field: "text", value: "text", partType: "summary_text"},
	"response.reasoning_text.delta":          {kind: "delta", container: "content", field: "text", value: "delta", partType: "reasoning_text"},
	"response.reasoning_text.done":           {kind: "done", container: "content", field: "text", value: "text", partType: "reasoning_text"},
}

func responsesKind(eventType string) responsesEvent {
	if kind, ok := responsesEventKinds[eventType]; ok {
		return kind
	}
	return responsesEvent{kind: "lifecycle"}
}

func responsesTargetOf(root map[string]any, kind responsesEvent) (responsesTarget, bool) {
	item, ok := streamevidence.Int(root["output_index"])
	if !ok || root["output_index"] == nil {
		return responsesTarget{}, false
	}
	target := responsesTarget{item: item, container: kind.container, field: kind.field, partType: kind.partType}
	if kind.container != "" {
		key := "content_index"
		if kind.container == "summary" {
			key = "summary_index"
		}
		part, ok := streamevidence.Int(root[key])
		if !ok || root[key] == nil {
			return responsesTarget{}, false
		}
		target.part = part
	}
	return target, true
}

// foldResponsesStream folds Responses events into the response body: the
// lifecycle snapshots merge in order, so the terminal one wins, and when the
// terminal snapshot carries no output, the output is built from the item,
// part, delta and done events. Every event is then compared with the body.
func foldResponsesStream(events []base.SSEEvent) streamFold {
	decoded, markerErr := streamevidence.DecodeEvents(events)
	fold := streamFold{body: map[string]any{}, residue: streamevidence.NewResidue(), problem: markerErr}
	items := map[int][]responsesPiece{}
	parts := map[responsesTarget][]responsesPiece{}
	deltas := map[responsesTarget][]responsesPiece{}
	dones := map[responsesTarget][]responsesPiece{}
	consumed := make([]bool, len(decoded))

	for _, event := range decoded {
		root := event.Object
		if root == nil {
			fold.residue.KeepEvent(event)
			continue
		}
		eventType := protocolutil.String(root["type"])
		known, ok := ConsumedResponsesEvents[eventType]
		if !ok {
			fold.residue.KeepEvent(event)
			continue
		}
		kind := responsesKind(eventType)
		if kind.kind == "lifecycle" {
			response := protocolutil.Map(root["response"])
			if response == nil {
				fold.residue.KeepEvent(event)
				continue
			}
			streamevidence.MergeSet(fold.body, response)
			if reason := responsesStopReason(response); reason != "" {
				fold.stopReason = reason
			}
		} else {
			target, ok := responsesTargetOf(root, kind)
			if !ok {
				fold.residue.KeepEvent(event)
				continue
			}
			switch kind.kind {
			case "item":
				item := protocolutil.Map(root["item"])
				if item == nil {
					fold.residue.KeepEvent(event)
					continue
				}
				items[target.item] = append(items[target.item], responsesPiece{event.Index, item})
			case "part":
				part := protocolutil.Map(root["part"])
				if part == nil {
					fold.residue.KeepEvent(event)
					continue
				}
				target.field, target.partType = "", ""
				parts[target] = append(parts[target], responsesPiece{event.Index, part})
			case "delta":
				text, isText := root[kind.value].(string)
				if !isText {
					fold.residue.KeepEvent(event)
					continue
				}
				deltas[target] = append(deltas[target], responsesPiece{event.Index, text})
			case "done":
				text, isText := root[kind.value].(string)
				if !isText {
					fold.residue.KeepEvent(event)
					continue
				}
				dones[target] = append(dones[target], responsesPiece{event.Index, text})
			}
		}
		consumed[event.Index] = true
		fold.residue.KeepUnknownKeys(event.Index, nil, root, known...)
		if value, exists := root["sequence_number"]; exists {
			if sequence, ok := streamevidence.Int(value); !ok || value == nil || sequence != event.Index {
				fold.residue.Keep(event.Index, []string{"sequence_number"}, value)
			}
		}
	}

	// Build the output from the item events when no snapshot carries one.
	if output, _ := fold.body["output"].([]any); len(output) == 0 && (len(items) > 0 || len(parts) > 0 || len(deltas) > 0 || len(dones) > 0) {
		built, err := buildResponsesOutput(items, parts, deltas, dones)
		if err != nil && fold.problem == nil {
			fold.problem = err
		}
		fold.body["output"] = built
	}

	// Compare every consumed event with the body.
	accumulated := map[responsesTarget]string{}
	for target, values := range deltas {
		var builder strings.Builder
		for _, value := range values {
			builder.WriteString(value.value.(string))
		}
		accumulated[target] = builder.String()
	}
	logprobs := map[responsesTarget][]any{}
	for _, event := range decoded {
		if !consumed[event.Index] {
			continue
		}
		root := event.Object
		kind := responsesKind(protocolutil.String(root["type"]))
		if kind.kind == "lifecycle" {
			fold.residue.KeepLeftover(event.Index, []string{"response"}, root["response"], fold.body, true)
			continue
		}
		target, _ := responsesTargetOf(root, kind)
		item := protocolutil.Map(responsesAt(fold.body["output"], target.item))
		if item == nil {
			fold.residue.KeepEvent(event)
			continue
		}
		if value, exists := root["item_id"]; exists && !streamevidence.Equal(value, item["id"]) {
			fold.residue.Keep(event.Index, []string{"item_id"}, value)
		}
		holder := item
		if target.container != "" {
			holder = protocolutil.Map(responsesAt(item[target.container], target.part))
			if holder == nil {
				fold.residue.KeepEvent(event)
				continue
			}
		}
		switch kind.kind {
		case "item":
			fold.residue.KeepLeftover(event.Index, []string{"item"}, root["item"], item, true)
		case "part":
			fold.residue.KeepLeftover(event.Index, []string{"part"}, root["part"], holder, true)
		case "delta":
			if held, _ := holder[target.field].(string); held != accumulated[target] {
				fold.residue.Keep(event.Index, []string{kind.value}, root[kind.value])
			}
			if value, exists := root["logprobs"]; exists {
				entries, ok := value.([]any)
				if !ok {
					fold.residue.Keep(event.Index, []string{"logprobs"}, value)
				} else {
					logprobs[target] = append(logprobs[target], entries...)
				}
			}
		case "done":
			held, present := holder[target.field]
			fold.residue.KeepLeftover(event.Index, []string{kind.value}, root[kind.value], held, present)
			if value, exists := root["logprobs"]; exists {
				held, present := holder["logprobs"]
				fold.residue.KeepLeftover(event.Index, []string{"logprobs"}, value, held, present)
			}
		}
	}
	// Delta logprobs are consumed when together they are the part's.
	for target, entries := range logprobs {
		item := protocolutil.Map(responsesAt(fold.body["output"], target.item))
		holder := protocolutil.Map(responsesAt(item[target.container], target.part))
		held, present := holder["logprobs"]
		if present && (streamevidence.Equal(held, entries) || (len(entries) == 0 && isEmptyArray(held))) {
			continue
		}
		for _, value := range deltas[target] {
			if delta := decoded[value.event].Object; delta != nil {
				if _, exists := delta["logprobs"]; exists {
					fold.residue.Keep(value.event, []string{"logprobs"}, delta["logprobs"])
				}
			}
		}
	}
	return fold
}

func isEmptyArray(value any) bool {
	values, ok := value.([]any)
	return ok && len(values) == 0
}

func responsesAt(value any, index int) any {
	values := protocolutil.Slice(value)
	if index < 0 || index >= len(values) {
		return nil
	}
	return values[index]
}

// buildResponsesOutput builds output items from item, part, delta and done
// events: item and part snapshots merge in order, a done value wins over the
// concatenated deltas, and a part that only deltas name is created with the
// part type the delta event implies. Item and part positions must be dense.
func buildResponsesOutput(items map[int][]responsesPiece, parts, deltas, dones map[responsesTarget][]responsesPiece) ([]any, error) {
	positions := map[int]bool{}
	for index := range items {
		positions[index] = true
	}
	for _, source := range []map[responsesTarget][]responsesPiece{parts, deltas, dones} {
		for target := range source {
			positions[target.item] = true
		}
	}
	output := make([]any, len(positions))
	built := make([]map[string]any, len(positions))
	for index := range positions {
		if index >= len(positions) {
			return nil, fmt.Errorf("openai normalizer: output item positions are not dense")
		}
		item := map[string]any{}
		for _, value := range values(items[index]) {
			streamevidence.MergeSet(item, value.(map[string]any))
		}
		built[index] = item
		output[index] = item
	}
	containerParts := map[responsesTarget]map[string]any{}
	partAt := func(target responsesTarget, partType string) map[string]any {
		key := responsesTarget{item: target.item, container: target.container, part: target.part}
		if containerParts[key] == nil {
			part := map[string]any{}
			for _, value := range values(parts[key]) {
				streamevidence.MergeSet(part, value.(map[string]any))
			}
			if len(part) == 0 && partType != "" {
				part["type"] = partType
			}
			containerParts[key] = part
		}
		return containerParts[key]
	}
	for target := range parts {
		partAt(target, "")
	}
	for _, source := range []map[responsesTarget][]responsesPiece{deltas, dones} {
		for target := range source {
			var holder map[string]any
			if target.container == "" {
				holder = built[target.item]
			} else {
				holder = partAt(target, target.partType)
			}
			if current, _ := holder[target.field].(string); current != "" {
				continue
			}
			if finals := values(dones[target]); len(finals) > 0 {
				holder[target.field] = finals[len(finals)-1]
				continue
			}
			var builder strings.Builder
			for _, piece := range values(deltas[target]) {
				builder.WriteString(piece.(string))
			}
			holder[target.field] = builder.String()
		}
	}
	// Attach parts to their items when the item snapshots carry none.
	containers := map[[2]any][]int{}
	for key := range containerParts {
		containers[[2]any{key.item, key.container}] = append(containers[[2]any{key.item, key.container}], key.part)
	}
	for key, partIndexes := range containers {
		item := built[key[0].(int)]
		container := key[1].(string)
		if existing, _ := item[container].([]any); len(existing) > 0 {
			continue
		}
		sort.Ints(partIndexes)
		list := make([]any, len(partIndexes))
		for position, partIndex := range partIndexes {
			if partIndex != position {
				return nil, fmt.Errorf("openai normalizer: %s part positions are not dense", container)
			}
			list[position] = containerParts[responsesTarget{item: key[0].(int), container: container, part: partIndex}]
		}
		item[container] = list
	}
	return output, nil
}

// responsesStopReason maps a response's terminal status to the stop reason
// the insights backfill reads, so that a released stream yields the stop
// reason the insights analysis reads from the raw events: completed is
// end_turn, incomplete is its incomplete_details.reason (other when none),
// failed and cancelled are other. A response still in progress has none.
func responsesStopReason(response map[string]any) string {
	switch strings.ToLower(protocolutil.String(response["status"])) {
	case "completed":
		return "end_turn"
	case "incomplete":
		if reason := protocolutil.String(protocolutil.Map(response["incomplete_details"])["reason"]); reason != "" {
			return reason
		}
		return "other"
	case "failed", "cancelled", "canceled":
		return "other"
	}
	return ""
}
