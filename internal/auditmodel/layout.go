package auditmodel

import (
	"fmt"
	"sort"
)

func ItemMarker(index int) map[string]any {
	return map[string]any{ItemMarkerKey: index}
}

// layoutKind selects how a layout puts items back into its envelope.
type layoutKind int

const (
	// layoutEnvelope returns the envelope unchanged; items are not used.
	layoutEnvelope layoutKind = iota
	// layoutMarkers replaces every item marker in the envelope with its item.
	layoutMarkers
	// layoutSlots sets one envelope key per slot rule; the envelope must be
	// a JSON object.
	layoutSlots
)

// slotArity is how many items of one slot a layout accepts and how they are
// written back under the slot's key.
type slotArity int

const (
	// slotArray writes every item of the slot as an array, possibly empty.
	slotArray slotArity = iota
	// slotOne requires exactly one item and writes it as the value.
	slotOne
	// slotOptional accepts zero or one item and writes the key only for one.
	slotOptional
	// slotAbsent requires no item and leaves the key unset.
	slotAbsent
)

type slotRule struct {
	slot  string
	arity slotArity
}

// layoutSpec describes one stored layout. Items whose slot has no rule are
// ignored, as they always were.
type layoutSpec struct {
	kind  layoutKind
	slots []slotRule
	// stream marks a stream response: the envelope describes the SSE events
	// and holds their summary, and SlotAggregate holds the aggregate (display
	// messages in the oldest layout, the folded provider body in the others).
	stream bool
}

func slots(rules ...slotRule) layoutSpec { return layoutSpec{kind: layoutSlots, slots: rules} }

// layouts holds every layout name that has ever been stored. The names are
// part of the stored format: a name is never renamed or removed, and a new
// protocol or a changed shape adds a new name. Every reader of a turn graph
// (the query service, the offline import check, an archive reader) imports
// this package, so a stored layout can always be assembled without any
// registration step.
var layouts = map[string]layoutSpec{
	LayoutNone:           {kind: layoutEnvelope},
	LayoutMarkerEnvelope: {kind: layoutMarkers},

	LayoutOpenAIChatRequest: slots(slotRule{SlotMessages, slotArray}),
	LayoutOpenAIResponsesRequestArray: slots(
		slotRule{SlotInstructions, slotOptional}, slotRule{SlotInput, slotArray}),
	LayoutOpenAIResponsesRequestSingle: slots(
		slotRule{SlotInstructions, slotOptional}, slotRule{SlotInput, slotOne}),
	LayoutOpenAIResponsesRequestNone: slots(
		slotRule{SlotInstructions, slotOptional}, slotRule{SlotInput, slotAbsent}),
	LayoutOpenAICompletionsPromptArray:  slots(slotRule{SlotPrompt, slotArray}),
	LayoutOpenAICompletionsPromptSingle: slots(slotRule{SlotPrompt, slotOne}),
	LayoutOpenAIStreamResponse:          {kind: layoutSlots, slots: []slotRule{{SlotAggregate, slotArray}}, stream: true},

	LayoutAnthropicMessagesRequestSystemNone: slots(
		slotRule{SlotMessages, slotArray}, slotRule{SlotSystem, slotAbsent}),
	LayoutAnthropicMessagesRequestSystemSingle: slots(
		slotRule{SlotMessages, slotArray}, slotRule{SlotSystem, slotOne}),
	LayoutAnthropicMessagesRequestSystemArray: slots(
		slotRule{SlotMessages, slotArray}, slotRule{SlotSystem, slotArray}),
	// The stream layouts below hold the event description, summary and
	// residue in the envelope, and under its aggregate key the folded
	// provider body split the way the non-stream response is: the body's
	// items are replaced by item markers (plus, for Responses, the echoed
	// instructions and tools), exactly like marker_envelope.
	LayoutAnthropicStreamResponse: {kind: layoutMarkers, stream: true},
	LayoutOpenAIStreamResponseV2:  {kind: layoutMarkers, stream: true},
}

// SlotTools holds the tool definitions a Responses stream's terminal
// response echoes, stored as an item so they deduplicate across turns.
const SlotTools = "tools"

// LayoutOpenAIStreamResponseV2 replaces LayoutOpenAIStreamResponse, whose
// aggregate items are display messages and whose envelope describes every
// event; rows stored with the old name keep assembling with its own row.
const LayoutOpenAIStreamResponseV2 = "openai.stream.response.v2"

// KnownLayout reports whether Assemble can rebuild layout.
func KnownLayout(layout string) bool {
	_, ok := layouts[layout]
	return ok
}

// StreamLayout reports whether layout is a stream response: its value is the
// SSE event description and summary, with the aggregated messages under
// SlotAggregate, not a provider JSON body.
func StreamLayout(layout string) bool {
	return layouts[layout].stream
}

// LayoutNames lists every known layout, sorted.
func LayoutNames() []string {
	names := make([]string, 0, len(layouts))
	for name := range layouts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Assemble rebuilds the normalized provider value without restoring binary
// bytes. Binary markers remain in place for independent verification/query use.
func Assemble(layout string, envelope any, items []Item) (any, error) {
	cloned, err := CloneJSON(envelope)
	if err != nil {
		return nil, err
	}
	values := make([]any, len(items))
	for index, item := range items {
		values[index], err = CloneJSON(item.Value)
		if err != nil {
			return nil, err
		}
	}

	spec, known := layouts[layout]
	if !known {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedLayout, layout)
	}
	switch spec.kind {
	case layoutEnvelope:
		return cloned, nil
	case layoutMarkers:
		return replaceItemMarkers(cloned, values)
	}
	root, _ := cloned.(map[string]any)
	if root == nil {
		return nil, ErrReconstruction
	}
	for _, rule := range spec.slots {
		slotValues := valuesForSlot(items, values, rule.slot)
		switch rule.arity {
		case slotArray:
			root[rule.slot] = slotValues
		case slotOne:
			if len(slotValues) != 1 {
				return nil, ErrReconstruction
			}
			root[rule.slot] = slotValues[0]
		case slotOptional:
			if len(slotValues) > 1 {
				return nil, ErrReconstruction
			}
			if len(slotValues) == 1 {
				root[rule.slot] = slotValues[0]
			}
		case slotAbsent:
			if len(slotValues) != 0 {
				return nil, ErrReconstruction
			}
		}
	}
	return root, nil
}

func valuesForSlot(items []Item, values []any, slot string) []any {
	result := make([]any, 0)
	for index, item := range items {
		if item.Slot == slot {
			result = append(result, values[index])
		}
	}
	return result
}

func replaceItemMarkers(value any, items []any) (any, error) {
	switch typed := value.(type) {
	case map[string]any:
		if len(typed) == 1 {
			if rawIndex, exists := typed[ItemMarkerKey]; exists {
				index, ok := markerIndex(rawIndex)
				if !ok || index < 0 || index >= len(items) {
					return nil, ErrReconstruction
				}
				return CloneJSON(items[index])
			}
		}
		for key, child := range typed {
			replaced, err := replaceItemMarkers(child, items)
			if err != nil {
				return nil, err
			}
			typed[key] = replaced
		}
		return typed, nil
	case []any:
		for index, child := range typed {
			replaced, err := replaceItemMarkers(child, items)
			if err != nil {
				return nil, err
			}
			typed[index] = replaced
		}
		return typed, nil
	default:
		return typed, nil
	}
}

func markerIndex(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int64:
		return int(typed), int64(int(typed)) == typed
	case float64:
		converted := int(typed)
		return converted, float64(converted) == typed
	case interface{ Int64() (int64, error) }:
		parsed, err := typed.Int64()
		return int(parsed), err == nil && int64(int(parsed)) == parsed
	default:
		return 0, false
	}
}
