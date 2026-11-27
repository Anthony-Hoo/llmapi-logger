package auditmodel

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"
)

// TestLayoutNamesArePinned lists every stored layout name. The names are part
// of the stored format: rows written with them must keep rebuilding, so a
// rename or removal fails here.
func TestLayoutNamesArePinned(t *testing.T) {
	t.Parallel()
	want := []string{
		"anthropic.messages.request.system_array",
		"anthropic.messages.request.system_none",
		"anthropic.messages.request.system_single",
		"anthropic.stream.response",
		"marker_envelope",
		"none",
		"openai.chat.request.messages",
		"openai.completions.request.prompt_array",
		"openai.completions.request.prompt_single",
		"openai.responses.request.input_array",
		"openai.responses.request.input_none",
		"openai.responses.request.input_single",
		"openai.stream.response",
	}
	if got := LayoutNames(); !slices.Equal(got, want) {
		t.Fatalf("layout names = %q, want %q", got, want)
	}
	var streams []string
	for _, name := range want {
		if StreamLayout(name) {
			streams = append(streams, name)
		}
	}
	if wantStreams := []string{"anthropic.stream.response", "openai.stream.response"}; !slices.Equal(streams, wantStreams) {
		t.Fatalf("stream layouts = %q, want %q", streams, wantStreams)
	}
	if KnownLayout("openai.unknown") || StreamLayout("openai.unknown") {
		t.Fatal("an unknown layout is reported as known")
	}
}

// assembleLegacy is the switch Assemble replaced, kept verbatim so the table
// can be proved equivalent on every layout.
func assembleLegacy(layout string, envelope any, items []Item) (any, error) {
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

	root, _ := cloned.(map[string]any)
	switch layout {
	case LayoutNone:
		return cloned, nil
	case LayoutOpenAIChatRequest:
		if root == nil {
			return nil, ErrReconstruction
		}
		root[SlotMessages] = valuesForSlot(items, values, SlotMessages)
		return root, nil
	case LayoutOpenAIResponsesRequestArray, LayoutOpenAIResponsesRequestSingle, LayoutOpenAIResponsesRequestNone:
		if root == nil {
			return nil, ErrReconstruction
		}
		instructions := valuesForSlot(items, values, SlotInstructions)
		if len(instructions) > 1 {
			return nil, ErrReconstruction
		}
		if len(instructions) == 1 {
			root[SlotInstructions] = instructions[0]
		}
		inputs := valuesForSlot(items, values, SlotInput)
		switch layout {
		case LayoutOpenAIResponsesRequestArray:
			root[SlotInput] = inputs
		case LayoutOpenAIResponsesRequestSingle:
			if len(inputs) != 1 {
				return nil, ErrReconstruction
			}
			root[SlotInput] = inputs[0]
		case LayoutOpenAIResponsesRequestNone:
			if len(inputs) != 0 {
				return nil, ErrReconstruction
			}
		}
		return root, nil
	case LayoutOpenAICompletionsPromptArray, LayoutOpenAICompletionsPromptSingle:
		if root == nil {
			return nil, ErrReconstruction
		}
		prompts := valuesForSlot(items, values, SlotPrompt)
		if layout == LayoutOpenAICompletionsPromptArray {
			root[SlotPrompt] = prompts
			return root, nil
		}
		if len(prompts) != 1 {
			return nil, ErrReconstruction
		}
		root[SlotPrompt] = prompts[0]
		return root, nil
	case LayoutAnthropicMessagesRequestSystemNone, LayoutAnthropicMessagesRequestSystemSingle, LayoutAnthropicMessagesRequestSystemArray:
		if root == nil {
			return nil, ErrReconstruction
		}
		root[SlotMessages] = valuesForSlot(items, values, SlotMessages)
		system := valuesForSlot(items, values, SlotSystem)
		switch layout {
		case LayoutAnthropicMessagesRequestSystemArray:
			root[SlotSystem] = system
		case LayoutAnthropicMessagesRequestSystemSingle:
			if len(system) != 1 {
				return nil, ErrReconstruction
			}
			root[SlotSystem] = system[0]
		case LayoutAnthropicMessagesRequestSystemNone:
			if len(system) != 0 {
				return nil, ErrReconstruction
			}
		}
		return root, nil
	case LayoutMarkerEnvelope:
		return replaceItemMarkers(cloned, values)
	case LayoutOpenAIStreamResponse, LayoutAnthropicStreamResponse:
		if root == nil {
			return nil, ErrReconstruction
		}
		root[SlotAggregate] = valuesForSlot(items, values, SlotAggregate)
		return root, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedLayout, layout)
	}
}

// TestAssembleMatchesLegacySwitch runs the table and the old switch over every
// layout (plus an unknown one) with each envelope shape and 0, 1 or 2 items in
// every slot, and requires the same value and the same error.
func TestAssembleMatchesLegacySwitch(t *testing.T) {
	t.Parallel()
	allSlots := []string{SlotInstructions, SlotMessages, SlotInput, SlotPrompt, SlotOutput, SlotChoice, SlotAggregate, SlotSystem, SlotContent}
	envelopes := map[string]func() any{
		"object": func() any { return map[string]any{"model": "model-example", "kept": []any{"a"}} },
		"markers": func() any {
			return map[string]any{"output": []any{ItemMarker(0), ItemMarker(1)}, "first": ItemMarker(0)}
		},
		"nil":    func() any { return nil },
		"string": func() any { return "not an object" },
		"array":  func() any { return []any{ItemMarker(0)} },
	}
	layoutNames := append(LayoutNames(), "openai.unknown", "")
	cases := 0
	for _, layout := range layoutNames {
		for envelopeName, envelope := range envelopes {
			// Two slots with 0, 1 or 2 items each, interleaved, covers every
			// pair of slots a layout reads and items in slots it ignores.
			for _, first := range allSlots {
				for _, second := range allSlots {
					for firstCount := range 3 {
						for secondCount := range 3 {
							var items []Item
							for index := range max(firstCount, secondCount) {
								if index < firstCount {
									items = append(items, Item{Slot: first, Kind: "kind", Value: map[string]any{"slot": first, "index": index}})
								}
								if index < secondCount {
									items = append(items, Item{Slot: second, Kind: "kind", Value: []any{second, index}})
								}
							}
							cases++
							name := fmt.Sprintf("%s/%s/%s=%d/%s=%d", layout, envelopeName, first, firstCount, second, secondCount)
							got, gotErr := Assemble(layout, envelope(), items)
							want, wantErr := assembleLegacy(layout, envelope(), items)
							if (gotErr == nil) != (wantErr == nil) || (gotErr != nil && gotErr.Error() != wantErr.Error()) {
								t.Fatalf("%s: error = %v, want %v", name, gotErr, wantErr)
							}
							for _, sentinel := range []error{ErrReconstruction, ErrUnsupportedLayout} {
								if errors.Is(gotErr, sentinel) != errors.Is(wantErr, sentinel) {
									t.Fatalf("%s: errors.Is(%v) differs: %v vs %v", name, sentinel, gotErr, wantErr)
								}
							}
							if !reflect.DeepEqual(got, want) {
								t.Fatalf("%s: value = %#v, want %#v", name, got, want)
							}
						}
					}
				}
			}
		}
	}
	if cases == 0 {
		t.Fatal("no cases ran")
	}
}
