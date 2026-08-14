package auditmodel

import (
	"fmt"
)

func ItemMarker(index int) map[string]any {
	return map[string]any{ItemMarkerKey: index}
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
	case LayoutMarkerEnvelope:
		return replaceItemMarkers(cloned, values)
	case LayoutOpenAIStreamResponse:
		if root == nil {
			return nil, ErrReconstruction
		}
		root[SlotAggregate] = valuesForSlot(items, values, SlotAggregate)
		return root, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedLayout, layout)
	}
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
