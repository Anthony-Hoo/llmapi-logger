package openai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/conversation"
	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/protocolutil"
)

func (implementation *Parser) NormalizeAudit(_ context.Context, input base.Input, result base.Result) (auditmodel.Turn, error) {
	if implementation == nil {
		return auditmodel.Turn{}, errors.New("openai normalizer: nil parser")
	}
	turn := auditmodel.Turn{
		AuditID:        input.AuditID,
		Protocol:       input.Protocol,
		ParserName:     implementation.name,
		ResponseID:     result.ResponseID,
		RequestLayout:  auditmodel.LayoutNone,
		ResponseLayout: auditmodel.LayoutNone,
	}
	if input.Request.Present {
		var root map[string]any
		if err := auditmodel.DecodeJSON(input.Request.Data, &root); err != nil || root == nil {
			return auditmodel.Turn{}, fmt.Errorf("openai normalizer: request JSON: %w", err)
		}
		if err := auditmodel.CheckReservedMarkers(root); err != nil {
			return auditmodel.Turn{}, err
		}
		request, err := implementation.normalizeRequest(root)
		if err != nil {
			return auditmodel.Turn{}, err
		}
		turn.RequestLayout = request.layout
		turn.RequestEnvelope = request.envelope
		turn.RequestItems = request.items
		turn.RequestOriginal = request.original
		turn.PreviousResponseID = protocolutil.String(root["previous_response_id"])
		turn.ConversationKey = conversationKey(root)
	}
	if input.Response.Present {
		if base.LooksLikeSSE(input.Response.ContentType, input.Response.Data) {
			response, err := implementation.normalizeStreamResponse(input.Response.Data, result)
			if err != nil {
				return auditmodel.Turn{}, err
			}
			turn.ResponseLayout = response.layout
			turn.ResponseEnvelope = response.envelope
			turn.ResponseItems = response.items
			turn.ResponseOriginal = response.original
		} else {
			var root map[string]any
			if err := auditmodel.DecodeJSON(input.Response.Data, &root); err != nil || root == nil {
				return auditmodel.Turn{}, fmt.Errorf("openai normalizer: response JSON: %w", err)
			}
			if err := auditmodel.CheckReservedMarkers(root); err != nil {
				return auditmodel.Turn{}, err
			}
			response, err := implementation.normalizeJSONResponse(root)
			if err != nil {
				return auditmodel.Turn{}, err
			}
			turn.ResponseLayout = response.layout
			turn.ResponseEnvelope = response.envelope
			turn.ResponseItems = response.items
			turn.ResponseOriginal = response.original
		}
	}
	if turn.RequestEnvelope == nil {
		turn.RequestEnvelope = nil
		turn.RequestOriginal = nil
	}
	if turn.ResponseEnvelope == nil {
		turn.ResponseEnvelope = nil
		turn.ResponseOriginal = nil
	}
	return turn, nil
}

type normalizedSide struct {
	layout   string
	envelope any
	items    []auditmodel.Item
	original any
}

func (implementation *Parser) normalizeRequest(root map[string]any) (normalizedSide, error) {
	original, err := cloneMap(root)
	if err != nil {
		return normalizedSide{}, err
	}
	envelope, err := cloneMap(root)
	if err != nil {
		return normalizedSide{}, err
	}
	items := make([]auditmodel.Item, 0)
	switch implementation.name {
	case ChatCompletions:
		values, exists := envelope["messages"]
		if !exists {
			return normalizedSide{}, errors.New("openai normalizer: chat request has no messages")
		}
		messages, ok := values.([]any)
		if !ok {
			return normalizedSide{}, errors.New("openai normalizer: chat messages is not an array")
		}
		for _, value := range messages {
			items = append(items, auditmodel.Item{
				Slot: auditmodel.SlotMessages, Kind: itemKind(protocolutil.Map(value), "message"), Value: value,
				Display: displayForChatMessage(protocolutil.Map(value), conversation.PhaseRequest, conversation.DirectionClientToUpstream),
			})
		}
		delete(envelope, "messages")
		return normalizedSide{layout: auditmodel.LayoutOpenAIChatRequest, envelope: envelope, items: items, original: original}, nil
	case Responses, ResponsesCompact:
		if instructions, exists := envelope["instructions"]; exists && instructions != nil {
			items = append(items, auditmodel.Item{
				Slot: auditmodel.SlotInstructions, Kind: "instructions", Value: instructions,
				Display: displayForInstructions(instructions),
			})
			delete(envelope, "instructions")
		}
		inputValue, exists := envelope["input"]
		layout := auditmodel.LayoutOpenAIResponsesRequestNone
		if exists {
			delete(envelope, "input")
			if values, ok := inputValue.([]any); ok {
				layout = auditmodel.LayoutOpenAIResponsesRequestArray
				for _, value := range values {
					items = append(items, responseInputItem(value))
				}
			} else {
				layout = auditmodel.LayoutOpenAIResponsesRequestSingle
				items = append(items, responseInputItem(inputValue))
			}
		}
		return normalizedSide{layout: layout, envelope: envelope, items: items, original: original}, nil
	case Completions:
		prompt, exists := envelope["prompt"]
		if !exists {
			return normalizedSide{}, errors.New("openai normalizer: completion request has no prompt")
		}
		delete(envelope, "prompt")
		layout := auditmodel.LayoutOpenAICompletionsPromptSingle
		if values, ok := prompt.([]any); ok {
			layout = auditmodel.LayoutOpenAICompletionsPromptArray
			for _, value := range values {
				items = append(items, auditmodel.Item{Slot: auditmodel.SlotPrompt, Kind: "prompt", Value: value, Display: displayForPrompt(value)})
			}
		} else {
			items = append(items, auditmodel.Item{Slot: auditmodel.SlotPrompt, Kind: "prompt", Value: prompt, Display: displayForPrompt(prompt)})
		}
		return normalizedSide{layout: layout, envelope: envelope, items: items, original: original}, nil
	default:
		return normalizedSide{}, errors.New("openai normalizer: unsupported parser")
	}
}

func (implementation *Parser) normalizeJSONResponse(root map[string]any) (normalizedSide, error) {
	original, err := cloneMap(root)
	if err != nil {
		return normalizedSide{}, err
	}
	envelope, err := cloneMap(root)
	if err != nil {
		return normalizedSide{}, err
	}
	items := make([]auditmodel.Item, 0)
	switch implementation.name {
	case ChatCompletions:
		choices := protocolutil.Slice(envelope["choices"])
		for _, choiceValue := range choices {
			choice := protocolutil.Map(choiceValue)
			if choice == nil {
				continue
			}
			message, exists := choice["message"]
			if !exists {
				continue
			}
			index := len(items)
			items = append(items, auditmodel.Item{
				Slot: auditmodel.SlotChoice, Kind: itemKind(protocolutil.Map(message), "message"), Value: message,
				Display: displayForChatMessage(protocolutil.Map(message), conversation.PhaseResponse, conversation.DirectionUpstreamToClient),
			})
			choice["message"] = auditmodel.ItemMarker(index)
		}
	case Completions:
		choices := protocolutil.Slice(envelope["choices"])
		for _, choiceValue := range choices {
			choice := protocolutil.Map(choiceValue)
			if choice == nil {
				continue
			}
			text, exists := choice["text"]
			if !exists {
				continue
			}
			index := len(items)
			items = append(items, auditmodel.Item{Slot: auditmodel.SlotChoice, Kind: "completion", Value: text, Display: displayForPrompt(text)})
			choice["text"] = auditmodel.ItemMarker(index)
		}
	case Responses, ResponsesCompact:
		output, exists := envelope["output"]
		if exists {
			values, ok := output.([]any)
			if !ok {
				return normalizedSide{}, errors.New("openai normalizer: response output is not an array")
			}
			markers := make([]any, 0, len(values))
			for _, value := range values {
				index := len(items)
				item := protocolutil.Map(value)
				items = append(items, auditmodel.Item{
					Slot: auditmodel.SlotOutput, Kind: itemKind(item, "output_item"), Value: value,
					Display: displayForResponsesItem(item, conversation.PhaseResponse, conversation.DirectionUpstreamToClient),
				})
				markers = append(markers, auditmodel.ItemMarker(index))
			}
			envelope["output"] = markers
		}
	default:
		return normalizedSide{}, errors.New("openai normalizer: unsupported response parser")
	}
	return normalizedSide{layout: auditmodel.LayoutMarkerEnvelope, envelope: envelope, items: items, original: original}, nil
}

func (implementation *Parser) normalizeStreamResponse(data []byte, result base.Result) (normalizedSide, error) {
	events, _ := base.DecodeSSEWithStatus(data)
	if len(events) == 0 {
		return normalizedSide{}, errors.New("openai normalizer: empty SSE")
	}
	descriptors := make([]any, 0, len(events))
	for _, event := range events {
		digest := sha256.Sum256(event.Data)
		descriptors = append(descriptors, map[string]any{
			"event":       event.Event,
			"data_length": len(event.Data),
			"data_sha256": hex.EncodeToString(digest[:]),
		})
	}
	items := make([]auditmodel.Item, 0)
	aggregateValues := make([]any, 0)
	if result.Conversation != nil {
		for _, message := range result.Conversation.Messages {
			if message.Phase != conversation.PhaseResponse {
				continue
			}
			display := auditmodel.DisplayFromConversation(message)
			value, err := displayJSONValue(display)
			if err != nil {
				return normalizedSide{}, err
			}
			items = append(items, auditmodel.Item{
				Slot: auditmodel.SlotAggregate, Kind: "stream_" + message.Role,
				Value: value, Display: []auditmodel.DisplayMessage{display},
			})
			aggregateValues = append(aggregateValues, value)
		}
	}
	envelope := map[string]any{
		"format": "sse",
		"events": descriptors,
		"summary": map[string]any{
			"response_id": result.ResponseID,
			"usage":       result.Usage,
			"error_type":  result.ErrorType,
			"error_code":  result.ErrorCode,
		},
	}
	original, err := cloneMap(envelope)
	if err != nil {
		return normalizedSide{}, err
	}
	original[auditmodel.SlotAggregate] = aggregateValues
	return normalizedSide{layout: auditmodel.LayoutOpenAIStreamResponse, envelope: envelope, items: items, original: original}, nil
}

func responseInputItem(value any) auditmodel.Item {
	if text, ok := value.(string); ok {
		return auditmodel.Item{
			Slot: auditmodel.SlotInput, Kind: "message", Value: text,
			Display: []auditmodel.DisplayMessage{{Role: conversation.RoleUser, Content: []auditmodel.DisplayPart{{Type: conversation.PartText, Text: text}}}},
		}
	}
	item := protocolutil.Map(value)
	return auditmodel.Item{
		Slot: auditmodel.SlotInput, Kind: itemKind(item, "input_item"), Value: value,
		Display: displayForResponsesItem(item, conversation.PhaseRequest, conversation.DirectionClientToUpstream),
	}
}

func displayForChatMessage(message map[string]any, phase, direction string) []auditmodel.DisplayMessage {
	temporary := base.Result{}
	appendChatMessage(message, phase, direction, &temporary)
	return displayFromResult(temporary)
}

func displayForResponsesItem(item map[string]any, phase, direction string) []auditmodel.DisplayMessage {
	temporary := base.Result{}
	appendResponsesItem(item, phase, direction, &temporary)
	return displayFromResult(temporary)
}

func displayForInstructions(value any) []auditmodel.DisplayMessage {
	text := conversation.ValueString(value)
	if text == "" {
		return nil
	}
	return []auditmodel.DisplayMessage{{Role: conversation.RoleDeveloper, Content: []auditmodel.DisplayPart{{Type: conversation.PartText, Text: text}}}}
}

func displayForPrompt(value any) []auditmodel.DisplayMessage {
	text := conversation.ValueString(value)
	if text == "" {
		return nil
	}
	return []auditmodel.DisplayMessage{{Role: conversation.RoleUser, Content: []auditmodel.DisplayPart{{Type: conversation.PartText, Text: text}}}}
}

func displayFromResult(result base.Result) []auditmodel.DisplayMessage {
	if result.Conversation == nil {
		return nil
	}
	display := make([]auditmodel.DisplayMessage, 0, len(result.Conversation.Messages))
	for _, message := range result.Conversation.Messages {
		display = append(display, auditmodel.DisplayFromConversation(message))
	}
	return display
}

func displayJSONValue(display auditmodel.DisplayMessage) (any, error) {
	encoded, err := auditmodel.CanonicalJSON(display)
	if err != nil {
		return nil, err
	}
	var value any
	if err := auditmodel.DecodeJSON(encoded, &value); err != nil {
		return nil, err
	}
	return value, nil
}

func itemKind(value map[string]any, fallback string) string {
	if typeName := protocolutil.String(value["type"]); typeName != "" {
		return typeName
	}
	if role := protocolutil.String(value["role"]); role != "" {
		return role + "_message"
	}
	return fallback
}

func conversationKey(root map[string]any) string {
	for _, key := range []string{"conversation_id", "prompt_cache_key", "thread_id"} {
		if value := protocolutil.String(root[key]); value != "" {
			return key + "\x00" + value
		}
	}
	if value := root["conversation"]; value != nil {
		if text := protocolutil.String(value); text != "" {
			return "conversation\x00" + text
		}
		if object := protocolutil.Map(value); object != nil {
			if id := protocolutil.String(object["id"]); id != "" {
				return "conversation.id\x00" + id
			}
		}
	}
	metadata := protocolutil.Map(root["metadata"])
	for _, key := range []string{"conversation_id", "thread_id", "session_id", "chat_id"} {
		if value := protocolutil.String(metadata[key]); value != "" {
			return "metadata." + key + "\x00" + value
		}
	}
	return ""
}

func cloneMap(value map[string]any) (map[string]any, error) {
	cloned, err := auditmodel.CloneJSON(value)
	if err != nil {
		return nil, err
	}
	result, ok := cloned.(map[string]any)
	if !ok {
		return nil, errors.New("openai normalizer: cloned value is not an object")
	}
	return result, nil
}

var _ base.AuditNormalizer = (*Parser)(nil)
