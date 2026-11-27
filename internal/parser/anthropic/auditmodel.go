package anthropic

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/insights"
	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/protocolutil"
)

// NormalizeAudit splits a Messages request and response into envelopes and
// content-addressed items. A client resends the whole history on every call,
// so each message is one item and is stored once however often it recurs.
func (implementation *Parser) NormalizeAudit(_ context.Context, input base.Input, result base.Result) (auditmodel.Turn, error) {
	if implementation == nil {
		return auditmodel.Turn{}, errors.New("anthropic normalizer: nil parser")
	}
	turn := auditmodel.Turn{
		AuditID:        input.AuditID,
		Protocol:       input.Protocol,
		ParserName:     Messages,
		ResponseID:     result.ResponseID,
		RequestLayout:  auditmodel.LayoutNone,
		ResponseLayout: auditmodel.LayoutNone,
		// Messages has no file_data convention; a tool argument with such a
		// name is ordinary text.
		SkipInlineFileData: true,
	}
	if input.Request.Present {
		root, err := decodeRoot(input.Request.Data, "request")
		if err != nil {
			return auditmodel.Turn{}, err
		}
		request, err := normalizeRequest(root)
		if err != nil {
			return auditmodel.Turn{}, err
		}
		turn.RequestLayout = request.layout
		turn.RequestEnvelope = request.envelope
		turn.RequestItems = request.items
		turn.RequestOriginal = request.original
		turn.ConversationKey = conversationKey(root)
	}
	if input.Response.Present {
		var response normalizedSide
		if base.LooksLikeSSE(input.Response.ContentType, input.Response.Data) {
			normalized, err := normalizeStreamResponse(input.Response.Data, result)
			if err != nil {
				return auditmodel.Turn{}, err
			}
			response = normalized
		} else {
			root, err := decodeRoot(input.Response.Data, "response")
			if err != nil {
				return auditmodel.Turn{}, err
			}
			normalized, err := normalizeJSONResponse(root)
			if err != nil {
				return auditmodel.Turn{}, err
			}
			response = normalized
		}
		turn.ResponseLayout = response.layout
		turn.ResponseEnvelope = response.envelope
		turn.ResponseItems = response.items
		turn.ResponseOriginal = response.original
	}
	return turn, nil
}

// conversationKey is the session a client declares in metadata, by the rule
// insights uses for its sessions. metadata.user_id alone names a user and is
// no key: Claude Code embeds a session id in it, which is. Without a key the
// parent turn is inferred from repeated content.
func conversationKey(root map[string]any) string {
	if session := insights.DeclaredSessionID(root); session != "" {
		return "metadata.session\x00" + session
	}
	return ""
}

type normalizedSide struct {
	layout   string
	envelope any
	items    []auditmodel.Item
	original any
}

func decodeRoot(data []byte, side string) (map[string]any, error) {
	var root map[string]any
	if err := auditmodel.DecodeJSON(data, &root); err != nil {
		return nil, fmt.Errorf("anthropic normalizer: %s JSON: %w", side, err)
	}
	if root == nil {
		return nil, fmt.Errorf("anthropic normalizer: %s JSON is not an object", side)
	}
	if err := auditmodel.CheckReservedMarkers(root); err != nil {
		return nil, err
	}
	return root, nil
}

// normalizeRequest takes messages and system out of the envelope. The system
// items follow the messages in the sequence: parent inference compares
// sequence prefixes, and a system prompt shared by unrelated sessions of one
// client must not count as common history.
func normalizeRequest(root map[string]any) (normalizedSide, error) {
	original, err := cloneMap(root)
	if err != nil {
		return normalizedSide{}, err
	}
	envelope, err := cloneMap(root)
	if err != nil {
		return normalizedSide{}, err
	}
	values, exists := envelope[auditmodel.SlotMessages]
	if !exists {
		return normalizedSide{}, errors.New("anthropic normalizer: request has no messages")
	}
	messages, ok := values.([]any)
	if !ok {
		return normalizedSide{}, errors.New("anthropic normalizer: messages is not an array")
	}
	items := make([]auditmodel.Item, 0, len(messages)+1)
	for _, value := range messages {
		items = append(items, auditmodel.Item{Slot: auditmodel.SlotMessages, Kind: messageKind(value), Value: value})
	}
	delete(envelope, auditmodel.SlotMessages)

	layout := auditmodel.LayoutAnthropicMessagesRequestSystemNone
	// A null system stays in the envelope, like any other scalar field.
	if system, exists := envelope[auditmodel.SlotSystem]; exists && system != nil {
		delete(envelope, auditmodel.SlotSystem)
		if blocks, ok := system.([]any); ok {
			layout = auditmodel.LayoutAnthropicMessagesRequestSystemArray
			for _, block := range blocks {
				items = append(items, auditmodel.Item{Slot: auditmodel.SlotSystem, Kind: "system", Value: block})
			}
		} else {
			layout = auditmodel.LayoutAnthropicMessagesRequestSystemSingle
			items = append(items, auditmodel.Item{Slot: auditmodel.SlotSystem, Kind: "system", Value: system})
		}
	}
	return normalizedSide{layout: layout, envelope: envelope, items: items, original: original}, nil
}

func normalizeJSONResponse(root map[string]any) (normalizedSide, error) {
	original, err := cloneMap(root)
	if err != nil {
		return normalizedSide{}, err
	}
	envelope, err := cloneMap(root)
	if err != nil {
		return normalizedSide{}, err
	}
	items := make([]auditmodel.Item, 0)
	// An error body has no content array and is kept whole in the envelope.
	if blocks, ok := envelope[auditmodel.SlotContent].([]any); ok {
		markers := make([]any, 0, len(blocks))
		for _, block := range blocks {
			markers = append(markers, auditmodel.ItemMarker(len(items)))
			items = append(items, auditmodel.Item{Slot: auditmodel.SlotContent, Kind: blockKind(block), Value: block})
		}
		envelope[auditmodel.SlotContent] = markers
	}
	return normalizedSide{layout: auditmodel.LayoutMarkerEnvelope, envelope: envelope, items: items, original: original}, nil
}

// normalizeStreamResponse keeps one descriptor per SSE event and the
// aggregated response messages, as the OpenAI stream layout does. The summary
// also holds the cache-aware usage and the stop reason, which the descriptors
// no longer yield once the raw body is released.
func normalizeStreamResponse(data []byte, result base.Result) (normalizedSide, error) {
	events, _ := base.DecodeSSEWithStatus(data)
	if len(events) == 0 {
		return normalizedSide{}, errors.New("anthropic normalizer: empty SSE")
	}
	descriptors := make([]any, 0, len(events))
	stopReason := ""
	for _, event := range events {
		if root, err := protocolutil.Object(event.Data); err == nil {
			for _, holder := range []any{root["delta"], root["message"]} {
				if reason := protocolutil.String(protocolutil.Map(holder)["stop_reason"]); reason != "" {
					stopReason = reason
				}
			}
		}
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
			value, err := auditmodel.CloneJSON(auditmodel.DisplayFromConversation(message))
			if err != nil {
				return normalizedSide{}, err
			}
			items = append(items, auditmodel.Item{Slot: auditmodel.SlotAggregate, Kind: "stream_" + message.Role, Value: value})
			aggregateValues = append(aggregateValues, value)
		}
	}
	envelope, err := cloneMap(map[string]any{
		"format": "sse",
		"events": descriptors,
		"summary": map[string]any{
			"response_id":      result.ResponseID,
			"usage":            result.Usage,
			"normalized_usage": result.Normalized,
			"stop_reason":      stopReason,
			"error_type":       result.ErrorType,
			"error_code":       result.ErrorCode,
		},
	})
	if err != nil {
		return normalizedSide{}, err
	}
	original, err := cloneMap(envelope)
	if err != nil {
		return normalizedSide{}, err
	}
	original[auditmodel.SlotAggregate] = aggregateValues
	return normalizedSide{layout: auditmodel.LayoutAnthropicStreamResponse, envelope: envelope, items: items, original: original}, nil
}

func messageKind(value any) string {
	if role := protocolutil.String(protocolutil.Map(value)["role"]); role != "" {
		return role + "_message"
	}
	return "message"
}

func blockKind(value any) string {
	if typeName := protocolutil.String(protocolutil.Map(value)["type"]); typeName != "" {
		return typeName
	}
	return "content_block"
}

func cloneMap(value map[string]any) (map[string]any, error) {
	cloned, err := auditmodel.CloneJSON(value)
	if err != nil {
		return nil, err
	}
	result, ok := cloned.(map[string]any)
	if !ok {
		return nil, errors.New("anthropic normalizer: cloned value is not an object")
	}
	return result, nil
}

var _ base.AuditNormalizer = (*Parser)(nil)
