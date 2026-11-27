package openai

import (
	"errors"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/conversation"
	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/protocolutil"
)

// ReconstructedConversation derives the management DTO from provider values
// rebuilt from the content-addressed graph. It avoids storing a second copy of
// message text solely for display.
func ReconstructedConversation(parserName string, request, response any, responseLayout string) (*conversation.Conversation, error) {
	if _, err := New(parserName); err != nil {
		return nil, err
	}
	result := base.Result{}
	if root := protocolutil.Map(request); root != nil {
		appendRequestConversation(root, parserName, &result)
	}
	switch responseLayout {
	case auditmodel.LayoutOpenAIStreamResponseV2:
		// The aggregate is the folded non-stream body.
		body := protocolutil.Map(protocolutil.Map(response)[auditmodel.SlotAggregate])
		if body == nil {
			return nil, errors.New("openai reconstruction: stream response has no aggregate body")
		}
		appendResponseConversation(body, parserName, &result)
	case auditmodel.LayoutOpenAIStreamResponse:
		// Parser version 2 stored display messages as the aggregate.
		root := protocolutil.Map(response)
		if root == nil {
			return nil, errors.New("openai reconstruction: stream response is not an object")
		}
		for _, value := range protocolutil.Slice(root[auditmodel.SlotAggregate]) {
			encoded, err := auditmodel.CanonicalJSON(value)
			if err != nil {
				return nil, err
			}
			var display auditmodel.DisplayMessage
			if err := auditmodel.DecodeJSON(encoded, &display); err != nil {
				return nil, err
			}
			conversation.Ensure(&result.Conversation).Append(display.ConversationMessage(
				conversation.PhaseResponse,
				conversation.DirectionUpstreamToClient,
			))
		}
	default:
		if root := protocolutil.Map(response); root != nil {
			appendResponseConversation(root, parserName, &result)
		}
	}
	return result.Conversation, nil
}
