package anthropic

import (
	"errors"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/conversation"
	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/protocolutil"
)

// ReconstructedConversation derives the management DTO from provider values
// rebuilt from the content-addressed graph, so message text is not stored a
// second time for display.
func ReconstructedConversation(request, response any, responseLayout string) (*conversation.Conversation, error) {
	result := base.Result{}
	if root := protocolutil.Map(request); root != nil {
		appendRequestConversation(root, &result)
	}
	if responseLayout == auditmodel.LayoutAnthropicStreamResponse {
		root := protocolutil.Map(response)
		if root == nil {
			return nil, errors.New("anthropic reconstruction: stream response is not an object")
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
	} else if root := protocolutil.Map(response); root != nil {
		appendResponseConversation(root, &result)
	}
	return result.Conversation, nil
}
