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
		// The aggregate is the folded Message body, read like a non-stream
		// response.
		message := protocolutil.Map(protocolutil.Map(response)[auditmodel.SlotAggregate])
		if message == nil {
			return nil, errors.New("anthropic reconstruction: stream response has no aggregate message")
		}
		appendResponseConversation(message, &result)
	} else if root := protocolutil.Map(response); root != nil {
		appendResponseConversation(root, &result)
	}
	return result.Conversation, nil
}
