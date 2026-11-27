package gemini

import (
	"errors"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/conversation"
	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/protocolutil"
	"llmapi-logger/internal/parser/streamevidence"
)

// ReconstructedConversation derives the management DTO from provider values
// rebuilt from the content-addressed graph, so message text is not stored a
// second time for display. It reads the three response forms the way Parse
// does: a folded stream body, a JSON array of chunks (folded here, as Parse
// folds it), or a GenerateContentResponse.
func ReconstructedConversation(request, response any, responseLayout string) (*conversation.Conversation, error) {
	result := base.Result{}
	if root := protocolutil.Map(request); root != nil {
		appendRequestConversation(root, &result)
	}
	if responseLayout == auditmodel.LayoutGeminiStreamResponse {
		body := protocolutil.Map(protocolutil.Map(response)[auditmodel.SlotAggregate])
		if body == nil {
			return nil, errors.New("gemini reconstruction: stream response has no aggregate body")
		}
		appendResponseConversation(body, &result)
		return result.Conversation, nil
	}
	if chunks, ok := response.([]any); ok {
		decoded := make([]streamevidence.Event, len(chunks))
		for index, chunk := range chunks {
			decoded[index] = streamevidence.Event{Index: index, Object: protocolutil.Map(chunk)}
		}
		appendResponseConversation(foldDecoded(decoded).body, &result)
		return result.Conversation, nil
	}
	if root := protocolutil.Map(response); root != nil {
		appendResponseConversation(root, &result)
	}
	return result.Conversation, nil
}
