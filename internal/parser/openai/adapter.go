package openai

import (
	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/conversation"
	base "llmapi-logger/internal/parser"
)

// Adapter returns the protocol adapter for one OpenAI parser name.
func Adapter(name string) (base.Adapter, error) {
	implementation, err := New(name)
	if err != nil {
		return base.Adapter{}, err
	}
	return base.Adapter{
		Parser: implementation,
		Conversation: func(request, response any, responseLayout string) (*conversation.Conversation, error) {
			return ReconstructedConversation(name, request, response, responseLayout)
		},
		Layouts: append(requestLayouts(name),
			auditmodel.LayoutNone, auditmodel.LayoutMarkerEnvelope, auditmodel.LayoutOpenAIStreamResponse),
	}, nil
}

// requestLayouts mirrors normalizeRequest: the layouts a request of this
// parser can be split into.
func requestLayouts(name string) []string {
	switch name {
	case ChatCompletions:
		return []string{auditmodel.LayoutOpenAIChatRequest}
	case Completions:
		return []string{auditmodel.LayoutOpenAICompletionsPromptArray, auditmodel.LayoutOpenAICompletionsPromptSingle}
	default:
		return []string{auditmodel.LayoutOpenAIResponsesRequestArray, auditmodel.LayoutOpenAIResponsesRequestSingle, auditmodel.LayoutOpenAIResponsesRequestNone}
	}
}
