package anthropic

import (
	"llmapi-logger/internal/auditmodel"
	base "llmapi-logger/internal/parser"
)

// Adapter returns the protocol adapter for Messages.
func Adapter() base.Adapter {
	return base.Adapter{
		Parser:       New(),
		Conversation: ReconstructedConversation,
		Layouts: []string{
			auditmodel.LayoutNone,
			auditmodel.LayoutAnthropicMessagesRequestSystemNone,
			auditmodel.LayoutAnthropicMessagesRequestSystemSingle,
			auditmodel.LayoutAnthropicMessagesRequestSystemArray,
			auditmodel.LayoutMarkerEnvelope,
			auditmodel.LayoutAnthropicStreamResponse,
		},
	}
}
