package gemini

import (
	"llmapi-logger/internal/auditmodel"
	base "llmapi-logger/internal/parser"
)

// Adapter returns the protocol adapter for one Gemini parser name. Both
// names share the normalizer: each reads a response by its form (SSE, JSON
// array or JSON object), not by the operation, so both declare every layout.
func Adapter(name string) (base.Adapter, error) {
	implementation, err := New(name)
	if err != nil {
		return base.Adapter{}, err
	}
	return base.Adapter{
		Parser:       implementation,
		Conversation: ReconstructedConversation,
		Layouts: []string{
			auditmodel.LayoutNone,
			auditmodel.LayoutGeminiRequestSystemNone,
			auditmodel.LayoutGeminiRequestSystemSingle,
			auditmodel.LayoutMarkerEnvelope,
			auditmodel.LayoutGeminiStreamResponse,
		},
	}, nil
}
