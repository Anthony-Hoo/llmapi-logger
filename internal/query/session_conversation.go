package query

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/security"
)

// SessionConversation returns the decrypted conversation of one audit for the
// session analysis batch (doc/features/24-session-analysis.md section 6.1):
// the verified turn graph projection for OpenAI records, otherwise the
// encrypted parser conversation. Headers, the request URI and raw bodies are
// not decrypted. Callers must keep the result in memory only.
func (service *Service) SessionConversation(ctx context.Context, auditID string) (*conversation.Conversation, error) {
	if ctx == nil {
		return nil, invalid("nil context")
	}
	if err := validateAuditID(auditID); err != nil {
		return nil, err
	}
	detail, err := service.store.QueryAuditDetail(ctx, auditID, nil)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query: read session conversation: %w", err)
	}
	if detail.TurnGraph != nil {
		reconstructed, err := reconstructTurnGraph(service.cipher, detail.Audit.ParserName, detail.TurnGraph)
		if err != nil {
			return nil, err
		}
		return reconstructed.Conversation, nil
	}
	parsed := detail.ParsedResult
	if parsed == nil || len(parsed.ParsedJSONEnc) == 0 {
		return nil, ErrNotFound
	}
	aad, err := security.AAD(auditID, "parsed_json", parsed.ParserName)
	if err != nil {
		return nil, ErrIntegrity
	}
	plaintext, err := service.cipher.Decrypt(aad, parsed.ParsedJSONEnc)
	if err != nil {
		return nil, ErrIntegrity
	}
	defer clear(plaintext)
	var envelope struct {
		Conversation *conversation.Conversation `json:"conversation"`
	}
	if err := json.Unmarshal(plaintext, &envelope); err != nil || !validConversation(envelope.Conversation) {
		return nil, ErrIntegrity
	}
	return envelope.Conversation, nil
}
