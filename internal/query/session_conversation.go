package query

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"llmapi-logger/internal/conversation"
)

// SessionConversation returns the decrypted conversation of one audit for the
// session analysis batch (doc/features/24-session-analysis.md section 6.1):
// the verified turn graph projection when the audit has one, otherwise the
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
	var turn func() (ReconstructedTurn, error)
	if detail.TurnGraph != nil {
		turn = func() (ReconstructedTurn, error) { return reconstructAuditTurn(service.cipher, detail) }
	}
	parsed := detail.ParsedResult
	return sessionConversation(turn, parsed != nil && len(parsed.ParsedJSONEnc) != 0,
		func() (parsedEnvelope, error) { return openParsedEnvelope(service.cipher, auditID, parsed) })
}

// sessionConversation is SessionConversation without decryption: turn, when
// not nil, reconstructs the audit's turn; hasParsed says the parsed result
// has a payload, which openParsed opens.
func sessionConversation(turn func() (ReconstructedTurn, error), hasParsed bool, openParsed func() (parsedEnvelope, error)) (*conversation.Conversation, error) {
	if turn != nil {
		reconstructed, err := turn()
		if err != nil {
			return nil, err
		}
		return reconstructed.Conversation, nil
	}
	if !hasParsed {
		return nil, ErrNotFound
	}
	envelope, err := openParsed()
	if err != nil {
		return nil, err
	}
	return envelope.Conversation, nil
}
