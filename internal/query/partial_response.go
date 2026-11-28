package query

import (
	"encoding/json"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// parsedEnvelope is what readers take from the decrypted parsed_json_enc: the
// fallback conversation of an audit without a turn, and the response-phase
// messages an audit with a request-only turn keeps
// (parser.PartialResponseMessagesKey). The writer stores one or the other,
// never both.
type parsedEnvelope struct {
	Conversation    *conversation.Conversation `json:"conversation"`
	PartialResponse []conversation.Message     `json:"partial_response_messages"`
}

// openParsedEnvelope decrypts and decodes the parsed result of an audit. A
// missing parsed result or one without a payload is an empty envelope. The
// fallback conversation must be well formed; the partial response messages
// are checked when they are merged.
func openParsedEnvelope(cipher security.Cipher, auditID string, parsed *storage.ParsedResultSummary) (parsedEnvelope, error) {
	if parsed == nil || len(parsed.ParsedJSONEnc) == 0 {
		return parsedEnvelope{}, nil
	}
	plaintext, err := auditmodel.OpenParsedResult(cipher, auditID, parsed.ParserName, parsed.ParsedJSONEnc)
	if err != nil {
		return parsedEnvelope{}, ErrIntegrity
	}
	defer clear(plaintext)
	return decodeParsedEnvelope(plaintext)
}

// decodeParsedEnvelope decodes the JSON held in parsed_json_enc once it has
// been decrypted and decompressed. It does not keep plaintext.
func decodeParsedEnvelope(plaintext []byte) (parsedEnvelope, error) {
	var envelope parsedEnvelope
	if err := json.Unmarshal(plaintext, &envelope); err != nil || !validConversation(envelope.Conversation) {
		return parsedEnvelope{}, ErrIntegrity
	}
	return envelope, nil
}

// reconstructAuditTurn rebuilds the turn of an audit and completes its
// conversation: a request-only turn (response layout none) rebuilds the
// request messages only, and the response-phase messages kept in the parsed
// result follow them (MergePartialResponse). Every reader of an audit's
// conversation goes through here, so the detail view, the session
// conversation, the exports and the backfills see the same messages.
func reconstructAuditTurn(cipher security.Cipher, detail storage.AuditQueryDetail) (ReconstructedTurn, error) {
	return completeAuditTurn(
		func() (ReconstructedTurn, error) {
			return reconstructTurnGraph(cipher, detail.Audit.ParserName, detail.TurnGraph)
		},
		func() (parsedEnvelope, error) {
			return openParsedEnvelope(cipher, detail.Audit.AuditID, detail.ParsedResult)
		},
	)
}

// completeAuditTurn is reconstructAuditTurn without decryption. The parsed
// envelope is opened only for a request-only turn.
func completeAuditTurn(reconstruct func() (ReconstructedTurn, error), openParsed func() (parsedEnvelope, error)) (ReconstructedTurn, error) {
	reconstructed, err := reconstruct()
	if err != nil {
		return ReconstructedTurn{}, err
	}
	if reconstructed.Turn.ResponseLayout != auditmodel.LayoutNone {
		return reconstructed, nil
	}
	envelope, err := openParsed()
	if err != nil {
		return ReconstructedTurn{}, err
	}
	merged, ok := MergePartialResponse(reconstructed.Conversation, envelope.PartialResponse)
	if !ok {
		return ReconstructedTurn{}, integrityAt("partial_response_messages")
	}
	reconstructed.Conversation = merged
	return reconstructed, nil
}

// MergePartialResponse appends the response-phase messages of a request-only
// turn after the request messages rebuilt from it, renumbering their Index so
// the result is contiguous. It does not change its arguments. ok is false
// when a partial message is not a well-formed response-phase message, or the
// merged conversation is not well formed. With no partial messages the
// rebuilt conversation is returned as it is.
//
// This is the one merge for every reader, the cold archive reader included.
func MergePartialResponse(rebuilt *conversation.Conversation, partial []conversation.Message) (*conversation.Conversation, bool) {
	if len(partial) == 0 {
		return rebuilt, true
	}
	merged := conversation.New()
	if rebuilt != nil {
		merged.SchemaVersion = rebuilt.SchemaVersion
		merged.Messages = append(merged.Messages, rebuilt.Messages...)
	}
	for _, message := range partial {
		if message.Phase != conversation.PhaseResponse {
			return nil, false
		}
		message.Index = len(merged.Messages)
		message.Content = append([]conversation.Part(nil), message.Content...)
		merged.Messages = append(merged.Messages, message)
	}
	if !validConversation(merged) {
		return nil, false
	}
	return merged, true
}
