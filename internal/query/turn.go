package query

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/parser/openai"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

func (service *Service) ReconstructTurn(ctx context.Context, auditID string) (ReconstructedTurn, error) {
	if ctx == nil {
		return ReconstructedTurn{}, invalid("nil context")
	}
	if err := validateAuditID(auditID); err != nil {
		return ReconstructedTurn{}, err
	}
	detail, err := service.store.QueryAuditDetail(ctx, auditID)
	if errors.Is(err, sql.ErrNoRows) {
		return ReconstructedTurn{}, ErrNotFound
	}
	if err != nil {
		return ReconstructedTurn{}, fmt.Errorf("query: read turn graph: %w", err)
	}
	if detail.TurnGraph == nil {
		return ReconstructedTurn{}, ErrNoTurnGraph
	}
	return reconstructTurnGraph(service.cipher, detail.Audit.ParserName, detail.TurnGraph)
}

func reconstructTurnGraph(cipher security.Cipher, parserName string, graph *sqlite.TurnGraph) (ReconstructedTurn, error) {
	if cipher == nil || graph == nil || graph.ReconstructionStatus != "verified" {
		return ReconstructedTurn{}, integrityAt("graph_header")
	}
	objects := make(map[string]auditmodel.StoredContent, len(graph.Objects))
	for _, object := range graph.Objects {
		if len(object.Hash) != 32 || len(object.SemanticHash) != 32 || object.Kind == "" ||
			object.PlaintextLength < 0 || object.EncodedLength < 0 || len(object.DataEnc) == 0 {
			return ReconstructedTurn{}, integrityAt("content_metadata")
		}
		objects[hex.EncodeToString(object.Hash)] = object
	}
	binaries := make(map[string]auditmodel.StoredBinary, len(graph.Binaries))
	for _, binary := range graph.Binaries {
		if len(binary.Hash) != 32 || binary.MediaType == "" || binary.PlaintextLength < 0 || binary.EncodedLength < 0 || len(binary.DataEnc) == 0 {
			return ReconstructedTurn{}, integrityAt("binary_metadata")
		}
		binaries[hex.EncodeToString(binary.Hash)] = binary
	}

	requestItems, err := openGraphItems(cipher, objects, graph.RequestRefs)
	if err != nil {
		return ReconstructedTurn{}, integrityAt("request_items")
	}
	responseItems, err := openGraphItems(cipher, objects, graph.ResponseRefs)
	if err != nil {
		return ReconstructedTurn{}, integrityAt("response_items")
	}
	requestEnvelope, err := openGraphEnvelope(cipher, objects, graph.RequestEnvelopeHash, "request_envelope")
	if err != nil {
		return ReconstructedTurn{}, integrityAt("request_envelope")
	}
	responseEnvelope, err := openGraphEnvelope(cipher, objects, graph.ResponseEnvelopeHash, "response_envelope")
	if err != nil {
		return ReconstructedTurn{}, integrityAt("response_envelope")
	}
	if !auditmodel.EqualHash(auditmodel.SequenceHash(graph.RequestRefs), graph.RequestSequenceHash) ||
		!auditmodel.EqualHash(auditmodel.SequenceHash(graph.ResponseRefs), graph.ResponseSequenceHash) {
		return ReconstructedTurn{}, integrityAt("sequence_hash")
	}
	request, err := auditmodel.Assemble(graph.RequestLayout, requestEnvelope, requestItems)
	if err != nil || !verifiedReconstruction(request, graph.RequestReconstructionHash) {
		return ReconstructedTurn{}, integrityAt("request_reconstruction")
	}
	response, err := auditmodel.Assemble(graph.ResponseLayout, responseEnvelope, responseItems)
	if err != nil || !verifiedReconstruction(response, graph.ResponseReconstructionHash) {
		return ReconstructedTurn{}, integrityAt("response_reconstruction")
	}

	openedBinaries := make(map[string][]byte)
	defer func() {
		for _, plaintext := range openedBinaries {
			clear(plaintext)
		}
	}()
	resolve := func(hash []byte) ([]byte, error) {
		key := hex.EncodeToString(hash)
		if plaintext, exists := openedBinaries[key]; exists {
			return plaintext, nil
		}
		stored, exists := binaries[key]
		if !exists {
			return nil, auditmodel.ErrReconstruction
		}
		plaintext, err := auditmodel.OpenBinary(cipher, stored)
		if err != nil {
			return nil, err
		}
		openedBinaries[key] = plaintext
		return plaintext, nil
	}
	request, err = auditmodel.RestoreBinaries(request, resolve)
	if err != nil {
		return ReconstructedTurn{}, integrityAt("request_binary_restore")
	}
	response, err = auditmodel.RestoreBinaries(response, resolve)
	if err != nil {
		return ReconstructedTurn{}, integrityAt("response_binary_restore")
	}
	view, err := openai.ReconstructedConversation(parserName, request, response, graph.ResponseLayout)
	if err != nil || !validConversation(view) {
		return ReconstructedTurn{}, integrityAt("conversation_projection")
	}
	return ReconstructedTurn{
		Turn:         mapTurn(graph),
		Request:      request,
		Response:     response,
		Conversation: view,
	}, nil
}

func integrityAt(stage string) error {
	return fmt.Errorf("query: turn %s: %w", stage, ErrIntegrity)
}

func openGraphItems(cipher security.Cipher, objects map[string]auditmodel.StoredContent, refs []auditmodel.ObjectRef) ([]auditmodel.Item, error) {
	items := make([]auditmodel.Item, 0, len(refs))
	for _, ref := range refs {
		stored, exists := objects[hex.EncodeToString(ref.ObjectHash)]
		if !exists || !auditmodel.EqualHash(stored.SemanticHash, ref.SemanticHash) {
			return nil, auditmodel.ErrIntegrity
		}
		decoded, err := auditmodel.OpenObject(cipher, stored)
		if err != nil {
			return nil, err
		}
		semanticHash, err := auditmodel.SemanticHash(decoded.Kind, decoded.Value)
		if err != nil || !auditmodel.EqualHash(semanticHash, ref.SemanticHash) {
			return nil, auditmodel.ErrIntegrity
		}
		items = append(items, auditmodel.Item{Slot: ref.Slot, Kind: decoded.Kind, Value: decoded.Value})
	}
	return items, nil
}

func openGraphEnvelope(cipher security.Cipher, objects map[string]auditmodel.StoredContent, hash []byte, wantKind string) (any, error) {
	stored, exists := objects[hex.EncodeToString(hash)]
	if !exists || stored.Kind != wantKind {
		return nil, auditmodel.ErrIntegrity
	}
	decoded, err := auditmodel.OpenObject(cipher, stored)
	if err != nil || decoded.Kind != wantKind {
		return nil, auditmodel.ErrIntegrity
	}
	return decoded.Value, nil
}

func verifiedReconstruction(value any, want []byte) bool {
	canonical, err := auditmodel.CanonicalJSON(value)
	return err == nil && auditmodel.EqualHash(auditmodel.ReconstructionHash(canonical), want)
}

func mapTurn(graph *sqlite.TurnGraph) Turn {
	return Turn{
		TurnID:                       graph.TurnID,
		ConversationID:               graph.ConversationID,
		ParentTurnID:                 graph.ParentTurnID,
		ParentBase:                   graph.ParentBase,
		LinkReason:                   graph.LinkReason,
		LinkConfidence:               graph.LinkConfidence,
		RequestLayout:                graph.RequestLayout,
		ResponseLayout:               graph.ResponseLayout,
		RequestItemCount:             len(graph.RequestRefs),
		ResponseItemCount:            len(graph.ResponseRefs),
		RequestSequenceSHA256:        hex.EncodeToString(graph.RequestSequenceHash),
		ResponseSequenceSHA256:       hex.EncodeToString(graph.ResponseSequenceHash),
		RequestReconstructionSHA256:  hex.EncodeToString(graph.RequestReconstructionHash),
		ResponseReconstructionSHA256: hex.EncodeToString(graph.ResponseReconstructionHash),
		ReconstructionStatus:         graph.ReconstructionStatus,
		PreviousResponseID:           graph.PreviousResponseID,
		ResponseID:                   graph.ResponseID,
		CreatedAtNS:                  graph.CreatedAtNS,
	}
}
