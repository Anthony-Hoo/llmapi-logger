package query

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/parser/builtin"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

func (service *Service) ReconstructTurn(ctx context.Context, auditID string) (ReconstructedTurn, error) {
	if ctx == nil {
		return ReconstructedTurn{}, invalid("nil context")
	}
	if err := validateAuditID(auditID); err != nil {
		return ReconstructedTurn{}, err
	}
	detail, err := service.store.QueryAuditDetail(ctx, auditID, nil)
	if errors.Is(err, sql.ErrNoRows) {
		return ReconstructedTurn{}, ErrNotFound
	}
	if err != nil {
		return ReconstructedTurn{}, fmt.Errorf("query: read turn graph: %w", err)
	}
	if detail.TurnGraph == nil {
		return ReconstructedTurn{}, ErrNoTurnGraph
	}
	return reconstructAuditTurn(service.cipher, detail)
}

// graphObject is one content object of a turn graph as the assembly reads
// it: its address, its kind, whether its stored metadata is well formed, and
// how to open it. The database path opens it by decrypting (OpenObject), the
// plain path by decoding plaintext it was given; open must return a freshly
// decoded value on every call, because assembly mutates what it gets.
type graphObject struct {
	hash         []byte
	semanticHash []byte
	kind         string
	wellFormed   bool
	open         func() (auditmodel.DecodedObject, error)
}

// graphBinary is one binary object of a turn graph as the assembly reads it.
type graphBinary struct {
	hash       []byte
	wellFormed bool
	open       func() ([]byte, error)
}

// graphContent is what assembleTurnGraph opens objects and binaries from.
// ownsBinaries says that opened binary bytes belong to the assembly, which
// clears them when it returns; plain input stays the caller's.
type graphContent struct {
	objects      []graphObject
	binaries     []graphBinary
	ownsBinaries bool
}

func reconstructTurnGraph(cipher security.Cipher, parserName string, graph *storage.TurnGraph) (ReconstructedTurn, error) {
	if cipher == nil || graph == nil {
		return ReconstructedTurn{}, integrityAt("graph_header")
	}
	return assembleTurnGraph(parserName, graph, cipherGraphContent(cipher, graph))
}

// cipherGraphContent opens the stored objects of graph lazily, so only the
// objects and binaries the turn references are ever decrypted.
func cipherGraphContent(cipher security.Cipher, graph *storage.TurnGraph) graphContent {
	content := graphContent{
		objects:      make([]graphObject, 0, len(graph.Objects)),
		binaries:     make([]graphBinary, 0, len(graph.Binaries)),
		ownsBinaries: true,
	}
	for _, object := range graph.Objects {
		content.objects = append(content.objects, graphObject{
			hash: object.Hash, semanticHash: object.SemanticHash, kind: object.Kind,
			wellFormed: len(object.Hash) == 32 && len(object.SemanticHash) == 32 && object.Kind != "" &&
				object.PlaintextLength >= 0 && object.EncodedLength >= 0 && len(object.DataEnc) != 0,
			open: func() (auditmodel.DecodedObject, error) { return auditmodel.OpenObject(cipher, object) },
		})
	}
	for _, binary := range graph.Binaries {
		content.binaries = append(content.binaries, graphBinary{
			hash: binary.Hash,
			wellFormed: len(binary.Hash) == 32 && binary.MediaType != "" && binary.PlaintextLength >= 0 &&
				binary.EncodedLength >= 0 && len(binary.DataEnc) != 0,
			open: func() ([]byte, error) { return auditmodel.OpenBinary(cipher, binary) },
		})
	}
	return content
}

// assembleTurnGraph is reconstruction without decryption: it checks the
// graph header and object metadata, opens the referenced objects through
// content, checks semantic, sequence and reconstruction hashes, assembles
// both sides, restores binaries and projects the conversation. Only the
// header fields of graph are read; its Objects and Binaries come from content.
func assembleTurnGraph(parserName string, graph *storage.TurnGraph, content graphContent) (ReconstructedTurn, error) {
	if graph == nil || graph.ReconstructionStatus != "verified" {
		return ReconstructedTurn{}, integrityAt("graph_header")
	}
	objects := make(map[string]graphObject, len(content.objects))
	for _, object := range content.objects {
		if !object.wellFormed {
			return ReconstructedTurn{}, integrityAt("content_metadata")
		}
		objects[hex.EncodeToString(object.hash)] = object
	}
	binaries := make(map[string]graphBinary, len(content.binaries))
	for _, binary := range content.binaries {
		if !binary.wellFormed {
			return ReconstructedTurn{}, integrityAt("binary_metadata")
		}
		binaries[hex.EncodeToString(binary.hash)] = binary
	}

	requestItems, err := openGraphItems(objects, graph.RequestRefs)
	if err != nil {
		return ReconstructedTurn{}, integrityAt("request_items")
	}
	responseItems, err := openGraphItems(objects, graph.ResponseRefs)
	if err != nil {
		return ReconstructedTurn{}, integrityAt("response_items")
	}
	requestEnvelope, err := openGraphEnvelope(objects, graph.RequestEnvelopeHash, "request_envelope")
	if err != nil {
		return ReconstructedTurn{}, integrityAt("request_envelope")
	}
	responseEnvelope, err := openGraphEnvelope(objects, graph.ResponseEnvelopeHash, "response_envelope")
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
	if content.ownsBinaries {
		defer func() {
			for _, plaintext := range openedBinaries {
				clear(plaintext)
			}
		}()
	}
	resolve := func(hash []byte) ([]byte, error) {
		key := hex.EncodeToString(hash)
		if plaintext, exists := openedBinaries[key]; exists {
			return plaintext, nil
		}
		stored, exists := binaries[key]
		if !exists {
			return nil, auditmodel.ErrReconstruction
		}
		plaintext, err := stored.open()
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
	view, err := reconstructedConversation(parserName, request, response, graph.ResponseLayout)
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

// reconstructedConversation projects rebuilt provider values with the adapter
// of the parser that normalized them.
func reconstructedConversation(parserName string, request, response any, responseLayout string) (*conversation.Conversation, error) {
	return builtin.Registry().RebuildConversation(parserName, request, response, responseLayout)
}

func integrityAt(stage string) error {
	return fmt.Errorf("query: turn %s: %w", stage, ErrIntegrity)
}

func openGraphItems(objects map[string]graphObject, refs []auditmodel.ObjectRef) ([]auditmodel.Item, error) {
	items := make([]auditmodel.Item, 0, len(refs))
	for _, ref := range refs {
		stored, exists := objects[hex.EncodeToString(ref.ObjectHash)]
		if !exists || !auditmodel.EqualHash(stored.semanticHash, ref.SemanticHash) {
			return nil, auditmodel.ErrIntegrity
		}
		decoded, err := stored.open()
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

func openGraphEnvelope(objects map[string]graphObject, hash []byte, wantKind string) (any, error) {
	stored, exists := objects[hex.EncodeToString(hash)]
	if !exists || stored.kind != wantKind {
		return nil, auditmodel.ErrIntegrity
	}
	decoded, err := stored.open()
	if err != nil || decoded.Kind != wantKind {
		return nil, auditmodel.ErrIntegrity
	}
	return decoded.Value, nil
}

func verifiedReconstruction(value any, want []byte) bool {
	canonical, err := auditmodel.CanonicalJSON(value)
	return err == nil && auditmodel.EqualHash(auditmodel.ReconstructionHash(canonical), want)
}

func mapTurn(graph *storage.TurnGraph) Turn {
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
