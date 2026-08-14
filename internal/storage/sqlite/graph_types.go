package sqlite

import (
	"bytes"
	"errors"

	"llmapi-logger/internal/auditmodel"
)

// ParsedAudit atomically persists the narrow parser summary and, when
// available, one verified content-addressed turn graph.
type ParsedAudit struct {
	Result ParsedResult
	Turn   *auditmodel.PreparedTurn
}

func validateParsedAudit(value ParsedAudit) error {
	if err := validateParsedResult(value.Result); err != nil {
		return err
	}
	if value.Turn == nil {
		return nil
	}
	turn := value.Turn
	if turn.AuditID != value.Result.AuditID || turn.ParserName != value.Result.ParserName || turn.Protocol == "" ||
		turn.RequestLayout == "" || turn.ResponseLayout == "" || turn.CreatedAtNS <= 0 ||
		len(turn.RequestEnvelopeHash) != 32 || len(turn.ResponseEnvelopeHash) != 32 ||
		len(turn.RequestSequenceHash) != 32 || len(turn.ResponseSequenceHash) != 32 ||
		len(turn.RequestReconstructionHash) != 32 || len(turn.ResponseReconstructionHash) != 32 ||
		(len(turn.ConversationKeyHash) != 0 && len(turn.ConversationKeyHash) != 32) {
		return errors.New("sqlite: invalid prepared turn")
	}
	for _, ref := range append(append([]auditmodel.ObjectRef(nil), turn.RequestRefs...), turn.ResponseRefs...) {
		if ref.Slot == "" || len(ref.ObjectHash) != 32 || len(ref.SemanticHash) != 32 {
			return errors.New("sqlite: invalid prepared turn reference")
		}
	}
	for _, object := range turn.Objects {
		if len(object.Hash) != 32 || len(object.SemanticHash) != 32 || object.Kind == "" ||
			object.PlaintextLength < 0 || object.EncodedLength < 0 || len(object.DataEnc) == 0 ||
			(object.Compression != auditmodel.CompressionNone && object.Compression != auditmodel.CompressionGZIP) {
			return errors.New("sqlite: invalid content object")
		}
	}
	for _, binary := range turn.Binaries {
		if len(binary.Hash) != 32 || binary.MediaType == "" || binary.PlaintextLength < 0 || binary.EncodedLength < 0 || len(binary.DataEnc) == 0 ||
			(binary.Compression != auditmodel.CompressionNone && binary.Compression != auditmodel.CompressionGZIP) {
			return errors.New("sqlite: invalid binary object")
		}
	}
	return nil
}

func cloneParsedAudit(value ParsedAudit) ParsedAudit {
	value.Result = cloneParsedResult(value.Result)
	if value.Turn == nil {
		return value
	}
	turn := *value.Turn
	turn.RequestEnvelopeHash = cloneBytes(turn.RequestEnvelopeHash)
	turn.ResponseEnvelopeHash = cloneBytes(turn.ResponseEnvelopeHash)
	turn.RequestSequenceHash = cloneBytes(turn.RequestSequenceHash)
	turn.ResponseSequenceHash = cloneBytes(turn.ResponseSequenceHash)
	turn.RequestReconstructionHash = cloneBytes(turn.RequestReconstructionHash)
	turn.ResponseReconstructionHash = cloneBytes(turn.ResponseReconstructionHash)
	turn.ConversationKeyHash = cloneBytes(turn.ConversationKeyHash)
	turn.RequestRefs = cloneObjectRefs(turn.RequestRefs)
	turn.ResponseRefs = cloneObjectRefs(turn.ResponseRefs)
	turn.Objects = make([]auditmodel.ContentObject, len(value.Turn.Objects))
	for index, object := range value.Turn.Objects {
		turn.Objects[index] = cloneContentObject(object)
	}
	turn.Binaries = make([]auditmodel.BinaryObject, len(value.Turn.Binaries))
	for index, binary := range value.Turn.Binaries {
		turn.Binaries[index] = binary
		turn.Binaries[index].Hash = cloneBytes(binary.Hash)
		turn.Binaries[index].DataEnc = cloneBytes(binary.DataEnc)
	}
	value.Turn = &turn
	return value
}

func cloneObjectRefs(values []auditmodel.ObjectRef) []auditmodel.ObjectRef {
	result := make([]auditmodel.ObjectRef, len(values))
	for index, value := range values {
		result[index] = value
		result[index].ObjectHash = cloneBytes(value.ObjectHash)
		result[index].SemanticHash = cloneBytes(value.SemanticHash)
	}
	return result
}

func cloneContentObject(value auditmodel.ContentObject) auditmodel.ContentObject {
	value.Hash = cloneBytes(value.Hash)
	value.SemanticHash = cloneBytes(value.SemanticHash)
	value.DataEnc = cloneBytes(value.DataEnc)
	value.BinaryRefs = append([]auditmodel.BinaryReference(nil), value.BinaryRefs...)
	for index := range value.BinaryRefs {
		value.BinaryRefs[index].BinaryHash = cloneBytes(value.BinaryRefs[index].BinaryHash)
	}
	value.ExternalRefs = append([]auditmodel.ExternalReference(nil), value.ExternalRefs...)
	for index := range value.ExternalRefs {
		value.ExternalRefs[index].ValueHash = cloneBytes(value.ExternalRefs[index].ValueHash)
		value.ExternalRefs[index].ValueEnc = cloneBytes(value.ExternalRefs[index].ValueEnc)
	}
	return value
}

func sameBytes(left, right []byte) bool { return bytes.Equal(left, right) }
