package audit

import (
	"net/http"

	"llmapi-logger/internal/headerblock"
	"llmapi-logger/internal/storage"
)

// Capture version 2 on the unified write path (design C.3 to C.8). Each
// stage keeps a deep copy of its Header fields, taken when the stage starts,
// and of its Trailer fields when they arrive. Every write that inserts stage
// rows carries the whole block of the stages written so far, sealed for that
// write; a write whose block would be the same as the last one written leaves
// it out.

// blockShape identifies the content of a block without its ciphertext: one
// bit per stage that has a section and one per stage whose Trailers are in
// it. Header fields never change after the stage starts, so two blocks of the
// same shape have the same plaintext.
type blockShape uint8

func (shape blockShape) with(stage *stageCapture) blockShape {
	order := stageOrder(stage.name)
	if order < 0 || order > 3 {
		return shape
	}
	shape |= 1 << order
	if stage.hasTrailers {
		shape |= 1 << (4 + order)
	}
	return shape
}

// headerBlockLocked reports whether this session writes capture version 2.
func (session *Session) headerBlockLocked() bool {
	return session.manager != nil && session.manager.captureVersion == storage.CaptureVersion2
}

// snapshotHeadersLocked keeps the fields of one Header or Trailer map, with
// the loop legacy uses for per-value rows (headerblock.Snapshot). A stage's
// Trailers are captured once; legacy would reject a second group of them.
func (session *Session) snapshotHeadersLocked(stage *stageCapture, kind string, headers http.Header) {
	fields := headerblock.Snapshot(headers)
	if kind == storage.HeaderKindTrailer {
		if stage.hasTrailers {
			return
		}
		stage.trailerFields, stage.hasTrailers = fields, true
		return
	}
	stage.headerFields = fields
}

// hasStageRowLocked reports whether the stage's row is in the database or
// queued: written by BeginAudit or a checkpoint that was accepted. An
// inbound stage BeginAudit could not store has no row and never gets one.
func (session *Session) hasStageRowLocked(stage *stageCapture) bool {
	return stage.rowWritten && (stage.name != storage.StageRequestReceived || !session.inboundNotStored)
}

// sealBlockLocked seals the block of the given stages, which must be in stage
// order.
func (session *Session) sealBlockLocked(stages []*stageCapture) (*storage.HeaderBlock, error) {
	sections := make([]headerblock.Stage, 0, len(stages))
	for _, stage := range stages {
		sections = append(sections, headerblock.Stage{Name: stage.name, Headers: stage.headerFields, Trailers: stage.trailerFields})
	}
	block, err := headerblock.SealBlock(session.cipher, session.auditID, sections)
	if err != nil {
		return nil, err
	}
	return &block, nil
}

// blockForLocked returns the block of the given stages and its shape, or nil
// when the last block written has the same shape.
func (session *Session) blockForLocked(stages []*stageCapture) (*storage.HeaderBlock, blockShape, error) {
	var shape blockShape
	for _, stage := range stages {
		shape = shape.with(stage)
	}
	if session.blockWritten && shape == session.writtenBlock {
		return nil, shape, nil
	}
	block, err := session.sealBlockLocked(stages)
	return block, shape, err
}

func (session *Session) markBlockWrittenLocked(shape blockShape) {
	session.writtenBlock, session.blockWritten = shape, true
}

// stageContent is the content-type and content-encoding the stage row
// stores, chosen from its Header fields by the parser's rule.
func stageContent(stage *stageCapture) storage.StageContent {
	contentType, contentEncoding := headerblock.ContentHeaders(stage.headerFields)
	return storage.StageContent{Stage: stage.name, ContentType: contentType, ContentEncoding: contentEncoding}
}

// sealInboundLocked prepares the version 2 part of BeginAudit: the sealed
// User-Agent and a block holding the inbound stage alone. A block that cannot
// be sealed leaves the inbound stage to the next write; a User-Agent that
// cannot be sealed is not stored, and the stage is marked as a header that
// could not be encrypted.
func (session *Session) sealInboundLocked(stage *stageCapture, record *storage.AuditRecord) (blockShape, bool) {
	userAgent, err := headerblock.SealUserAgent(session.cipher, session.auditID, headerblock.UserAgentValues(stage.headerFields))
	if err != nil {
		session.markStageFaultLocked(stage, "header_encryption_failed")
	} else {
		record.UserAgentEnc = userAgent
	}
	block, err := session.sealBlockLocked([]*stageCapture{stage})
	if err != nil {
		return 0, false
	}
	content := stageContent(stage)
	record.Inbound.HeaderBlock = block
	record.Inbound.ContentType, record.Inbound.ContentEncoding = content.ContentType, content.ContentEncoding
	return blockShape(0).with(stage), true
}

// clearHeaderFieldsLocked drops the plaintext Header values once the commit
// has been answered.
func (session *Session) clearHeaderFieldsLocked() {
	for _, stage := range session.stages {
		for _, fields := range [2][]headerblock.Field{stage.headerFields, stage.trailerFields} {
			for _, field := range fields {
				for _, value := range field.Values {
					clear(value)
				}
			}
		}
	}
}
