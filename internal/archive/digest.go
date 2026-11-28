package archive

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"math"
	"slices"
	"strings"

	"llmapi-logger/internal/storage"
)

// recordDigestDomain starts the record digest input (E.2). It carries the
// format version: version 0 is the trial format.
const recordDigestDomain = "llmapi-logger/archive-record/v" + FormatVersion + "\x00"

// digestEncoder writes the E.1 notation. Every method appends to w.
type digestEncoder struct {
	w io.Writer
}

func (e digestEncoder) raw(data []byte) { _, _ = e.w.Write(data) }

func (e digestEncoder) u64(value uint64) {
	var buffer [8]byte
	binary.BigEndian.PutUint64(buffer[:], value)
	e.raw(buffer[:])
}

// B(x) = u64be(len(x)) || x
func (e digestEncoder) b(data []byte) {
	e.u64(uint64(len(data)))
	e.raw(data)
}

// T(s) = B(bytes of s)
func (e digestEncoder) t(text string) { e.b([]byte(text)) }

// I(v) = B(8-byte big-endian two's complement of v)
func (e digestEncoder) i(value int64) {
	var buffer [8]byte
	binary.BigEndian.PutUint64(buffer[:], uint64(value))
	e.b(buffer[:])
}

func (e digestEncoder) flag(value bool) {
	if value {
		e.i(1)
	} else {
		e.i(0)
	}
}

// N(e): 0x00 for NULL, otherwise 0x01 then e.
func (e digestEncoder) null() { e.raw([]byte{0}) }

func (e digestEncoder) present() { e.raw([]byte{1}) }

func (e digestEncoder) nText(value *string) {
	if value == nil {
		e.null()
		return
	}
	e.present()
	e.t(*value)
}

func (e digestEncoder) nInt(value *int64) {
	if value == nil {
		e.null()
		return
	}
	e.present()
	e.i(*value)
}

func (e digestEncoder) nFlag(value *bool) {
	if value == nil {
		e.null()
		return
	}
	e.present()
	e.flag(*value)
}

func (e digestEncoder) nBytes(value []byte) {
	if value == nil {
		e.null()
		return
	}
	e.present()
	e.b(value)
}

// H(p) = B(SHA-256(p)); the argument is the digest already computed.
func (e digestEncoder) h(digest [32]byte) { e.b(digest[:]) }

// L(n) = I(n)
func (e digestEncoder) l(count int) { e.i(int64(count)) }

// M(s) = T(s)
func (e digestEncoder) m(name string) { e.t(name) }

// V(value): 0x00 H(value) for a plain value, 0x01 I(length) B(value_fpr) for
// a credential.
func (e digestEncoder) v(value ProjectedValue) {
	if value.Omitted {
		e.raw([]byte{1})
		e.i(value.Length)
		e.b(value.Fingerprint[:])
		return
	}
	e.raw([]byte{0})
	e.h(sha256.Sum256([]byte(value.Value)))
}

// U: the projected Request-URI.
func (e digestEncoder) u(uri RequestURI) {
	e.m("request_uri")
	e.t(uri.Path)
	e.flag(uri.HasQuery)
	e.l(len(uri.Segments))
	for _, segment := range uri.Segments {
		if segment.Credential {
			e.raw([]byte{1})
			e.t(segment.RawName)
			e.flag(segment.HasEquals)
			e.i(segment.Length)
			e.b(segment.Fingerprint[:])
			continue
		}
		e.raw([]byte{0})
		e.t(segment.Raw)
	}
}

func sha256Sum(data []byte) [32]byte { return sha256.Sum256(data) }

// Digest returns the record digest of E.2. The record must be canonical
// (Canonicalize) and, if it has a turn, materialised (Turn.Materialize);
// otherwise it returns ErrFormat or ErrNotMaterialized.
func Digest(record *Record) ([32]byte, error) {
	digest := sha256.New()
	if err := writeDigestInput(digest, record); err != nil {
		return [32]byte{}, err
	}
	var sum [32]byte
	copy(sum[:], digest.Sum(nil))
	return sum, nil
}

func writeDigestInput(w io.Writer, record *Record) error {
	if err := record.CheckCanonical(); err != nil {
		return err
	}
	if record.Turn != nil && record.Turn.RequestRefs == nil && record.Turn.Row.RequestItemCount > 0 {
		return ErrNotMaterialized
	}
	parsedDigest, err := record.parsedJSONDigest()
	if err != nil {
		return err
	}
	e := digestEncoder{w: w}
	e.raw([]byte(recordDigestDomain))
	audit := record.Audit
	e.t(audit.AuditID)

	e.m("audit_records")
	e.i(audit.SchemaGeneration)
	e.i(audit.StartedAtNS)
	e.i(audit.EndedAtNS)
	e.t(audit.RouteID)
	e.t(audit.Protocol)
	e.t(audit.ParserName)
	e.t(audit.Method)
	e.t(audit.Path)
	e.u(audit.RequestURI)
	e.t(audit.Mode)
	e.nInt(audit.StatusCode)
	e.nInt(audit.TTFTNS)
	e.t(audit.ForwardStatus)
	e.t(audit.CaptureStatus)
	e.t(audit.ParseStatus)
	e.nText(audit.BlockedBy)
	e.nText(audit.BlockCode)
	e.nText(audit.ErrorCode)
	e.nText(audit.NewAPIRequestID)
	e.t(audit.CallerStatus)
	e.i(audit.CallerAttempts)
	e.nInt(audit.CallerNextAtNS)
	e.nInt(audit.CallerUpdatedAtNS)
	e.nBytes(audit.APIKeyFPR)
	e.i(audit.ParseSaveFailures)
	e.nInt(audit.ParseNextAtNS)
	e.i(audit.CaptureVersion)
	if audit.UserAgent == nil {
		e.null()
	} else {
		e.present()
		e.l(len(audit.UserAgent))
		for _, value := range audit.UserAgent {
			e.v(value)
		}
	}

	e.m("http_stages")
	e.l(len(record.Stages))
	for _, stage := range record.Stages {
		e.t(stage.Stage)
		e.t(stage.State)
		e.t(stage.Proto)
		e.t(stage.Method)
		e.t(stage.Host)
		e.nInt(int64Pointer(stage.StatusCode))
		e.nInt(stage.ContentLength)
		e.i(stage.StartedAtNS)
		e.nInt(stage.EndedAtNS)
		e.nText(stage.ErrorCode)
		e.nText(stage.ContentType)
		e.nText(stage.ContentEncoding)
	}

	headers := record.Headers
	e.m("headers")
	e.i(headers.CaptureVersion)
	e.flag(headers.BlockPresent)
	if headers.BlockStages == nil {
		e.null()
	} else {
		e.present()
		e.l(len(headers.BlockStages))
		for _, stage := range headers.BlockStages {
			e.t(stage)
		}
	}
	e.l(len(headers.Values))
	for _, value := range headers.Values {
		e.t(value.Stage)
		e.t(value.Kind)
		e.t(value.Name)
		e.i(value.ValueIndex)
		e.v(value.Value)
	}

	e.m("body_streams")
	e.l(len(record.Bodies))
	for _, body := range record.Bodies {
		e.t(body.Stage)
		e.t(body.SourceStage)
		e.i(body.ObservedLength)
		e.i(body.StoredLength)
		e.nBytes(body.SHA256)
		e.flag(body.HashComplete)
		e.flag(body.EOFSeen)
		e.t(body.State)
		e.t(body.RetentionState)
		e.nInt(body.FirstObservedAtNS)
		e.nInt(body.LastObservedAtNS)
		e.i(body.ChunkCount)
		e.i(body.StreamEventCount)
		e.flag(body.StreamTimelineComplete)
		e.nText(body.ErrorCode)
	}

	e.m("body_chunks")
	e.l(len(record.RawChunks))
	for _, chunk := range record.RawChunks {
		e.t(chunk.Stage)
		e.i(chunk.Seq)
		e.i(chunk.Offset)
		e.i(chunk.PlaintextLength)
		e.i(chunk.ObservedAtNS)
		e.h(chunk.SHA256)
	}

	e.m("stream_timelines")
	e.l(len(record.Timelines))
	for _, timeline := range record.Timelines {
		e.t(timeline.Stage)
		e.i(timeline.EventCount)
		e.nInt(timeline.FirstEventAtNS)
		e.nInt(timeline.LastEventAtNS)
		e.flag(timeline.Complete)
		e.i(timeline.PlaintextLength)
		if timeline.Plaintext == nil {
			e.null()
		} else {
			e.present()
			e.h(sha256.Sum256(timeline.Plaintext))
		}
	}

	e.m("parsed_results")
	if parsed := record.ParsedResult; parsed == nil {
		e.null()
	} else {
		e.present()
		e.t(parsed.ParserName)
		e.t(parsed.ParserVersion)
		e.t(parsed.Status)
		e.nText(parsed.RequestModel)
		e.nText(parsed.ResponseModel)
		e.nFlag(parsed.RequestedStream)
		e.nFlag(parsed.ObservedStream)
		e.nText(parsed.ResponseID)
		e.nInt(parsed.UsageInput)
		e.nInt(parsed.UsageOutput)
		e.nInt(parsed.UsageTotal)
		e.nText(parsed.ErrorType)
		e.nText(parsed.ErrorCode)
		e.nText(parsed.UpstreamErrorClass)
		e.nInt(parsed.MessageCount)
		e.nInt(parsed.ToolCallCount)
		e.nFlag(parsed.HasToolCall)
		if parsedDigest == nil {
			e.null()
		} else {
			e.present()
			e.h(*parsedDigest)
		}
		e.i(parsed.ParsedAtNS)
	}

	e.m("token_links")
	if link := record.TokenLink; link == nil {
		e.null()
	} else {
		e.present()
		e.i(link.NewAPIUserID)
		e.t(link.Username)
		e.i(link.NewAPITokenID)
		e.t(link.TokenName)
		e.i(link.LinkedAtNS)
		e.t(link.BillingState)
		e.nInt(link.Quota)
		if link.QuotaPerUnit == nil {
			e.null()
		} else {
			e.present()
			var bits [8]byte
			binary.BigEndian.PutUint64(bits[:], math.Float64bits(*link.QuotaPerUnit))
			e.b(bits[:])
		}
		e.nInt(link.BilledPromptTokens)
		e.nInt(link.BilledCompletionTokens)
		e.i(link.BillingAttempts)
	}

	e.m("turn")
	if turn := record.Turn; turn == nil {
		e.null()
	} else {
		e.present()
		row := turn.Row
		e.t(row.TurnID)
		e.t(row.ConversationID)
		e.nText(row.ParentTurnID)
		e.t(row.ParentBase)
		e.t(row.LinkReason)
		e.i(row.LinkConfidence)
		e.t(row.RequestLayout)
		e.t(row.ResponseLayout)
		e.b(row.RequestEnvelopeHash)
		e.b(row.ResponseEnvelopeHash)
		e.i(row.RequestItemCount)
		e.i(row.ResponseItemCount)
		e.b(row.RequestSequenceHash)
		e.b(row.ResponseSequenceHash)
		e.b(row.RequestReconstructionHash)
		e.b(row.ResponseReconstructionHash)
		e.t(row.ReconstructionStatus)
		e.nText(row.PreviousResponseID)
		e.nText(row.ResponseID)
		e.i(row.CreatedAtNS)
		e.m("request_refs")
		e.l(len(turn.RequestRefs))
		for _, ref := range turn.RequestRefs {
			e.t(ref.Slot)
			e.b(ref.ObjectHash)
			e.b(ref.SemanticHash)
		}
		e.m("response_items")
		e.l(len(turn.ResponseItems))
		for _, item := range turn.ResponseItems {
			e.i(item.Ordinal)
			e.t(item.Slot)
			e.b(item.ObjectHash)
			e.b(item.SemanticHash)
		}
		e.m("content_objects")
		e.l(len(turn.Objects))
		for _, object := range turn.Objects {
			e.b(object.Hash)
			e.b(object.SemanticHash)
			e.t(object.Kind)
			e.i(object.PlaintextLength)
		}
		e.m("binary_refs")
		e.l(len(turn.BinaryRefs))
		for _, ref := range turn.BinaryRefs {
			e.b(ref.ObjectHash)
			e.t(ref.JSONPointer)
			e.b(ref.BinaryHash)
			e.t(ref.MediaType)
			e.t(ref.Encoding)
		}
		e.m("external_refs")
		e.l(len(turn.ExternalRefs))
		for _, ref := range turn.ExternalRefs {
			e.b(ref.ObjectHash)
			e.t(ref.JSONPointer)
			e.t(ref.RefKind)
			e.b(ref.ValueHash)
			e.h(sha256.Sum256([]byte(ref.Value)))
		}
		e.m("binary_objects")
		e.l(len(turn.Binaries))
		for _, binary := range turn.Binaries {
			e.b(binary.Hash)
			e.t(binary.MediaType)
			e.i(binary.PlaintextLength)
		}
	}

	e.m("conversation")
	if conversation := record.Conversation; conversation == nil {
		e.null()
	} else {
		e.present()
		e.t(conversation.ConversationID)
		e.t(conversation.Protocol)
		e.nBytes(conversation.KeyHash)
		e.i(conversation.CreatedAtNS)
	}

	e.m("audit_project_identity")
	if identity := record.ProjectIdentity; identity == nil {
		e.null()
	} else {
		e.present()
		e.i(identity.IdentityVersion)
		e.i(identity.ExtractedAtNS)
		e.t(identity.Source)
		e.flag(identity.BodyScanned)
		e.nBytes(identity.IdentityFPR)
		e.nBytes(identity.RemoteFPR)
		e.nBytes(identity.RepoRootFPR)
		e.nBytes(identity.CwdFPR)
		if identity.Identity == nil {
			e.null()
		} else {
			e.present()
			e.h(sha256.Sum256(identity.Identity))
		}
	}

	e.m("integrity_events")
	e.l(len(record.IntegrityEvents))
	for _, event := range record.IntegrityEvents {
		e.i(event.Sequence)
		e.t(event.EventType)
		e.nBytes(event.PreviousMAC)
		e.b(event.PayloadDigest)
		e.b(event.EventMAC)
		e.i(event.CreatedAtNS)
	}
	return nil
}

// parsedJSONDigest is the SHA-256 of the opened parsed_json, from the bytes
// when the record has them and from the line's reference otherwise; nil for
// NULL.
func (record *Record) parsedJSONDigest() (*[32]byte, error) {
	parsed := record.ParsedResult
	if parsed == nil {
		return nil, nil
	}
	if parsed.ParsedJSON != nil && parsed.ParsedJSONRef != nil {
		return nil, formatError("parsed_json given both inline and by reference")
	}
	if parsed.ParsedJSONRef != nil {
		sum := parsed.ParsedJSONRef.SHA256
		return &sum, nil
	}
	if parsed.ParsedJSON == nil {
		return nil, nil
	}
	sum := sha256.Sum256(parsed.ParsedJSON)
	return &sum, nil
}

func int64Pointer(value *int) *int64 {
	if value == nil {
		return nil
	}
	converted := int64(*value)
	return &converted
}

// Canonicalize sorts every list of the record into the order E.2 and C.2
// define: stages, bodies and timelines by stage order; header values in the
// flat order of headerblock.Flatten; raw chunks by stage order and seq;
// response items by ordinal; context operations by op_index; objects and
// binaries by hash bytes; binary refs by (object_hash, json_pointer,
// binary_hash); external refs by (object_hash, json_pointer, ref_kind);
// integrity events by sequence. The materialised request refs and the
// User-Agent values keep their order. It then checks the record with
// CheckCanonical.
func (record *Record) Canonicalize() error {
	sortStable(record.Stages, func(left, right Stage) int {
		return cmp.Compare(storage.StageOrder(left.Stage), storage.StageOrder(right.Stage))
	})
	sortStable(record.Headers.Values, compareHeaderValues)
	sortStable(record.Headers.BlockStages, func(left, right string) int {
		return cmp.Compare(storage.StageOrder(left), storage.StageOrder(right))
	})
	sortStable(record.Bodies, func(left, right storage.BodyStream) int {
		return cmp.Compare(storage.StageOrder(left.Stage), storage.StageOrder(right.Stage))
	})
	sortStable(record.RawChunks, compareRawChunks)
	sortStable(record.Timelines, func(left, right Timeline) int {
		return cmp.Compare(storage.StageOrder(left.Stage), storage.StageOrder(right.Stage))
	})
	if turn := record.Turn; turn != nil {
		sortStable(turn.Context.Ops, func(left, right ContextOp) int { return cmp.Compare(left.OpIndex, right.OpIndex) })
		sortStable(turn.ResponseItems, func(left, right ResponseItem) int { return cmp.Compare(left.Ordinal, right.Ordinal) })
		sortStable(turn.Objects, func(left, right ObjectMeta) int { return bytes.Compare(left.Hash, right.Hash) })
		sortStable(turn.BinaryRefs, compareBinaryRefs)
		sortStable(turn.ExternalRefs, compareExternalRefs)
		sortStable(turn.Binaries, func(left, right BinaryMeta) int { return bytes.Compare(left.Hash, right.Hash) })
	}
	sortStable(record.IntegrityEvents, func(left, right IntegrityEvent) int { return cmp.Compare(left.Sequence, right.Sequence) })
	return record.CheckCanonical()
}

// CheckCanonical reports ErrFormat unless every list is strictly in the
// order Canonicalize produces (no two entries with the same key), every
// stage name is known, and the head fields agree: Headers.CaptureVersion
// equals Audit.CaptureVersion, block stages only with a block, a non-empty
// user_agent list when present, a known request context form with only its
// own list, and the turn's conversation equals the conversation row's.
func (record *Record) CheckCanonical() error {
	for _, stage := range record.Stages {
		if storage.StageOrder(stage.Stage) < 0 {
			return formatError("unknown stage %q", stage.Stage)
		}
	}
	if !strictlySorted(record.Stages, func(left, right Stage) int {
		return cmp.Compare(storage.StageOrder(left.Stage), storage.StageOrder(right.Stage))
	}) {
		return formatError("http_stages not in stage order")
	}
	for _, value := range record.Headers.Values {
		if storage.StageOrder(value.Stage) < 0 || (value.Kind != storage.HeaderKindHeader && value.Kind != storage.HeaderKindTrailer) {
			return formatError("header value with unknown stage or kind")
		}
	}
	if !strictlySorted(record.Headers.Values, compareHeaderValues) {
		return formatError("header values not in flat order")
	}
	for _, stage := range record.Headers.BlockStages {
		if storage.StageOrder(stage) < 0 {
			return formatError("unknown block stage %q", stage)
		}
	}
	if !strictlySorted(record.Headers.BlockStages, func(left, right string) int {
		return cmp.Compare(storage.StageOrder(left), storage.StageOrder(right))
	}) {
		return formatError("block stages not in stage order")
	}
	if record.Headers.CaptureVersion != record.Audit.CaptureVersion {
		return formatError("headers capture_version differs from audit_records")
	}
	if record.Headers.BlockStages != nil && !record.Headers.BlockPresent {
		return formatError("block stages without a block")
	}
	if record.Audit.UserAgent != nil && len(record.Audit.UserAgent) == 0 {
		return formatError("empty user_agent list")
	}
	for _, body := range record.Bodies {
		if storage.StageOrder(body.Stage) < 0 || storage.StageOrder(body.SourceStage) < 0 {
			return formatError("body with unknown stage")
		}
	}
	if !strictlySorted(record.Bodies, func(left, right storage.BodyStream) int {
		return cmp.Compare(storage.StageOrder(left.Stage), storage.StageOrder(right.Stage))
	}) {
		return formatError("body_streams not in stage order")
	}
	for _, chunk := range record.RawChunks {
		if storage.StageOrder(chunk.Stage) < 0 {
			return formatError("raw chunk with unknown stage")
		}
	}
	if !strictlySorted(record.RawChunks, compareRawChunks) {
		return formatError("raw_chunks not in (stage, seq) order")
	}
	for _, timeline := range record.Timelines {
		if storage.StageOrder(timeline.Stage) < 0 {
			return formatError("timeline with unknown stage")
		}
	}
	if !strictlySorted(record.Timelines, func(left, right Timeline) int {
		return cmp.Compare(storage.StageOrder(left.Stage), storage.StageOrder(right.Stage))
	}) {
		return formatError("stream_timelines not in stage order")
	}
	if turn := record.Turn; turn != nil {
		if !strictlySorted(turn.Context.Ops, func(left, right ContextOp) int { return cmp.Compare(left.OpIndex, right.OpIndex) }) {
			return formatError("context operations not in op_index order")
		}
		if !strictlySorted(turn.ResponseItems, func(left, right ResponseItem) int { return cmp.Compare(left.Ordinal, right.Ordinal) }) {
			return formatError("response items not in ordinal order")
		}
		if !strictlySorted(turn.Objects, func(left, right ObjectMeta) int { return bytes.Compare(left.Hash, right.Hash) }) {
			return formatError("turn objects not in hash order")
		}
		if !strictlySorted(turn.BinaryRefs, compareBinaryRefs) {
			return formatError("binary refs not in key order")
		}
		if !strictlySorted(turn.ExternalRefs, compareExternalRefs) {
			return formatError("external refs not in key order")
		}
		if !strictlySorted(turn.Binaries, func(left, right BinaryMeta) int { return bytes.Compare(left.Hash, right.Hash) }) {
			return formatError("binaries not in hash order")
		}
		switch turn.Context.Form {
		case ContextDelta:
			if turn.Context.Refs != nil {
				return formatError("delta context with refs")
			}
		case ContextMaterialized:
			if turn.Context.Ops != nil {
				return formatError("materialized context with ops")
			}
		default:
			return formatError("unknown request context form %q", turn.Context.Form)
		}
		if record.Conversation != nil && record.Conversation.ConversationID != turn.Row.ConversationID {
			return formatError("conversation row differs from the turn's conversation")
		}
	}
	if !strictlySorted(record.IntegrityEvents, func(left, right IntegrityEvent) int { return cmp.Compare(left.Sequence, right.Sequence) }) {
		return formatError("integrity events not in sequence order")
	}
	return nil
}

func compareHeaderValues(left, right HeaderValue) int {
	return cmp.Or(
		cmp.Compare(storage.StageOrder(left.Stage), storage.StageOrder(right.Stage)),
		strings.Compare(left.Kind, right.Kind),
		strings.Compare(left.Name, right.Name),
		cmp.Compare(left.ValueIndex, right.ValueIndex),
	)
}

func compareRawChunks(left, right RawChunk) int {
	return cmp.Or(cmp.Compare(storage.StageOrder(left.Stage), storage.StageOrder(right.Stage)), cmp.Compare(left.Seq, right.Seq))
}

func compareBinaryRefs(left, right BinaryRef) int {
	return cmp.Or(bytes.Compare(left.ObjectHash, right.ObjectHash), strings.Compare(left.JSONPointer, right.JSONPointer), bytes.Compare(left.BinaryHash, right.BinaryHash))
}

func compareExternalRefs(left, right ExternalRef) int {
	return cmp.Or(bytes.Compare(left.ObjectHash, right.ObjectHash), strings.Compare(left.JSONPointer, right.JSONPointer), strings.Compare(left.RefKind, right.RefKind))
}

func compareInt(left, right int64) int { return cmp.Compare(left, right) }

func sortStable[T any](values []T, compare func(T, T) int) { slices.SortStableFunc(values, compare) }

func strictlySorted[T any](values []T, compare func(T, T) int) bool {
	for index := 1; index < len(values); index++ {
		if compare(values[index-1], values[index]) >= 0 {
			return false
		}
	}
	return true
}
