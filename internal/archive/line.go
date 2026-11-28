package archive

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"unicode/utf8"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/storage"
)

// ParsedJSONInlineLimit is the largest parsed_json a line carries itself;
// a longer one goes to the objects file in parts of at most this many bytes
// (C.2).
const ParsedJSONInlineLimit = 1 << 20

// Objects file entry types (C.5) and the gap entry type (C.6).
const (
	EntryContentObject  = "content_object"
	EntryBinaryObject   = "binary_object"
	EntryRawChunk       = "raw_chunk"
	EntryParsedJSONPart = "parsed_json_part"
	EntryGap            = "gap"
)

var lineKeys = []string{
	"type", "audit_id", "conversation_id", "protocol", "started_at_ns", "ended_at_ns", "revision",
	"audit_records", "http_stages", "headers", "body_streams", "raw_chunks", "stream_timelines",
	"parsed_results", "token_links", "turn", "conversation", "audit_project_identity",
	"integrity_events", "record_digest",
}

var auditKeys = []string{
	"audit_id", "schema_generation", "started_at_ns", "ended_at_ns", "route_id", "protocol",
	"parser_name", "method", "path", "request_uri", "mode", "status_code", "ttft_ns",
	"forward_status", "capture_status", "parse_status", "blocked_by", "block_code", "error_code",
	"newapi_request_id", "caller_status", "caller_attempts", "caller_next_at_ns",
	"caller_updated_at_ns", "api_key_fpr", "parse_save_failures", "parse_next_at_ns",
	"capture_version", "user_agent",
}

// ParsedJSONPart is one parsed_json_part entry of the objects file.
type ParsedJSONPart struct {
	AuditID string
	Part    int64
	Data    []byte
}

// ContentObject is one content_object entry of the objects file: Data is
// the canonical JSON text the object_hash is taken over.
type ContentObject struct {
	Hash            []byte
	SemanticHash    []byte
	Kind            string
	PlaintextLength int64
	CreatedAtNS     int64
	Data            []byte
}

// BinaryObject is one binary_object entry of the objects file.
type BinaryObject struct {
	Hash            []byte
	MediaType       string
	PlaintextLength int64
	CreatedAtNS     int64
	Data            []byte
}

// RawChunkData is one raw_chunk entry of the objects file: the plaintext of
// the raw chunk (stage, seq) of one audit.
type RawChunkData struct {
	AuditID string
	Stage   string
	Seq     int64
	Data    []byte
}

// ObjectEntry is one decoded objects file line; exactly one field is set.
type ObjectEntry struct {
	Content        *ContentObject
	Binary         *BinaryObject
	RawChunk       *RawChunkData
	ParsedJSONPart *ParsedJSONPart
}

// Gap is one audit_gaps row, a line of the gaps file.
type Gap struct {
	ID           int64
	StartedAtNS  int64
	EndedAtNS    int64
	Reason       string
	RequestCount int64
	Detail       string
	CreatedAtNS  int64
}

// EncodeLine encodes a canonical, materialised record as one line of the
// lines file, without the trailing newline, and returns its record digest.
// A parsed_json over ParsedJSONInlineLimit is written as parsed_json_ref and
// returned as parts for the objects file; a record that already carries only
// a ParsedJSONRef is written with that reference and no parts.
func EncodeLine(record *Record) ([]byte, [32]byte, []ParsedJSONPart, error) {
	digest, err := Digest(record)
	if err != nil {
		return nil, [32]byte{}, nil, err
	}
	var parts []ParsedJSONPart
	parsed := jsonNull
	if record.ParsedResult != nil {
		var ref *ParsedJSONRef
		inline := record.ParsedResult.ParsedJSON
		if len(inline) > ParsedJSONInlineLimit {
			var split ParsedJSONRef
			split, parts = SplitParsedJSON(record.Audit.AuditID, inline)
			ref, inline = &split, nil
		} else if record.ParsedResult.ParsedJSONRef != nil {
			ref = record.ParsedResult.ParsedJSONRef
		}
		parsed = encodeParsedResult(record.ParsedResult, inline, ref)
	}
	line := object(
		member{"type", jsonString("audit")},
		member{"audit_id", jText(record.Audit.AuditID)},
		member{"conversation_id", jNText(record.ConversationID())},
		member{"protocol", jText(record.Audit.Protocol)},
		member{"started_at_ns", jInt(record.Audit.StartedAtNS)},
		member{"ended_at_ns", jInt(record.Audit.EndedAtNS)},
		member{"revision", jInt(record.Revision)},
		member{"audit_records", encodeAudit(record.Audit)},
		member{"http_stages", encodeStages(record.Stages)},
		member{"headers", encodeHeaders(record.Headers)},
		member{"body_streams", encodeBodies(record.Bodies)},
		member{"raw_chunks", encodeRawChunks(record.RawChunks)},
		member{"stream_timelines", encodeTimelines(record.Timelines)},
		member{"parsed_results", parsed},
		member{"token_links", encodeTokenLink(record.TokenLink)},
		member{"turn", encodeTurn(record.Turn)},
		member{"conversation", encodeConversation(record.Conversation)},
		member{"audit_project_identity", encodeIdentity(record.ProjectIdentity)},
		member{"integrity_events", encodeEvents(record.IntegrityEvents)},
		member{"record_digest", jHex(digest[:])},
	)
	return line, digest, parts, nil
}

// SplitParsedJSON splits a parsed_json into parts of at most
// ParsedJSONInlineLimit bytes. A cut that would fall inside a UTF-8 sequence
// moves back to the start of that sequence (at most three bytes); bytes that
// are not valid UTF-8 never move a cut.
func SplitParsedJSON(auditID string, data []byte) (ParsedJSONRef, []ParsedJSONPart) {
	ref := ParsedJSONRef{SHA256: sha256Sum(data), Length: int64(len(data))}
	var parts []ParsedJSONPart
	for start := 0; start < len(data); {
		end := min(start+ParsedJSONInlineLimit, len(data))
		if end < len(data) {
			cut := end
			for back := 0; back < utf8.UTFMax-1 && cut > start && !utf8.RuneStart(data[cut]); back++ {
				cut--
			}
			if utf8.RuneStart(data[cut]) && cut > start && utf8.FullRune(data[cut:]) {
				end = cut
			}
		}
		parts = append(parts, ParsedJSONPart{AuditID: auditID, Part: int64(len(parts)), Data: bytes.Clone(data[start:end])})
		start = end
	}
	ref.Parts = int64(len(parts))
	return ref, parts
}

// JoinParsedJSON concatenates the parts of a split parsed_json, which must
// be the reference's parts numbered from 0 in order, and checks the result
// against the reference's length and SHA-256.
func JoinParsedJSON(ref ParsedJSONRef, parts []ParsedJSONPart) ([]byte, error) {
	if int64(len(parts)) != ref.Parts {
		return nil, formatError("parsed_json has %d parts, the reference says %d", len(parts), ref.Parts)
	}
	joined := make([]byte, 0, ref.Length)
	for index, part := range parts {
		if part.Part != int64(index) || len(part.Data) == 0 || len(part.Data) > ParsedJSONInlineLimit {
			return nil, formatError("parsed_json part %d out of order or out of bounds", index)
		}
		joined = append(joined, part.Data...)
	}
	if int64(len(joined)) != ref.Length || sha256Sum(joined) != ref.SHA256 {
		return nil, ErrIntegrity
	}
	return joined, nil
}

func encodeProjected(value ProjectedValue, prefix ...member) []byte {
	if value.Omitted {
		return object(append(prefix,
			member{"value_omitted", jsonString(OmittedCredential)},
			member{"length", jInt(value.Length)},
			member{"value_fpr", jHex(value.Fingerprint[:])})...)
	}
	return object(append(prefix, member{"value", jText(value.Value)})...)
}

func encodeRequestURI(uri RequestURI) []byte {
	segments := make([][]byte, 0, len(uri.Segments))
	for _, segment := range uri.Segments {
		if segment.Credential {
			segments = append(segments, object(
				member{"raw_name", jText(segment.RawName)},
				member{"has_equals", jBool(segment.HasEquals)},
				member{"value_omitted", jsonString(OmittedCredential)},
				member{"length", jInt(segment.Length)},
				member{"value_fpr", jHex(segment.Fingerprint[:])}))
			continue
		}
		segments = append(segments, object(member{"raw", jText(segment.Raw)}))
	}
	return object(
		member{"path", jText(uri.Path)},
		member{"has_query", jBool(uri.HasQuery)},
		member{"segments", array(segments)})
}

func encodeAudit(audit AuditRow) []byte {
	userAgent := jsonNull
	if audit.UserAgent != nil {
		items := make([][]byte, 0, len(audit.UserAgent))
		for _, value := range audit.UserAgent {
			items = append(items, encodeProjected(value))
		}
		userAgent = array(items)
	}
	return object(
		member{"audit_id", jText(audit.AuditID)},
		member{"schema_generation", jInt(audit.SchemaGeneration)},
		member{"started_at_ns", jInt(audit.StartedAtNS)},
		member{"ended_at_ns", jInt(audit.EndedAtNS)},
		member{"route_id", jText(audit.RouteID)},
		member{"protocol", jText(audit.Protocol)},
		member{"parser_name", jText(audit.ParserName)},
		member{"method", jText(audit.Method)},
		member{"path", jText(audit.Path)},
		member{"request_uri", encodeRequestURI(audit.RequestURI)},
		member{"mode", jText(audit.Mode)},
		member{"status_code", jNInt(audit.StatusCode)},
		member{"ttft_ns", jNInt(audit.TTFTNS)},
		member{"forward_status", jText(audit.ForwardStatus)},
		member{"capture_status", jText(audit.CaptureStatus)},
		member{"parse_status", jText(audit.ParseStatus)},
		member{"blocked_by", jNText(audit.BlockedBy)},
		member{"block_code", jNText(audit.BlockCode)},
		member{"error_code", jNText(audit.ErrorCode)},
		member{"newapi_request_id", jNText(audit.NewAPIRequestID)},
		member{"caller_status", jText(audit.CallerStatus)},
		member{"caller_attempts", jInt(audit.CallerAttempts)},
		member{"caller_next_at_ns", jNInt(audit.CallerNextAtNS)},
		member{"caller_updated_at_ns", jNInt(audit.CallerUpdatedAtNS)},
		member{"api_key_fpr", jNHex(audit.APIKeyFPR)},
		member{"parse_save_failures", jInt(audit.ParseSaveFailures)},
		member{"parse_next_at_ns", jNInt(audit.ParseNextAtNS)},
		member{"capture_version", jInt(audit.CaptureVersion)},
		member{"user_agent", userAgent},
	)
}

func encodeStages(stages []Stage) []byte {
	items := make([][]byte, 0, len(stages))
	for _, stage := range stages {
		items = append(items, object(
			member{"stage", jText(stage.Stage)},
			member{"state", jText(stage.State)},
			member{"proto", jText(stage.Proto)},
			member{"method", jText(stage.Method)},
			member{"host", jText(stage.Host)},
			member{"status_code", jNInt(int64Pointer(stage.StatusCode))},
			member{"content_length", jNInt(stage.ContentLength)},
			member{"started_at_ns", jInt(stage.StartedAtNS)},
			member{"ended_at_ns", jNInt(stage.EndedAtNS)},
			member{"error_code", jNText(stage.ErrorCode)},
			member{"content_type", jNText(stage.ContentType)},
			member{"content_encoding", jNText(stage.ContentEncoding)},
		))
	}
	return array(items)
}

func encodeHeaders(headers Headers) []byte {
	stages := jsonNull
	if headers.BlockStages != nil {
		stages = jStrings(headers.BlockStages)
	}
	values := make([][]byte, 0, len(headers.Values))
	for _, value := range headers.Values {
		values = append(values, encodeProjected(value.Value,
			member{"stage", jText(value.Stage)},
			member{"kind", jText(value.Kind)},
			member{"name", jText(value.Name)},
			member{"value_index", jInt(value.ValueIndex)}))
	}
	return object(
		member{"capture_version", jInt(headers.CaptureVersion)},
		member{"block_present", jBool(headers.BlockPresent)},
		member{"block_stages", stages},
		member{"values", array(values)},
	)
}

func encodeBodies(bodies []storage.BodyStream) []byte {
	items := make([][]byte, 0, len(bodies))
	for _, body := range bodies {
		items = append(items, object(
			member{"stage", jText(body.Stage)},
			member{"source_stage", jText(body.SourceStage)},
			member{"observed_length", jInt(body.ObservedLength)},
			member{"stored_length", jInt(body.StoredLength)},
			member{"sha256", jNHex(body.SHA256)},
			member{"hash_complete", jFlag(body.HashComplete)},
			member{"eof_seen", jFlag(body.EOFSeen)},
			member{"state", jText(body.State)},
			member{"retention_state", jText(body.RetentionState)},
			member{"first_observed_at_ns", jNInt(body.FirstObservedAtNS)},
			member{"last_observed_at_ns", jNInt(body.LastObservedAtNS)},
			member{"chunk_count", jInt(body.ChunkCount)},
			member{"stream_event_count", jInt(body.StreamEventCount)},
			member{"stream_timeline_complete", jFlag(body.StreamTimelineComplete)},
			member{"error_code", jNText(body.ErrorCode)},
		))
	}
	return array(items)
}

func encodeRawChunks(chunks []RawChunk) []byte {
	items := make([][]byte, 0, len(chunks))
	for _, chunk := range chunks {
		items = append(items, object(
			member{"stage", jText(chunk.Stage)},
			member{"seq", jInt(chunk.Seq)},
			member{"offset", jInt(chunk.Offset)},
			member{"plaintext_length", jInt(chunk.PlaintextLength)},
			member{"observed_at_ns", jInt(chunk.ObservedAtNS)},
			member{"sha256", jHex(chunk.SHA256[:])},
		))
	}
	return array(items)
}

func encodeTimelines(timelines []Timeline) []byte {
	items := make([][]byte, 0, len(timelines))
	for _, timeline := range timelines {
		items = append(items, object(
			member{"stage", jText(timeline.Stage)},
			member{"event_count", jInt(timeline.EventCount)},
			member{"first_event_at_ns", jNInt(timeline.FirstEventAtNS)},
			member{"last_event_at_ns", jNInt(timeline.LastEventAtNS)},
			member{"timeline_complete", jFlag(timeline.Complete)},
			member{"plaintext_length", jInt(timeline.PlaintextLength)},
			member{"timeline_b64", jNB64(timeline.Plaintext)},
		))
	}
	return array(items)
}

func encodeParsedResult(parsed *ParsedResult, inline []byte, ref *ParsedJSONRef) []byte {
	parsedJSON := jsonNull
	if inline != nil {
		parsedJSON = jTextBytes(inline)
	}
	parsedRef := jsonNull
	if ref != nil {
		parsedRef = object(
			member{"sha256", jHex(ref.SHA256[:])},
			member{"length", jInt(ref.Length)},
			member{"parts", jInt(ref.Parts)})
	}
	return object(
		member{"parser_name", jText(parsed.ParserName)},
		member{"parser_version", jText(parsed.ParserVersion)},
		member{"status", jText(parsed.Status)},
		member{"request_model", jNText(parsed.RequestModel)},
		member{"response_model", jNText(parsed.ResponseModel)},
		member{"requested_stream", jNFlag(parsed.RequestedStream)},
		member{"observed_stream", jNFlag(parsed.ObservedStream)},
		member{"response_id", jNText(parsed.ResponseID)},
		member{"usage_input", jNInt(parsed.UsageInput)},
		member{"usage_output", jNInt(parsed.UsageOutput)},
		member{"usage_total", jNInt(parsed.UsageTotal)},
		member{"error_type", jNText(parsed.ErrorType)},
		member{"error_code", jNText(parsed.ErrorCode)},
		member{"upstream_error_class", jNText(parsed.UpstreamErrorClass)},
		member{"message_count", jNInt(parsed.MessageCount)},
		member{"tool_call_count", jNInt(parsed.ToolCallCount)},
		member{"has_tool_call", jNFlag(parsed.HasToolCall)},
		member{"parsed_json", parsedJSON},
		member{"parsed_json_ref", parsedRef},
		member{"parsed_at_ns", jInt(parsed.ParsedAtNS)},
	)
}

func encodeTokenLink(link *TokenLink) []byte {
	if link == nil {
		return jsonNull
	}
	return object(
		member{"newapi_user_id", jInt(link.NewAPIUserID)},
		member{"username", jText(link.Username)},
		member{"newapi_token_id", jInt(link.NewAPITokenID)},
		member{"token_name", jText(link.TokenName)},
		member{"linked_at_ns", jInt(link.LinkedAtNS)},
		member{"billing_state", jText(link.BillingState)},
		member{"quota", jNInt(link.Quota)},
		member{"quota_per_unit", jNFloat(link.QuotaPerUnit)},
		member{"billed_prompt_tokens", jNInt(link.BilledPromptTokens)},
		member{"billed_completion_tokens", jNInt(link.BilledCompletionTokens)},
		member{"billing_attempts", jInt(link.BillingAttempts)},
	)
}

func encodeRef(ref auditmodel.ObjectRef) []byte {
	return object(
		member{"slot", jText(ref.Slot)},
		member{"object_hash", jHex(ref.ObjectHash)},
		member{"semantic_hash", jHex(ref.SemanticHash)})
}

func encodeTurn(turn *Turn) []byte {
	if turn == nil {
		return jsonNull
	}
	row := turn.Row
	var context []byte
	if turn.Context.Form == ContextMaterialized {
		refs := make([][]byte, 0, len(turn.Context.Refs))
		for _, ref := range turn.Context.Refs {
			refs = append(refs, encodeRef(ref))
		}
		context = object(member{"form", jsonString(ContextMaterialized)}, member{"refs", array(refs)})
	} else {
		ops := make([][]byte, 0, len(turn.Context.Ops))
		for _, op := range turn.Context.Ops {
			ops = append(ops, object(
				member{"op_index", jInt(op.OpIndex)},
				member{"operation", jText(op.Operation)},
				member{"item_count", jInt(op.ItemCount)},
				member{"slot", jNText(op.Slot)},
				member{"object_hash", jNHex(op.ObjectHash)},
				member{"semantic_hash", jNHex(op.SemanticHash)}))
		}
		context = object(member{"form", jsonString(ContextDelta)}, member{"ops", array(ops)})
	}
	responses := make([][]byte, 0, len(turn.ResponseItems))
	for _, item := range turn.ResponseItems {
		responses = append(responses, object(
			member{"ordinal", jInt(item.Ordinal)},
			member{"slot", jText(item.Slot)},
			member{"object_hash", jHex(item.ObjectHash)},
			member{"semantic_hash", jHex(item.SemanticHash)}))
	}
	objects := make([][]byte, 0, len(turn.Objects))
	for _, object_ := range turn.Objects {
		objects = append(objects, object(
			member{"object_hash", jHex(object_.Hash)},
			member{"semantic_hash", jHex(object_.SemanticHash)},
			member{"object_kind", jText(object_.Kind)},
			member{"plaintext_length", jInt(object_.PlaintextLength)}))
	}
	binaryRefs := make([][]byte, 0, len(turn.BinaryRefs))
	for _, ref := range turn.BinaryRefs {
		binaryRefs = append(binaryRefs, object(
			member{"object_hash", jHex(ref.ObjectHash)},
			member{"json_pointer", jText(ref.JSONPointer)},
			member{"binary_hash", jHex(ref.BinaryHash)},
			member{"media_type", jText(ref.MediaType)},
			member{"encoding", jText(ref.Encoding)}))
	}
	externalRefs := make([][]byte, 0, len(turn.ExternalRefs))
	for _, ref := range turn.ExternalRefs {
		externalRefs = append(externalRefs, object(
			member{"object_hash", jHex(ref.ObjectHash)},
			member{"json_pointer", jText(ref.JSONPointer)},
			member{"ref_kind", jText(ref.RefKind)},
			member{"value_hash", jHex(ref.ValueHash)},
			member{"value", jText(ref.Value)}))
	}
	binaries := make([][]byte, 0, len(turn.Binaries))
	for _, binary := range turn.Binaries {
		binaries = append(binaries, object(
			member{"binary_hash", jHex(binary.Hash)},
			member{"media_type", jText(binary.MediaType)},
			member{"plaintext_length", jInt(binary.PlaintextLength)}))
	}
	return object(
		member{"turns", object(
			member{"turn_id", jText(row.TurnID)},
			member{"conversation_id", jText(row.ConversationID)},
			member{"parent_turn_id", jNText(row.ParentTurnID)},
			member{"parent_base", jText(row.ParentBase)},
			member{"link_reason", jText(row.LinkReason)},
			member{"link_confidence", jInt(row.LinkConfidence)},
			member{"request_layout", jText(row.RequestLayout)},
			member{"response_layout", jText(row.ResponseLayout)},
			member{"request_envelope_hash", jHex(row.RequestEnvelopeHash)},
			member{"response_envelope_hash", jHex(row.ResponseEnvelopeHash)},
			member{"request_item_count", jInt(row.RequestItemCount)},
			member{"response_item_count", jInt(row.ResponseItemCount)},
			member{"request_sequence_hash", jHex(row.RequestSequenceHash)},
			member{"response_sequence_hash", jHex(row.ResponseSequenceHash)},
			member{"request_reconstruction_hash", jHex(row.RequestReconstructionHash)},
			member{"response_reconstruction_hash", jHex(row.ResponseReconstructionHash)},
			member{"reconstruction_status", jText(row.ReconstructionStatus)},
			member{"previous_response_id", jNText(row.PreviousResponseID)},
			member{"response_id", jNText(row.ResponseID)},
			member{"created_at_ns", jInt(row.CreatedAtNS)},
		)},
		member{"request_context", context},
		member{"response_items", array(responses)},
		member{"objects", array(objects)},
		member{"binary_refs", array(binaryRefs)},
		member{"external_refs", array(externalRefs)},
		member{"binaries", array(binaries)},
	)
}

func encodeConversation(conversation *Conversation) []byte {
	if conversation == nil {
		return jsonNull
	}
	return object(
		member{"conversation_id", jText(conversation.ConversationID)},
		member{"protocol", jText(conversation.Protocol)},
		member{"key_hash", jNHex(conversation.KeyHash)},
		member{"created_at_ns", jInt(conversation.CreatedAtNS)},
	)
}

func encodeIdentity(identity *ProjectIdentity) []byte {
	if identity == nil {
		return jsonNull
	}
	text := jsonNull
	if identity.Identity != nil {
		text = jTextBytes(identity.Identity)
	}
	return object(
		member{"identity_version", jInt(identity.IdentityVersion)},
		member{"extracted_at_ns", jInt(identity.ExtractedAtNS)},
		member{"source", jText(identity.Source)},
		member{"body_scanned", jFlag(identity.BodyScanned)},
		member{"identity_fpr", jNHex(identity.IdentityFPR)},
		member{"remote_fpr", jNHex(identity.RemoteFPR)},
		member{"repo_root_fpr", jNHex(identity.RepoRootFPR)},
		member{"cwd_fpr", jNHex(identity.CwdFPR)},
		member{"identity", text},
	)
}

func encodeEvents(events []IntegrityEvent) []byte {
	items := make([][]byte, 0, len(events))
	for _, event := range events {
		items = append(items, object(
			member{"sequence", jInt(event.Sequence)},
			member{"event_type", jText(event.EventType)},
			member{"previous_mac", jNHex(event.PreviousMAC)},
			member{"payload_digest", jHex(event.PayloadDigest)},
			member{"event_mac", jHex(event.EventMAC)},
			member{"created_at_ns", jInt(event.CreatedAtNS)},
		))
	}
	return array(items)
}

// DecodeLine decodes one line of the lines file and returns the record and
// the record_digest the line carries. It rejects unknown, missing and
// duplicate keys, non-canonical values, lists out of canonical order, and a
// line head that disagrees with the rows. A materialized-form turn has its
// RequestRefs set; a delta-form turn needs Turn.Materialize before Digest.
// A split parsed_json is returned as ParsedJSONRef with ParsedJSON nil.
func DecodeLine(line []byte) (*Record, [32]byte, error) {
	if !utf8.Valid(line) {
		return nil, [32]byte{}, formatError("line is not valid UTF-8")
	}
	f, err := decodeObject(line, lineKeys...)
	if err != nil {
		return nil, [32]byte{}, err
	}
	e := &errs{}
	if kind := e.str(f.rawString("type")); e.err == nil && kind != "audit" {
		return nil, [32]byte{}, formatError("line type %q", kind)
	}
	record := &Record{}
	headAuditID := e.str(f.text("audit_id"))
	headConversation := e.nstr(f.nText("conversation_id"))
	headProtocol := e.str(f.text("protocol"))
	headStarted := e.i64(f.integer("started_at_ns"))
	headEnded := e.i64(f.integer("ended_at_ns"))
	record.Revision = e.i64(f.integer("revision"))
	digest := e.h(f.hash("record_digest"))
	if e.err != nil {
		return nil, [32]byte{}, e.err
	}
	steps := []func() error{
		func() (err error) { record.Audit, err = decodeAudit(f["audit_records"]); return },
		func() (err error) { record.Stages, err = decodeStages(f, record.Audit.AuditID); return },
		func() (err error) { record.Headers, err = decodeHeaders(f["headers"]); return },
		func() (err error) { record.Bodies, err = decodeBodies(f, record.Audit.AuditID); return },
		func() (err error) { record.RawChunks, err = decodeRawChunks(f); return },
		func() (err error) { record.Timelines, err = decodeTimelines(f); return },
		func() (err error) { record.ParsedResult, err = decodeParsedResult(f["parsed_results"]); return },
		func() (err error) { record.TokenLink, err = decodeTokenLink(f["token_links"]); return },
		func() (err error) { record.Turn, err = decodeTurn(f["turn"]); return },
		func() (err error) { record.Conversation, err = decodeConversation(f["conversation"]); return },
		func() (err error) { record.ProjectIdentity, err = decodeIdentity(f["audit_project_identity"]); return },
		func() (err error) { record.IntegrityEvents, err = decodeEvents(f); return },
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return nil, [32]byte{}, err
		}
	}
	audit := record.Audit
	if headAuditID != audit.AuditID || headProtocol != audit.Protocol || headStarted != audit.StartedAtNS || headEnded != audit.EndedAtNS {
		return nil, [32]byte{}, formatError("line head differs from audit_records")
	}
	conversation := record.ConversationID()
	if (headConversation == nil) != (conversation == nil) || (conversation != nil && *headConversation != *conversation) {
		return nil, [32]byte{}, formatError("line head conversation_id differs from the turn")
	}
	if err := record.CheckCanonical(); err != nil {
		return nil, [32]byte{}, err
	}
	return record, digest, nil
}

func decodeProjected(raw []byte, prefix ...string) (fields, ProjectedValue, error) {
	keys, err := objectKeys(raw)
	if err != nil {
		return nil, ProjectedValue{}, err
	}
	if keys["value_omitted"] {
		f, err := decodeObject(raw, append(prefix, "value_omitted", "length", "value_fpr")...)
		if err != nil {
			return nil, ProjectedValue{}, err
		}
		e := &errs{}
		reason := e.str(f.rawString("value_omitted"))
		value := ProjectedValue{Omitted: true, Length: e.i64(f.integer("length")), Fingerprint: e.h(f.hash("value_fpr"))}
		if e.err == nil && (reason != OmittedCredential || value.Length < 0) {
			e.err = formatError("value_omitted %q or negative length", reason)
		}
		return f, value, e.err
	}
	f, err := decodeObject(raw, append(prefix, "value")...)
	if err != nil {
		return nil, ProjectedValue{}, err
	}
	value, err := f.text("value")
	return f, ProjectedValue{Value: value}, err
}

func decodeRequestURI(raw []byte) (RequestURI, error) {
	f, err := decodeObject(raw, "path", "has_query", "segments")
	if err != nil {
		return RequestURI{}, err
	}
	e := &errs{}
	uri := RequestURI{Path: e.str(f.text("path")), HasQuery: e.bl(f.boolean("has_query"))}
	items := e.arr(f.array("segments"))
	if e.err != nil {
		return RequestURI{}, e.err
	}
	uri.Segments = make([]QuerySegment, 0, len(items))
	for _, item := range items {
		keys, err := objectKeys(item)
		if err != nil {
			return RequestURI{}, err
		}
		if keys["value_omitted"] {
			s, err := decodeObject(item, "raw_name", "has_equals", "value_omitted", "length", "value_fpr")
			if err != nil {
				return RequestURI{}, err
			}
			segment := QuerySegment{Credential: true, RawName: e.str(s.text("raw_name")), HasEquals: e.bl(s.boolean("has_equals")),
				Length: e.i64(s.integer("length")), Fingerprint: e.h(s.hash("value_fpr"))}
			if reason := e.str(s.rawString("value_omitted")); e.err == nil && (reason != OmittedCredential || segment.Length < 0) {
				e.err = formatError("request_uri segment value_omitted %q or negative length", reason)
			}
			uri.Segments = append(uri.Segments, segment)
		} else {
			s, err := decodeObject(item, "raw")
			if err != nil {
				return RequestURI{}, err
			}
			uri.Segments = append(uri.Segments, QuerySegment{Raw: e.str(s.text("raw"))})
		}
		if e.err != nil {
			return RequestURI{}, e.err
		}
	}
	if !uri.HasQuery && len(uri.Segments) != 0 {
		return RequestURI{}, formatError("request_uri segments without a query")
	}
	if uri.HasQuery && len(uri.Segments) == 0 {
		return RequestURI{}, formatError("request_uri query without segments")
	}
	return uri, nil
}

func decodeAudit(raw []byte) (AuditRow, error) {
	f, err := decodeObject(raw, auditKeys...)
	if err != nil {
		return AuditRow{}, err
	}
	e := &errs{}
	audit := AuditRow{
		AuditID:           e.str(f.text("audit_id")),
		SchemaGeneration:  e.i64(f.integer("schema_generation")),
		StartedAtNS:       e.i64(f.integer("started_at_ns")),
		EndedAtNS:         e.i64(f.integer("ended_at_ns")),
		RouteID:           e.str(f.text("route_id")),
		Protocol:          e.str(f.text("protocol")),
		ParserName:        e.str(f.text("parser_name")),
		Method:            e.str(f.text("method")),
		Path:              e.str(f.text("path")),
		Mode:              e.str(f.text("mode")),
		StatusCode:        e.ni64(f.nInteger("status_code")),
		TTFTNS:            e.ni64(f.nInteger("ttft_ns")),
		ForwardStatus:     e.str(f.text("forward_status")),
		CaptureStatus:     e.str(f.text("capture_status")),
		ParseStatus:       e.str(f.text("parse_status")),
		BlockedBy:         e.nstr(f.nText("blocked_by")),
		BlockCode:         e.nstr(f.nText("block_code")),
		ErrorCode:         e.nstr(f.nText("error_code")),
		NewAPIRequestID:   e.nstr(f.nText("newapi_request_id")),
		CallerStatus:      e.str(f.text("caller_status")),
		CallerAttempts:    e.i64(f.integer("caller_attempts")),
		CallerNextAtNS:    e.ni64(f.nInteger("caller_next_at_ns")),
		CallerUpdatedAtNS: e.ni64(f.nInteger("caller_updated_at_ns")),
		APIKeyFPR:         e.by(f.nHexBytes("api_key_fpr")),
		ParseSaveFailures: e.i64(f.integer("parse_save_failures")),
		ParseNextAtNS:     e.ni64(f.nInteger("parse_next_at_ns")),
		CaptureVersion:    e.i64(f.integer("capture_version")),
	}
	if e.err != nil {
		return AuditRow{}, e.err
	}
	if audit.RequestURI, err = decodeRequestURI(f["request_uri"]); err != nil {
		return AuditRow{}, err
	}
	items, err := f.nArray("user_agent")
	if err != nil {
		return AuditRow{}, err
	}
	if items != nil {
		if len(items) == 0 {
			return AuditRow{}, formatError("user_agent is an empty list")
		}
		audit.UserAgent = make([]ProjectedValue, 0, len(items))
		for _, item := range items {
			_, value, err := decodeProjected(item)
			if err != nil {
				return AuditRow{}, err
			}
			audit.UserAgent = append(audit.UserAgent, value)
		}
	}
	return audit, nil
}

func decodeList(f fields, key string, decode func(json.RawMessage) error) error {
	items, err := f.array(key)
	if err != nil {
		return err
	}
	for _, item := range items {
		if err := decode(item); err != nil {
			return err
		}
	}
	return nil
}

func decodeStages(f fields, auditID string) ([]Stage, error) {
	stages := []Stage{}
	err := decodeList(f, "http_stages", func(raw json.RawMessage) error {
		s, err := decodeObject(raw, "stage", "state", "proto", "method", "host", "status_code", "content_length",
			"started_at_ns", "ended_at_ns", "error_code", "content_type", "content_encoding")
		if err != nil {
			return err
		}
		e := &errs{}
		stage := Stage{HTTPStage: storage.HTTPStage{
			AuditID: auditID, Stage: e.str(s.text("stage")), State: e.str(s.text("state")),
			Proto: e.str(s.text("proto")), Method: e.str(s.text("method")), Host: e.str(s.text("host")),
			StatusCode: e.nint(s.nIntegerInt("status_code")), ContentLength: e.ni64(s.nInteger("content_length")),
			StartedAtNS: e.i64(s.integer("started_at_ns")), EndedAtNS: e.ni64(s.nInteger("ended_at_ns")),
			ErrorCode: e.nstr(s.nText("error_code")),
		}, ContentType: e.nstr(s.nText("content_type")), ContentEncoding: e.nstr(s.nText("content_encoding"))}
		stages = append(stages, stage)
		return e.err
	})
	return stages, err
}

func decodeHeaders(raw []byte) (Headers, error) {
	f, err := decodeObject(raw, "capture_version", "block_present", "block_stages", "values")
	if err != nil {
		return Headers{}, err
	}
	e := &errs{}
	headers := Headers{CaptureVersion: e.i64(f.integer("capture_version")), BlockPresent: e.bl(f.boolean("block_present"))}
	if e.err != nil {
		return Headers{}, e.err
	}
	if !isNull(f["block_stages"]) {
		if headers.BlockStages, err = f.strings("block_stages"); err != nil {
			return Headers{}, err
		}
	}
	headers.Values = []HeaderValue{}
	err = decodeList(f, "values", func(item json.RawMessage) error {
		v, value, err := decodeProjected(item, "stage", "kind", "name", "value_index")
		if err != nil {
			return err
		}
		e := &errs{}
		headers.Values = append(headers.Values, HeaderValue{
			Stage: e.str(v.text("stage")), Kind: e.str(v.text("kind")), Name: e.str(v.text("name")),
			ValueIndex: e.i64(v.integer("value_index")), Value: value,
		})
		return e.err
	})
	return headers, err
}

func decodeBodies(f fields, auditID string) ([]storage.BodyStream, error) {
	bodies := []storage.BodyStream{}
	err := decodeList(f, "body_streams", func(raw json.RawMessage) error {
		b, err := decodeObject(raw, "stage", "source_stage", "observed_length", "stored_length", "sha256",
			"hash_complete", "eof_seen", "state", "retention_state", "first_observed_at_ns",
			"last_observed_at_ns", "chunk_count", "stream_event_count", "stream_timeline_complete", "error_code")
		if err != nil {
			return err
		}
		e := &errs{}
		bodies = append(bodies, storage.BodyStream{
			AuditID: auditID, Stage: e.str(b.text("stage")), SourceStage: e.str(b.text("source_stage")),
			ObservedLength: e.i64(b.integer("observed_length")), StoredLength: e.i64(b.integer("stored_length")),
			SHA256: e.by(b.nHexBytes("sha256")), HashComplete: e.bl(b.flag("hash_complete")),
			EOFSeen: e.bl(b.flag("eof_seen")), State: e.str(b.text("state")),
			RetentionState:    e.str(b.text("retention_state")),
			FirstObservedAtNS: e.ni64(b.nInteger("first_observed_at_ns")),
			LastObservedAtNS:  e.ni64(b.nInteger("last_observed_at_ns")),
			ChunkCount:        e.i64(b.integer("chunk_count")), StreamEventCount: e.i64(b.integer("stream_event_count")),
			StreamTimelineComplete: e.bl(b.flag("stream_timeline_complete")), ErrorCode: e.nstr(b.nText("error_code")),
		})
		return e.err
	})
	return bodies, err
}

func decodeRawChunks(f fields) ([]RawChunk, error) {
	chunks := []RawChunk{}
	err := decodeList(f, "raw_chunks", func(raw json.RawMessage) error {
		c, err := decodeObject(raw, "stage", "seq", "offset", "plaintext_length", "observed_at_ns", "sha256")
		if err != nil {
			return err
		}
		e := &errs{}
		chunks = append(chunks, RawChunk{
			Stage: e.str(c.text("stage")), Seq: e.i64(c.integer("seq")), Offset: e.i64(c.integer("offset")),
			PlaintextLength: e.i64(c.integer("plaintext_length")), ObservedAtNS: e.i64(c.integer("observed_at_ns")),
			SHA256: e.h(c.hash("sha256")),
		})
		return e.err
	})
	return chunks, err
}

func decodeTimelines(f fields) ([]Timeline, error) {
	timelines := []Timeline{}
	err := decodeList(f, "stream_timelines", func(raw json.RawMessage) error {
		t, err := decodeObject(raw, "stage", "event_count", "first_event_at_ns", "last_event_at_ns",
			"timeline_complete", "plaintext_length", "timeline_b64")
		if err != nil {
			return err
		}
		e := &errs{}
		timelines = append(timelines, Timeline{
			Stage: e.str(t.text("stage")), EventCount: e.i64(t.integer("event_count")),
			FirstEventAtNS: e.ni64(t.nInteger("first_event_at_ns")), LastEventAtNS: e.ni64(t.nInteger("last_event_at_ns")),
			Complete: e.bl(t.flag("timeline_complete")), PlaintextLength: e.i64(t.integer("plaintext_length")),
			Plaintext: e.by(t.nBase64("timeline_b64")),
		})
		return e.err
	})
	return timelines, err
}

func decodeParsedResult(raw json.RawMessage) (*ParsedResult, error) {
	if isNull(raw) {
		return nil, nil
	}
	f, err := decodeObject(raw, "parser_name", "parser_version", "status", "request_model", "response_model",
		"requested_stream", "observed_stream", "response_id", "usage_input", "usage_output", "usage_total",
		"error_type", "error_code", "upstream_error_class", "message_count", "tool_call_count",
		"has_tool_call", "parsed_json", "parsed_json_ref", "parsed_at_ns")
	if err != nil {
		return nil, err
	}
	e := &errs{}
	parsed := &ParsedResult{
		ParserName: e.str(f.text("parser_name")), ParserVersion: e.str(f.text("parser_version")),
		Status: e.str(f.text("status")), RequestModel: e.nstr(f.nText("request_model")),
		ResponseModel: e.nstr(f.nText("response_model")), RequestedStream: e.nbl(f.nFlag("requested_stream")),
		ObservedStream: e.nbl(f.nFlag("observed_stream")), ResponseID: e.nstr(f.nText("response_id")),
		UsageInput: e.ni64(f.nInteger("usage_input")), UsageOutput: e.ni64(f.nInteger("usage_output")),
		UsageTotal: e.ni64(f.nInteger("usage_total")), ErrorType: e.nstr(f.nText("error_type")),
		ErrorCode: e.nstr(f.nText("error_code")), UpstreamErrorClass: e.nstr(f.nText("upstream_error_class")),
		MessageCount: e.ni64(f.nInteger("message_count")), ToolCallCount: e.ni64(f.nInteger("tool_call_count")),
		HasToolCall: e.nbl(f.nFlag("has_tool_call")), ParsedJSON: e.by(f.nTextBytes("parsed_json")),
		ParsedAtNS: e.i64(f.integer("parsed_at_ns")),
	}
	if e.err != nil {
		return nil, e.err
	}
	if !isNull(f["parsed_json_ref"]) {
		r, err := decodeObject(f["parsed_json_ref"], "sha256", "length", "parts")
		if err != nil {
			return nil, err
		}
		ref := &ParsedJSONRef{SHA256: e.h(r.hash("sha256")), Length: e.i64(r.integer("length")), Parts: e.i64(r.integer("parts"))}
		if e.err != nil {
			return nil, e.err
		}
		if parsed.ParsedJSON != nil || ref.Length <= ParsedJSONInlineLimit || ref.Parts < 2 {
			return nil, formatError("parsed_json_ref with inline parsed_json, or for a value that fits the line")
		}
		parsed.ParsedJSONRef = ref
	} else if len(parsed.ParsedJSON) > ParsedJSONInlineLimit {
		return nil, formatError("inline parsed_json over the line limit")
	}
	return parsed, nil
}

func decodeTokenLink(raw json.RawMessage) (*TokenLink, error) {
	if isNull(raw) {
		return nil, nil
	}
	f, err := decodeObject(raw, "newapi_user_id", "username", "newapi_token_id", "token_name", "linked_at_ns",
		"billing_state", "quota", "quota_per_unit", "billed_prompt_tokens", "billed_completion_tokens", "billing_attempts")
	if err != nil {
		return nil, err
	}
	e := &errs{}
	link := &TokenLink{
		NewAPIUserID: e.i64(f.integer("newapi_user_id")), Username: e.str(f.text("username")),
		NewAPITokenID: e.i64(f.integer("newapi_token_id")), TokenName: e.str(f.text("token_name")),
		LinkedAtNS: e.i64(f.integer("linked_at_ns")), BillingState: e.str(f.text("billing_state")),
		Quota: e.ni64(f.nInteger("quota")), QuotaPerUnit: e.nf(f.nFloat("quota_per_unit")),
		BilledPromptTokens:     e.ni64(f.nInteger("billed_prompt_tokens")),
		BilledCompletionTokens: e.ni64(f.nInteger("billed_completion_tokens")),
		BillingAttempts:        e.i64(f.integer("billing_attempts")),
	}
	return link, e.err
}

func decodeRef(raw json.RawMessage) (auditmodel.ObjectRef, error) {
	f, err := decodeObject(raw, "slot", "object_hash", "semantic_hash")
	if err != nil {
		return auditmodel.ObjectRef{}, err
	}
	e := &errs{}
	ref := auditmodel.ObjectRef{Slot: e.str(f.text("slot")), ObjectHash: e.by(f.hexBytes("object_hash")), SemanticHash: e.by(f.hexBytes("semantic_hash"))}
	return ref, e.err
}

func decodeTurn(raw json.RawMessage) (*Turn, error) {
	if isNull(raw) {
		return nil, nil
	}
	f, err := decodeObject(raw, "turns", "request_context", "response_items", "objects", "binary_refs", "external_refs", "binaries")
	if err != nil {
		return nil, err
	}
	r, err := decodeObject(f["turns"], "turn_id", "conversation_id", "parent_turn_id", "parent_base", "link_reason",
		"link_confidence", "request_layout", "response_layout", "request_envelope_hash", "response_envelope_hash",
		"request_item_count", "response_item_count", "request_sequence_hash", "response_sequence_hash",
		"request_reconstruction_hash", "response_reconstruction_hash", "reconstruction_status",
		"previous_response_id", "response_id", "created_at_ns")
	if err != nil {
		return nil, err
	}
	e := &errs{}
	turn := &Turn{Row: TurnRow{
		TurnID: e.str(r.text("turn_id")), ConversationID: e.str(r.text("conversation_id")),
		ParentTurnID: e.nstr(r.nText("parent_turn_id")), ParentBase: e.str(r.text("parent_base")),
		LinkReason: e.str(r.text("link_reason")), LinkConfidence: e.i64(r.integer("link_confidence")),
		RequestLayout: e.str(r.text("request_layout")), ResponseLayout: e.str(r.text("response_layout")),
		RequestEnvelopeHash:        e.by(r.hexBytes("request_envelope_hash")),
		ResponseEnvelopeHash:       e.by(r.hexBytes("response_envelope_hash")),
		RequestItemCount:           e.i64(r.integer("request_item_count")),
		ResponseItemCount:          e.i64(r.integer("response_item_count")),
		RequestSequenceHash:        e.by(r.hexBytes("request_sequence_hash")),
		ResponseSequenceHash:       e.by(r.hexBytes("response_sequence_hash")),
		RequestReconstructionHash:  e.by(r.hexBytes("request_reconstruction_hash")),
		ResponseReconstructionHash: e.by(r.hexBytes("response_reconstruction_hash")),
		ReconstructionStatus:       e.str(r.text("reconstruction_status")),
		PreviousResponseID:         e.nstr(r.nText("previous_response_id")),
		ResponseID:                 e.nstr(r.nText("response_id")),
		CreatedAtNS:                e.i64(r.integer("created_at_ns")),
	}}
	if e.err != nil {
		return nil, e.err
	}
	keys, err := objectKeys(f["request_context"])
	if err != nil {
		return nil, err
	}
	if keys["refs"] {
		c, err := decodeObject(f["request_context"], "form", "refs")
		if err != nil {
			return nil, err
		}
		if form := e.str(c.rawString("form")); e.err == nil && form != ContextMaterialized {
			return nil, formatError("request_context form %q with refs", form)
		}
		turn.Context = RequestContext{Form: ContextMaterialized, Refs: []auditmodel.ObjectRef{}}
		if err := decodeList(c, "refs", func(item json.RawMessage) error {
			ref, err := decodeRef(item)
			turn.Context.Refs = append(turn.Context.Refs, ref)
			return err
		}); err != nil {
			return nil, err
		}
		turn.RequestRefs = cloneRefs(turn.Context.Refs)
	} else {
		c, err := decodeObject(f["request_context"], "form", "ops")
		if err != nil {
			return nil, err
		}
		if form := e.str(c.rawString("form")); e.err == nil && form != ContextDelta {
			return nil, formatError("request_context form %q with ops", form)
		}
		turn.Context = RequestContext{Form: ContextDelta, Ops: []ContextOp{}}
		if err := decodeList(c, "ops", func(item json.RawMessage) error {
			o, err := decodeObject(item, "op_index", "operation", "item_count", "slot", "object_hash", "semantic_hash")
			if err != nil {
				return err
			}
			turn.Context.Ops = append(turn.Context.Ops, ContextOp{
				OpIndex: e.i64(o.integer("op_index")), Operation: e.str(o.text("operation")),
				ItemCount: e.i64(o.integer("item_count")), Slot: e.nstr(o.nText("slot")),
				ObjectHash: e.by(o.nHexBytes("object_hash")), SemanticHash: e.by(o.nHexBytes("semantic_hash")),
			})
			return e.err
		}); err != nil {
			return nil, err
		}
	}
	if e.err != nil {
		return nil, e.err
	}
	turn.ResponseItems = []ResponseItem{}
	turn.Objects = []ObjectMeta{}
	turn.BinaryRefs = []BinaryRef{}
	turn.ExternalRefs = []ExternalRef{}
	turn.Binaries = []BinaryMeta{}
	lists := []struct {
		key    string
		keys   []string
		decode func(fields)
	}{
		{"response_items", []string{"ordinal", "slot", "object_hash", "semantic_hash"}, func(x fields) {
			turn.ResponseItems = append(turn.ResponseItems, ResponseItem{Ordinal: e.i64(x.integer("ordinal")), Slot: e.str(x.text("slot")),
				ObjectHash: e.by(x.hexBytes("object_hash")), SemanticHash: e.by(x.hexBytes("semantic_hash"))})
		}},
		{"objects", []string{"object_hash", "semantic_hash", "object_kind", "plaintext_length"}, func(x fields) {
			turn.Objects = append(turn.Objects, ObjectMeta{Hash: e.by(x.hexBytes("object_hash")), SemanticHash: e.by(x.hexBytes("semantic_hash")),
				Kind: e.str(x.text("object_kind")), PlaintextLength: e.i64(x.integer("plaintext_length"))})
		}},
		{"binary_refs", []string{"object_hash", "json_pointer", "binary_hash", "media_type", "encoding"}, func(x fields) {
			turn.BinaryRefs = append(turn.BinaryRefs, BinaryRef{ObjectHash: e.by(x.hexBytes("object_hash")), JSONPointer: e.str(x.text("json_pointer")),
				BinaryHash: e.by(x.hexBytes("binary_hash")), MediaType: e.str(x.text("media_type")), Encoding: e.str(x.text("encoding"))})
		}},
		{"external_refs", []string{"object_hash", "json_pointer", "ref_kind", "value_hash", "value"}, func(x fields) {
			turn.ExternalRefs = append(turn.ExternalRefs, ExternalRef{ObjectHash: e.by(x.hexBytes("object_hash")), JSONPointer: e.str(x.text("json_pointer")),
				RefKind: e.str(x.text("ref_kind")), ValueHash: e.by(x.hexBytes("value_hash")), Value: e.str(x.text("value"))})
		}},
		{"binaries", []string{"binary_hash", "media_type", "plaintext_length"}, func(x fields) {
			turn.Binaries = append(turn.Binaries, BinaryMeta{Hash: e.by(x.hexBytes("binary_hash")), MediaType: e.str(x.text("media_type")),
				PlaintextLength: e.i64(x.integer("plaintext_length"))})
		}},
	}
	for _, list := range lists {
		if err := decodeList(f, list.key, func(item json.RawMessage) error {
			x, err := decodeObject(item, list.keys...)
			if err != nil {
				return err
			}
			list.decode(x)
			return e.err
		}); err != nil {
			return nil, err
		}
	}
	return turn, nil
}

func decodeConversation(raw json.RawMessage) (*Conversation, error) {
	if isNull(raw) {
		return nil, nil
	}
	f, err := decodeObject(raw, "conversation_id", "protocol", "key_hash", "created_at_ns")
	if err != nil {
		return nil, err
	}
	e := &errs{}
	conversation := &Conversation{ConversationID: e.str(f.text("conversation_id")), Protocol: e.str(f.text("protocol")),
		KeyHash: e.by(f.nHexBytes("key_hash")), CreatedAtNS: e.i64(f.integer("created_at_ns"))}
	return conversation, e.err
}

func decodeIdentity(raw json.RawMessage) (*ProjectIdentity, error) {
	if isNull(raw) {
		return nil, nil
	}
	f, err := decodeObject(raw, "identity_version", "extracted_at_ns", "source", "body_scanned", "identity_fpr",
		"remote_fpr", "repo_root_fpr", "cwd_fpr", "identity")
	if err != nil {
		return nil, err
	}
	e := &errs{}
	identity := &ProjectIdentity{
		IdentityVersion: e.i64(f.integer("identity_version")), ExtractedAtNS: e.i64(f.integer("extracted_at_ns")),
		Source: e.str(f.text("source")), BodyScanned: e.bl(f.flag("body_scanned")),
		IdentityFPR: e.by(f.nHexBytes("identity_fpr")), RemoteFPR: e.by(f.nHexBytes("remote_fpr")),
		RepoRootFPR: e.by(f.nHexBytes("repo_root_fpr")), CwdFPR: e.by(f.nHexBytes("cwd_fpr")),
		Identity: e.by(f.nTextBytes("identity")),
	}
	return identity, e.err
}

func decodeEvents(f fields) ([]IntegrityEvent, error) {
	events := []IntegrityEvent{}
	err := decodeList(f, "integrity_events", func(raw json.RawMessage) error {
		x, err := decodeObject(raw, "sequence", "event_type", "previous_mac", "payload_digest", "event_mac", "created_at_ns")
		if err != nil {
			return err
		}
		e := &errs{}
		events = append(events, IntegrityEvent{
			Sequence: e.i64(x.integer("sequence")), EventType: e.str(x.text("event_type")),
			PreviousMAC: e.by(x.nHexBytes("previous_mac")), PayloadDigest: e.by(x.hexBytes("payload_digest")),
			EventMAC: e.by(x.hexBytes("event_mac")), CreatedAtNS: e.i64(x.integer("created_at_ns")),
		})
		return e.err
	})
	return events, err
}

// EncodeContentObject, EncodeBinaryObject, EncodeRawChunk and
// EncodeParsedJSONPart encode one objects file line (C.5), without the
// trailing newline.
func EncodeContentObject(object_ ContentObject) []byte {
	return object(
		member{"type", jsonString(EntryContentObject)},
		member{"object_hash", jHex(object_.Hash)},
		member{"semantic_hash", jHex(object_.SemanticHash)},
		member{"object_kind", jText(object_.Kind)},
		member{"plaintext_length", jInt(object_.PlaintextLength)},
		member{"created_at_ns", jInt(object_.CreatedAtNS)},
		member{"data", jTextBytes(object_.Data)},
	)
}

func EncodeBinaryObject(binary BinaryObject) []byte {
	return object(
		member{"type", jsonString(EntryBinaryObject)},
		member{"binary_hash", jHex(binary.Hash)},
		member{"media_type", jText(binary.MediaType)},
		member{"plaintext_length", jInt(binary.PlaintextLength)},
		member{"created_at_ns", jInt(binary.CreatedAtNS)},
		member{"data_b64", jB64(binary.Data)},
	)
}

func EncodeRawChunk(chunk RawChunkData) []byte {
	return object(
		member{"type", jsonString(EntryRawChunk)},
		member{"audit_id", jText(chunk.AuditID)},
		member{"stage", jText(chunk.Stage)},
		member{"seq", jInt(chunk.Seq)},
		member{"data_b64", jB64(chunk.Data)},
	)
}

func EncodeParsedJSONPart(part ParsedJSONPart) []byte {
	return object(
		member{"type", jsonString(EntryParsedJSONPart)},
		member{"audit_id", jText(part.AuditID)},
		member{"part", jInt(part.Part)},
		member{"data", jTextBytes(part.Data)},
	)
}

// DecodeObjectEntry decodes one objects file line. It checks the shape and
// encoding only; the content addresses and lengths are checked by the
// reader against the lines (J.2).
func DecodeObjectEntry(line []byte) (ObjectEntry, error) {
	if !utf8.Valid(line) {
		return ObjectEntry{}, formatError("objects line is not valid UTF-8")
	}
	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(line, &probe); err != nil {
		return ObjectEntry{}, formatError("objects line: %v", err)
	}
	e := &errs{}
	switch probe.Type {
	case EntryContentObject:
		f, err := decodeObject(line, "type", "object_hash", "semantic_hash", "object_kind", "plaintext_length", "created_at_ns", "data")
		if err != nil {
			return ObjectEntry{}, err
		}
		content := &ContentObject{Hash: e.by(f.hexBytes("object_hash")), SemanticHash: e.by(f.hexBytes("semantic_hash")),
			Kind: e.str(f.text("object_kind")), PlaintextLength: e.i64(f.integer("plaintext_length")),
			CreatedAtNS: e.i64(f.integer("created_at_ns")), Data: e.by(f.textBytes("data"))}
		return ObjectEntry{Content: content}, e.err
	case EntryBinaryObject:
		f, err := decodeObject(line, "type", "binary_hash", "media_type", "plaintext_length", "created_at_ns", "data_b64")
		if err != nil {
			return ObjectEntry{}, err
		}
		binary := &BinaryObject{Hash: e.by(f.hexBytes("binary_hash")), MediaType: e.str(f.text("media_type")),
			PlaintextLength: e.i64(f.integer("plaintext_length")), CreatedAtNS: e.i64(f.integer("created_at_ns")),
			Data: e.by(f.base64("data_b64"))}
		return ObjectEntry{Binary: binary}, e.err
	case EntryRawChunk:
		f, err := decodeObject(line, "type", "audit_id", "stage", "seq", "data_b64")
		if err != nil {
			return ObjectEntry{}, err
		}
		chunk := &RawChunkData{AuditID: e.str(f.text("audit_id")), Stage: e.str(f.text("stage")),
			Seq: e.i64(f.integer("seq")), Data: e.by(f.base64("data_b64"))}
		return ObjectEntry{RawChunk: chunk}, e.err
	case EntryParsedJSONPart:
		f, err := decodeObject(line, "type", "audit_id", "part", "data")
		if err != nil {
			return ObjectEntry{}, err
		}
		part := &ParsedJSONPart{AuditID: e.str(f.text("audit_id")), Part: e.i64(f.integer("part")), Data: e.by(f.textBytes("data"))}
		return ObjectEntry{ParsedJSONPart: part}, e.err
	}
	return ObjectEntry{}, formatError("unknown objects entry type %q", probe.Type)
}

// EncodeGap encodes one gaps file line (C.6), without the trailing newline.
func EncodeGap(gap Gap) []byte {
	return object(
		member{"type", jsonString(EntryGap)},
		member{"id", jInt(gap.ID)},
		member{"started_at_ns", jInt(gap.StartedAtNS)},
		member{"ended_at_ns", jInt(gap.EndedAtNS)},
		member{"reason", jText(gap.Reason)},
		member{"request_count", jInt(gap.RequestCount)},
		member{"detail", jText(gap.Detail)},
		member{"created_at_ns", jInt(gap.CreatedAtNS)},
	)
}

// DecodeGap decodes one gaps file line.
func DecodeGap(line []byte) (Gap, error) {
	if !utf8.Valid(line) {
		return Gap{}, formatError("gaps line is not valid UTF-8")
	}
	f, err := decodeObject(line, "type", "id", "started_at_ns", "ended_at_ns", "reason", "request_count", "detail", "created_at_ns")
	if err != nil {
		return Gap{}, err
	}
	e := &errs{}
	if kind := e.str(f.rawString("type")); e.err == nil && kind != EntryGap {
		return Gap{}, formatError("gaps line type %q", kind)
	}
	gap := Gap{ID: e.i64(f.integer("id")), StartedAtNS: e.i64(f.integer("started_at_ns")),
		EndedAtNS: e.i64(f.integer("ended_at_ns")), Reason: e.str(f.text("reason")),
		RequestCount: e.i64(f.integer("request_count")), Detail: e.str(f.text("detail")),
		CreatedAtNS: e.i64(f.integer("created_at_ns"))}
	return gap, e.err
}

// The JSON rules of C.1, shared by every file of a segment. Encoders write
// keys in a fixed order; decoders accept any order but require exactly the
// documented keys, each once, and only the canonical encoding of each value:
//   - 64-bit integers: a JSON string holding strconv.FormatInt's output;
//   - 0/1 integer columns: "0" or "1";
//   - floats: a JSON string holding strconv.FormatFloat(v, 'g', -1, 64);
//   - hashes and keyed fingerprints: a JSON string of lowercase hex;
//   - binary content: a JSON string of padded standard base64;
//   - text: a JSON string when the bytes are valid UTF-8, otherwise
//     {"b64": <padded standard base64>};
//   - format-level flags (has_query, has_equals, block_present, encrypted):
//     JSON true or false;
//   - NULL: null, never an absent key.

type member struct {
	key   string
	value []byte
}

func object(members ...member) []byte {
	var buffer bytes.Buffer
	buffer.WriteByte('{')
	for index, m := range members {
		if index > 0 {
			buffer.WriteByte(',')
		}
		buffer.Write(jsonString(m.key))
		buffer.WriteByte(':')
		buffer.Write(m.value)
	}
	buffer.WriteByte('}')
	return buffer.Bytes()
}

func array(items [][]byte) []byte {
	var buffer bytes.Buffer
	buffer.WriteByte('[')
	for index, item := range items {
		if index > 0 {
			buffer.WriteByte(',')
		}
		buffer.Write(item)
	}
	buffer.WriteByte(']')
	return buffer.Bytes()
}

var jsonNull = []byte("null")

// jsonString encodes valid UTF-8 as a JSON string.
func jsonString(value string) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}

func jText(value string) []byte {
	if utf8.ValidString(value) {
		return jsonString(value)
	}
	return object(member{"b64", jsonString(base64.StdEncoding.EncodeToString([]byte(value)))})
}

func jTextBytes(value []byte) []byte { return jText(string(value)) }

func jNText(value *string) []byte {
	if value == nil {
		return jsonNull
	}
	return jText(*value)
}

func jInt(value int64) []byte { return jsonString(strconv.FormatInt(value, 10)) }

func jNInt(value *int64) []byte {
	if value == nil {
		return jsonNull
	}
	return jInt(*value)
}

func jFlag(value bool) []byte {
	if value {
		return jsonString("1")
	}
	return jsonString("0")
}

func jNFlag(value *bool) []byte {
	if value == nil {
		return jsonNull
	}
	return jFlag(*value)
}

func jBool(value bool) []byte {
	if value {
		return []byte("true")
	}
	return []byte("false")
}

func jHex(value []byte) []byte { return jsonString(hex.EncodeToString(value)) }

func jNHex(value []byte) []byte {
	if value == nil {
		return jsonNull
	}
	return jHex(value)
}

func jB64(value []byte) []byte { return jsonString(base64.StdEncoding.EncodeToString(value)) }

func jNB64(value []byte) []byte {
	if value == nil {
		return jsonNull
	}
	return jB64(value)
}

func jNFloat(value *float64) []byte {
	if value == nil {
		return jsonNull
	}
	return jsonString(strconv.FormatFloat(*value, 'g', -1, 64))
}

func jStrings(values []string) []byte {
	items := make([][]byte, 0, len(values))
	for _, value := range values {
		items = append(items, jText(value))
	}
	return array(items)
}

// fields is one decoded JSON object.
type fields map[string]json.RawMessage

func isNull(raw json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(raw), jsonNull) }

// decodeObject parses a JSON object that has exactly the given keys, each
// once. Trailing data after the object is an error.
func decodeObject(raw []byte, keys ...string) (fields, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, formatError("expected an object")
	}
	out := make(fields, len(keys))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, formatError("object key: %v", err)
		}
		key, ok := token.(string)
		if !ok {
			return nil, formatError("object key")
		}
		if _, duplicate := out[key]; duplicate {
			return nil, formatError("duplicate key %q", key)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, formatError("value of %q: %v", key, err)
		}
		out[key] = value
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, formatError("unterminated object")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, formatError("data after the object")
	}
	if len(out) != len(keys) {
		for key := range out {
			if !containsString(keys, key) {
				return nil, formatError("unknown key %q", key)
			}
		}
	}
	for _, key := range keys {
		if _, ok := out[key]; !ok {
			return nil, formatError("missing key %q", key)
		}
	}
	return out, nil
}

// hasKey reports whether an object has key, for the decoders of the shapes
// that are unions of two key sets.
func objectKeys(raw []byte) (map[string]bool, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil || probe == nil {
		return nil, formatError("expected an object")
	}
	keys := make(map[string]bool, len(probe))
	for key := range probe {
		keys[key] = true
	}
	return keys, nil
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func (f fields) rawString(key string) (string, error) {
	raw := f[key]
	if len(raw) == 0 || raw[0] != '"' {
		return "", formatError("%s: expected a string", key)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", formatError("%s: %v", key, err)
	}
	return value, nil
}

func (f fields) text(key string) (string, error) {
	raw := f[key]
	if len(raw) > 0 && raw[0] == '{' {
		wrapped, err := decodeObject(raw, "b64")
		if err != nil {
			return "", formatError("%s: %v", key, err)
		}
		data, err := wrapped.base64("b64")
		if err != nil {
			return "", formatError("%s: %v", key, err)
		}
		if utf8.Valid(data) {
			return "", formatError("%s: b64 form used for valid UTF-8", key)
		}
		return string(data), nil
	}
	return f.rawString(key)
}

func (f fields) nText(key string) (*string, error) {
	if isNull(f[key]) {
		return nil, nil
	}
	value, err := f.text(key)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func (f fields) textBytes(key string) ([]byte, error) {
	value, err := f.text(key)
	return []byte(value), err
}

func (f fields) nTextBytes(key string) ([]byte, error) {
	value, err := f.nText(key)
	if value == nil || err != nil {
		return nil, err
	}
	return []byte(*value), nil
}

func (f fields) integer(key string) (int64, error) {
	text, err := f.rawString(key)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil || strconv.FormatInt(value, 10) != text {
		return 0, formatError("%s: not a canonical decimal integer", key)
	}
	return value, nil
}

func (f fields) nInteger(key string) (*int64, error) {
	if isNull(f[key]) {
		return nil, nil
	}
	value, err := f.integer(key)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func (f fields) nIntegerInt(key string) (*int, error) {
	value, err := f.nInteger(key)
	if value == nil || err != nil {
		return nil, err
	}
	if *value < math.MinInt32 || *value > math.MaxInt32 {
		return nil, formatError("%s: out of range", key)
	}
	converted := int(*value)
	return &converted, nil
}

func (f fields) flag(key string) (bool, error) {
	text, err := f.rawString(key)
	if err != nil {
		return false, err
	}
	switch text {
	case "0":
		return false, nil
	case "1":
		return true, nil
	}
	return false, formatError("%s: expected \"0\" or \"1\"", key)
}

func (f fields) nFlag(key string) (*bool, error) {
	if isNull(f[key]) {
		return nil, nil
	}
	value, err := f.flag(key)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func (f fields) boolean(key string) (bool, error) {
	switch string(bytes.TrimSpace(f[key])) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, formatError("%s: expected true or false", key)
}

func (f fields) hexBytes(key string) ([]byte, error) {
	text, err := f.rawString(key)
	if err != nil {
		return nil, err
	}
	value, err := hex.DecodeString(text)
	if err != nil || hex.EncodeToString(value) != text {
		return nil, formatError("%s: not lowercase hex", key)
	}
	return value, nil
}

func (f fields) nHexBytes(key string) ([]byte, error) {
	if isNull(f[key]) {
		return nil, nil
	}
	return f.hexBytes(key)
}

func (f fields) hash(key string) ([32]byte, error) {
	value, err := f.hexBytes(key)
	if err != nil {
		return [32]byte{}, err
	}
	if len(value) != 32 {
		return [32]byte{}, formatError("%s: expected 32 bytes", key)
	}
	var out [32]byte
	copy(out[:], value)
	return out, nil
}

func (f fields) base64(key string) ([]byte, error) {
	text, err := f.rawString(key)
	if err != nil {
		return nil, err
	}
	value, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || base64.StdEncoding.EncodeToString(value) != text {
		return nil, formatError("%s: not padded standard base64", key)
	}
	return value, nil
}

func (f fields) nBase64(key string) ([]byte, error) {
	if isNull(f[key]) {
		return nil, nil
	}
	return f.base64(key)
}

func (f fields) nFloat(key string) (*float64, error) {
	if isNull(f[key]) {
		return nil, nil
	}
	text, err := f.rawString(key)
	if err != nil {
		return nil, err
	}
	value, err := strconv.ParseFloat(text, 64)
	if err != nil || strconv.FormatFloat(value, 'g', -1, 64) != text {
		return nil, formatError("%s: not a canonical float", key)
	}
	return &value, nil
}

func (f fields) array(key string) ([]json.RawMessage, error) {
	raw := bytes.TrimSpace(f[key])
	if len(raw) == 0 || raw[0] != '[' {
		return nil, formatError("%s: expected an array", key)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, formatError("%s: %v", key, err)
	}
	if items == nil {
		items = []json.RawMessage{}
	}
	return items, nil
}

func (f fields) nArray(key string) ([]json.RawMessage, error) {
	if isNull(f[key]) {
		return nil, nil
	}
	return f.array(key)
}

func (f fields) strings(key string) ([]string, error) {
	items, err := f.array(key)
	if err != nil {
		return nil, err
	}
	values := make([]string, 0, len(items))
	for _, item := range items {
		value, err := fields{"item": item}.text("item")
		if err != nil {
			return nil, formatError("%s: %v", key, err)
		}
		values = append(values, value)
	}
	return values, nil
}

// errs collects the first error of a run of field reads.
type errs struct{ err error }

func (e *errs) keep(err error) {
	if e.err == nil && err != nil {
		e.err = err
	}
}

func (e *errs) str(value string, err error) string    { e.keep(err); return value }
func (e *errs) nstr(value *string, err error) *string { e.keep(err); return value }
func (e *errs) i64(value int64, err error) int64      { e.keep(err); return value }
func (e *errs) ni64(value *int64, err error) *int64   { e.keep(err); return value }
func (e *errs) nint(value *int, err error) *int       { e.keep(err); return value }
func (e *errs) bl(value bool, err error) bool         { e.keep(err); return value }
func (e *errs) nbl(value *bool, err error) *bool      { e.keep(err); return value }
func (e *errs) by(value []byte, err error) []byte     { e.keep(err); return value }
func (e *errs) h(value [32]byte, err error) [32]byte  { e.keep(err); return value }
func (e *errs) nf(value *float64, err error) *float64 { e.keep(err); return value }
func (e *errs) arr(value []json.RawMessage, err error) []json.RawMessage {
	e.keep(err)
	return value
}
