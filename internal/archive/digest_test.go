package archive

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"llmapi-logger/internal/headerblock"
	"llmapi-logger/internal/storage"
)

var update = flag.Bool("update", false, "rewrite the testdata vectors")

func flipHash(value []byte) []byte {
	out := bytes.Clone(value)
	out[0] ^= 1
	return out
}

func flipSum(value [32]byte) [32]byte {
	value[0] ^= 1
	return value
}

func moreText(value *string) *string {
	if value == nil {
		return text("x")
	}
	return text(*value + "x")
}

func moreInt(value *int64) *int64 {
	if value == nil {
		return integer(1)
	}
	return integer(*value + 1)
}

func notFlag(value *bool) *bool {
	if value == nil {
		return boolPtr(true)
	}
	return boolPtr(!*value)
}

// digestMutators change exactly one archived column of fullRecord, keyed by
// "table.column". Every column of the specification must have an entry, so
// adding a column to Columns without deciding how the record carries it
// fails TestDigestCoversTheSpecification. nil means the column is not part
// of the record (it lives in the objects or gaps file).
var digestMutators = map[string]func(*Record){
	"audit_records.audit_id":             func(r *Record) { r.Audit.AuditID += "x" },
	"audit_records.schema_generation":    func(r *Record) { r.Audit.SchemaGeneration++ },
	"audit_records.started_at_ns":        func(r *Record) { r.Audit.StartedAtNS++ },
	"audit_records.ended_at_ns":          func(r *Record) { r.Audit.EndedAtNS++ },
	"audit_records.route_id":             func(r *Record) { r.Audit.RouteID += "x" },
	"audit_records.protocol":             func(r *Record) { r.Audit.Protocol += "x" },
	"audit_records.parser_name":          func(r *Record) { r.Audit.ParserName += "x" },
	"audit_records.method":               func(r *Record) { r.Audit.Method += "x" },
	"audit_records.path":                 func(r *Record) { r.Audit.Path += "x" },
	"audit_records.request_uri_enc":      func(r *Record) { r.Audit.RequestURI.Segments[0].Raw += "x" },
	"audit_records.mode":                 func(r *Record) { r.Audit.Mode += "x" },
	"audit_records.status_code":          func(r *Record) { r.Audit.StatusCode = moreInt(r.Audit.StatusCode) },
	"audit_records.ttft_ns":              func(r *Record) { r.Audit.TTFTNS = moreInt(r.Audit.TTFTNS) },
	"audit_records.forward_status":       func(r *Record) { r.Audit.ForwardStatus += "x" },
	"audit_records.capture_status":       func(r *Record) { r.Audit.CaptureStatus += "x" },
	"audit_records.parse_status":         func(r *Record) { r.Audit.ParseStatus += "x" },
	"audit_records.blocked_by":           func(r *Record) { r.Audit.BlockedBy = moreText(r.Audit.BlockedBy) },
	"audit_records.block_code":           func(r *Record) { r.Audit.BlockCode = moreText(r.Audit.BlockCode) },
	"audit_records.error_code":           func(r *Record) { r.Audit.ErrorCode = moreText(r.Audit.ErrorCode) },
	"audit_records.newapi_request_id":    func(r *Record) { r.Audit.NewAPIRequestID = moreText(r.Audit.NewAPIRequestID) },
	"audit_records.caller_status":        func(r *Record) { r.Audit.CallerStatus += "x" },
	"audit_records.caller_attempts":      func(r *Record) { r.Audit.CallerAttempts++ },
	"audit_records.caller_next_at_ns":    func(r *Record) { r.Audit.CallerNextAtNS = moreInt(r.Audit.CallerNextAtNS) },
	"audit_records.caller_updated_at_ns": func(r *Record) { r.Audit.CallerUpdatedAtNS = moreInt(r.Audit.CallerUpdatedAtNS) },
	"audit_records.api_key_fpr":          func(r *Record) { r.Audit.APIKeyFPR = flipHash(r.Audit.APIKeyFPR) },
	"audit_records.parse_save_failures":  func(r *Record) { r.Audit.ParseSaveFailures++ },
	"audit_records.parse_next_at_ns":     func(r *Record) { r.Audit.ParseNextAtNS = moreInt(r.Audit.ParseNextAtNS) },
	"audit_records.capture_version": func(r *Record) {
		r.Audit.CaptureVersion++
		r.Headers.CaptureVersion++
	},
	"audit_records.user_agent_enc": func(r *Record) { r.Audit.UserAgent[0].Value += "x" },

	"http_stages.audit_id":         func(r *Record) { r.Audit.AuditID += "x" },
	"http_stages.stage":            func(r *Record) { r.Stages[1].Stage = storage.StageResponseSent },
	"http_stages.state":            func(r *Record) { r.Stages[0].State += "x" },
	"http_stages.proto":            func(r *Record) { r.Stages[0].Proto += "x" },
	"http_stages.method":           func(r *Record) { r.Stages[0].Method += "x" },
	"http_stages.host":             func(r *Record) { r.Stages[0].Host += "x" },
	"http_stages.status_code":      func(r *Record) { r.Stages[0].StatusCode = small(*r.Stages[0].StatusCode + 1) },
	"http_stages.content_length":   func(r *Record) { r.Stages[0].ContentLength = moreInt(r.Stages[0].ContentLength) },
	"http_stages.started_at_ns":    func(r *Record) { r.Stages[0].StartedAtNS++ },
	"http_stages.ended_at_ns":      func(r *Record) { r.Stages[0].EndedAtNS = moreInt(r.Stages[0].EndedAtNS) },
	"http_stages.error_code":       func(r *Record) { r.Stages[0].ErrorCode = moreText(r.Stages[0].ErrorCode) },
	"http_stages.content_type":     func(r *Record) { r.Stages[0].ContentType = moreText(r.Stages[0].ContentType) },
	"http_stages.content_encoding": func(r *Record) { r.Stages[0].ContentEncoding = moreText(r.Stages[0].ContentEncoding) },

	"http_headers.audit_id":     func(r *Record) { r.Audit.AuditID += "x" },
	"http_headers.stage":        func(r *Record) { r.Headers.Values[3].Stage = storage.StageResponseSent },
	"http_headers.kind":         func(r *Record) { r.Headers.Values[1].Kind = storage.HeaderKindTrailer },
	"http_headers.name":         func(r *Record) { r.Headers.Values[1].Name += "x" },
	"http_headers.value_index":  func(r *Record) { r.Headers.Values[1].ValueIndex++ },
	"http_headers.value_length": func(r *Record) { r.Headers.Values[0].Value.Length++ },
	"http_headers.value_enc":    func(r *Record) { r.Headers.Values[1].Value.Value += "x" },

	"http_header_blocks.audit_id":         func(r *Record) { r.Headers.BlockPresent, r.Headers.BlockStages = false, nil },
	"http_header_blocks.block_enc":        func(r *Record) { r.Headers.BlockStages = r.Headers.BlockStages[:1] },
	"http_header_blocks.compression":      nil,
	"http_header_blocks.plaintext_length": nil,

	"body_streams.audit_id":                 func(r *Record) { r.Audit.AuditID += "x" },
	"body_streams.stage":                    func(r *Record) { r.Bodies[0].Stage = storage.StageResponseSent },
	"body_streams.source_stage":             func(r *Record) { r.Bodies[0].SourceStage = storage.StageResponseSent },
	"body_streams.observed_length":          func(r *Record) { r.Bodies[0].ObservedLength++ },
	"body_streams.stored_length":            func(r *Record) { r.Bodies[0].StoredLength++ },
	"body_streams.sha256":                   func(r *Record) { r.Bodies[0].SHA256 = flipHash(r.Bodies[0].SHA256) },
	"body_streams.hash_complete":            func(r *Record) { r.Bodies[0].HashComplete = !r.Bodies[0].HashComplete },
	"body_streams.eof_seen":                 func(r *Record) { r.Bodies[0].EOFSeen = !r.Bodies[0].EOFSeen },
	"body_streams.state":                    func(r *Record) { r.Bodies[0].State += "x" },
	"body_streams.retention_state":          func(r *Record) { r.Bodies[0].RetentionState += "x" },
	"body_streams.first_observed_at_ns":     func(r *Record) { r.Bodies[0].FirstObservedAtNS = moreInt(r.Bodies[0].FirstObservedAtNS) },
	"body_streams.last_observed_at_ns":      func(r *Record) { r.Bodies[0].LastObservedAtNS = moreInt(r.Bodies[0].LastObservedAtNS) },
	"body_streams.chunk_count":              func(r *Record) { r.Bodies[0].ChunkCount++ },
	"body_streams.stream_event_count":       func(r *Record) { r.Bodies[0].StreamEventCount++ },
	"body_streams.stream_timeline_complete": func(r *Record) { r.Bodies[0].StreamTimelineComplete = !r.Bodies[0].StreamTimelineComplete },
	"body_streams.error_code":               func(r *Record) { r.Bodies[0].ErrorCode = moreText(r.Bodies[0].ErrorCode) },

	"body_chunks.audit_id":         func(r *Record) { r.Audit.AuditID += "x" },
	"body_chunks.stage":            func(r *Record) { r.RawChunks[0].Stage = storage.StageResponseSent },
	"body_chunks.seq":              func(r *Record) { r.RawChunks[0].Seq++ },
	"body_chunks.offset":           func(r *Record) { r.RawChunks[0].Offset++ },
	"body_chunks.plaintext_length": func(r *Record) { r.RawChunks[0].PlaintextLength++ },
	"body_chunks.observed_at_ns":   func(r *Record) { r.RawChunks[0].ObservedAtNS++ },
	"body_chunks.data_enc":         func(r *Record) { r.RawChunks[0].SHA256 = flipSum(r.RawChunks[0].SHA256) },
	"body_chunks.encoded_length":   nil,
	"body_chunks.compression":      nil,

	"stream_timelines.audit_id":          func(r *Record) { r.Audit.AuditID += "x" },
	"stream_timelines.stage":             func(r *Record) { r.Timelines[0].Stage = storage.StageResponseSent },
	"stream_timelines.event_count":       func(r *Record) { r.Timelines[0].EventCount++ },
	"stream_timelines.first_event_at_ns": func(r *Record) { r.Timelines[0].FirstEventAtNS = moreInt(r.Timelines[0].FirstEventAtNS) },
	"stream_timelines.last_event_at_ns":  func(r *Record) { r.Timelines[0].LastEventAtNS = moreInt(r.Timelines[0].LastEventAtNS) },
	"stream_timelines.timeline_complete": func(r *Record) { r.Timelines[0].Complete = !r.Timelines[0].Complete },
	"stream_timelines.compression":       nil,
	"stream_timelines.plaintext_length":  func(r *Record) { r.Timelines[0].PlaintextLength++ },
	"stream_timelines.timeline_enc":      func(r *Record) { r.Timelines[0].Plaintext = append(r.Timelines[0].Plaintext, 9) },

	"parsed_results.audit_id":             func(r *Record) { r.Audit.AuditID += "x" },
	"parsed_results.parser_name":          func(r *Record) { r.ParsedResult.ParserName += "x" },
	"parsed_results.parser_version":       func(r *Record) { r.ParsedResult.ParserVersion += "x" },
	"parsed_results.status":               func(r *Record) { r.ParsedResult.Status += "x" },
	"parsed_results.request_model":        func(r *Record) { r.ParsedResult.RequestModel = moreText(r.ParsedResult.RequestModel) },
	"parsed_results.response_model":       func(r *Record) { r.ParsedResult.ResponseModel = moreText(r.ParsedResult.ResponseModel) },
	"parsed_results.requested_stream":     func(r *Record) { r.ParsedResult.RequestedStream = notFlag(r.ParsedResult.RequestedStream) },
	"parsed_results.observed_stream":      func(r *Record) { r.ParsedResult.ObservedStream = notFlag(r.ParsedResult.ObservedStream) },
	"parsed_results.response_id":          func(r *Record) { r.ParsedResult.ResponseID = moreText(r.ParsedResult.ResponseID) },
	"parsed_results.usage_input":          func(r *Record) { r.ParsedResult.UsageInput = moreInt(r.ParsedResult.UsageInput) },
	"parsed_results.usage_output":         func(r *Record) { r.ParsedResult.UsageOutput = moreInt(r.ParsedResult.UsageOutput) },
	"parsed_results.usage_total":          func(r *Record) { r.ParsedResult.UsageTotal = moreInt(r.ParsedResult.UsageTotal) },
	"parsed_results.error_type":           func(r *Record) { r.ParsedResult.ErrorType = moreText(r.ParsedResult.ErrorType) },
	"parsed_results.error_code":           func(r *Record) { r.ParsedResult.ErrorCode = moreText(r.ParsedResult.ErrorCode) },
	"parsed_results.message_count":        func(r *Record) { r.ParsedResult.MessageCount = moreInt(r.ParsedResult.MessageCount) },
	"parsed_results.tool_call_count":      func(r *Record) { r.ParsedResult.ToolCallCount = moreInt(r.ParsedResult.ToolCallCount) },
	"parsed_results.has_tool_call":        func(r *Record) { r.ParsedResult.HasToolCall = notFlag(r.ParsedResult.HasToolCall) },
	"parsed_results.parsed_json_enc":      func(r *Record) { r.ParsedResult.ParsedJSON = append(r.ParsedResult.ParsedJSON, ' ') },
	"parsed_results.parsed_at_ns":         func(r *Record) { r.ParsedResult.ParsedAtNS++ },
	"parsed_results.upstream_error_class": func(r *Record) { r.ParsedResult.UpstreamErrorClass = moreText(r.ParsedResult.UpstreamErrorClass) },

	"token_links.audit_id":        func(r *Record) { r.Audit.AuditID += "x" },
	"token_links.newapi_user_id":  func(r *Record) { r.TokenLink.NewAPIUserID++ },
	"token_links.username":        func(r *Record) { r.TokenLink.Username += "x" },
	"token_links.newapi_token_id": func(r *Record) { r.TokenLink.NewAPITokenID++ },
	"token_links.token_name":      func(r *Record) { r.TokenLink.TokenName += "x" },
	"token_links.linked_at_ns":    func(r *Record) { r.TokenLink.LinkedAtNS++ },
	"token_links.billing_state":   func(r *Record) { r.TokenLink.BillingState += "x" },
	"token_links.quota":           func(r *Record) { r.TokenLink.Quota = moreInt(r.TokenLink.Quota) },
	"token_links.quota_per_unit": func(r *Record) {
		value := *r.TokenLink.QuotaPerUnit * 2
		r.TokenLink.QuotaPerUnit = &value
	},
	"token_links.billed_prompt_tokens":     func(r *Record) { r.TokenLink.BilledPromptTokens = moreInt(r.TokenLink.BilledPromptTokens) },
	"token_links.billed_completion_tokens": func(r *Record) { r.TokenLink.BilledCompletionTokens = moreInt(r.TokenLink.BilledCompletionTokens) },
	"token_links.billing_attempts":         func(r *Record) { r.TokenLink.BillingAttempts++ },

	"turns.turn_id":                     func(r *Record) { r.Turn.Row.TurnID += "x" },
	"turns.audit_id":                    func(r *Record) { r.Audit.AuditID += "x" },
	"turns.conversation_id":             func(r *Record) { r.Turn.Row.ConversationID += "x"; r.Conversation.ConversationID += "x" },
	"turns.parent_turn_id":              func(r *Record) { r.Turn.Row.ParentTurnID = moreText(r.Turn.Row.ParentTurnID) },
	"turns.parent_base":                 func(r *Record) { r.Turn.Row.ParentBase += "x" },
	"turns.link_reason":                 func(r *Record) { r.Turn.Row.LinkReason += "x" },
	"turns.link_confidence":             func(r *Record) { r.Turn.Row.LinkConfidence++ },
	"turns.request_layout":              func(r *Record) { r.Turn.Row.RequestLayout += "x" },
	"turns.response_layout":             func(r *Record) { r.Turn.Row.ResponseLayout += "x" },
	"turns.request_envelope_hash":       func(r *Record) { r.Turn.Row.RequestEnvelopeHash = flipHash(r.Turn.Row.RequestEnvelopeHash) },
	"turns.response_envelope_hash":      func(r *Record) { r.Turn.Row.ResponseEnvelopeHash = flipHash(r.Turn.Row.ResponseEnvelopeHash) },
	"turns.request_item_count":          func(r *Record) { r.Turn.Row.RequestItemCount++ },
	"turns.response_item_count":         func(r *Record) { r.Turn.Row.ResponseItemCount++ },
	"turns.request_sequence_hash":       func(r *Record) { r.Turn.Row.RequestSequenceHash = flipHash(r.Turn.Row.RequestSequenceHash) },
	"turns.response_sequence_hash":      func(r *Record) { r.Turn.Row.ResponseSequenceHash = flipHash(r.Turn.Row.ResponseSequenceHash) },
	"turns.request_reconstruction_hash": func(r *Record) { r.Turn.Row.RequestReconstructionHash = flipHash(r.Turn.Row.RequestReconstructionHash) },
	"turns.response_reconstruction_hash": func(r *Record) {
		r.Turn.Row.ResponseReconstructionHash = flipHash(r.Turn.Row.ResponseReconstructionHash)
	},
	"turns.reconstruction_status": func(r *Record) { r.Turn.Row.ReconstructionStatus += "x" },
	"turns.previous_response_id":  func(r *Record) { r.Turn.Row.PreviousResponseID = moreText(r.Turn.Row.PreviousResponseID) },
	"turns.response_id":           func(r *Record) { r.Turn.Row.ResponseID = moreText(r.Turn.Row.ResponseID) },
	"turns.created_at_ns":         func(r *Record) { r.Turn.Row.CreatedAtNS++ },

	// The context operations are archived but not digested (Q6 甲): the
	// digest covers the materialised refs, which these mutations leave alone.
	"turn_context_ops.turn_id":       func(r *Record) { deltaOps(r)[0].OpIndex = 0 },
	"turn_context_ops.op_index":      func(r *Record) { ops := deltaOps(r); ops[0].OpIndex, ops[1].OpIndex = 1, 0 },
	"turn_context_ops.operation":     func(r *Record) { deltaOps(r)[0].Operation = "delete" },
	"turn_context_ops.item_count":    func(r *Record) { deltaOps(r)[0].ItemCount = 5 },
	"turn_context_ops.slot":          func(r *Record) { deltaOps(r)[0].Slot = text("other") },
	"turn_context_ops.object_hash":   func(r *Record) { deltaOps(r)[0].ObjectHash = hashOf(0xee) },
	"turn_context_ops.semantic_hash": func(r *Record) { deltaOps(r)[0].SemanticHash = hashOf(0xef) },

	"turn_response_items.turn_id":       func(r *Record) { r.Turn.Row.TurnID += "x" },
	"turn_response_items.ordinal":       func(r *Record) { r.Turn.ResponseItems[0].Ordinal++ },
	"turn_response_items.slot":          func(r *Record) { r.Turn.ResponseItems[0].Slot += "x" },
	"turn_response_items.object_hash":   func(r *Record) { r.Turn.ResponseItems[0].ObjectHash = flipHash(r.Turn.ResponseItems[0].ObjectHash) },
	"turn_response_items.semantic_hash": func(r *Record) { r.Turn.ResponseItems[0].SemanticHash = flipHash(r.Turn.ResponseItems[0].SemanticHash) },

	"conversations.conversation_id": func(r *Record) { r.Conversation.ConversationID += "x"; r.Turn.Row.ConversationID += "x" },
	"conversations.protocol":        func(r *Record) { r.Conversation.Protocol += "x" },
	"conversations.key_hash":        func(r *Record) { r.Conversation.KeyHash = flipHash(r.Conversation.KeyHash) },
	"conversations.created_at_ns":   func(r *Record) { r.Conversation.CreatedAtNS++ },
	"conversations.updated_at_ns":   nil,

	"content_objects.object_hash":      func(r *Record) { r.Turn.Objects[4].Hash = flipHash(r.Turn.Objects[4].Hash) },
	"content_objects.semantic_hash":    func(r *Record) { r.Turn.Objects[0].SemanticHash = flipHash(r.Turn.Objects[0].SemanticHash) },
	"content_objects.kind":             func(r *Record) { r.Turn.Objects[0].Kind += "x" },
	"content_objects.compression":      nil,
	"content_objects.plaintext_length": func(r *Record) { r.Turn.Objects[0].PlaintextLength++ },
	"content_objects.encoded_length":   nil,
	"content_objects.data_enc":         nil,
	"content_objects.created_at_ns":    nil,

	"binary_objects.binary_hash":      func(r *Record) { r.Turn.Binaries[0].Hash = flipHash(r.Turn.Binaries[0].Hash) },
	"binary_objects.media_type":       func(r *Record) { r.Turn.Binaries[0].MediaType += "x" },
	"binary_objects.compression":      nil,
	"binary_objects.plaintext_length": func(r *Record) { r.Turn.Binaries[0].PlaintextLength++ },
	"binary_objects.encoded_length":   nil,
	"binary_objects.data_enc":         nil,
	"binary_objects.created_at_ns":    nil,

	"content_binary_refs.object_hash":  func(r *Record) { r.Turn.BinaryRefs[0].ObjectHash = flipHash(r.Turn.BinaryRefs[0].ObjectHash) },
	"content_binary_refs.json_pointer": func(r *Record) { r.Turn.BinaryRefs[0].JSONPointer += "x" },
	"content_binary_refs.binary_hash":  func(r *Record) { r.Turn.BinaryRefs[0].BinaryHash = flipHash(r.Turn.BinaryRefs[0].BinaryHash) },
	"content_binary_refs.media_type":   func(r *Record) { r.Turn.BinaryRefs[0].MediaType += "x" },
	"content_binary_refs.encoding":     func(r *Record) { r.Turn.BinaryRefs[0].Encoding += "x" },

	"content_external_refs.object_hash":  func(r *Record) { r.Turn.ExternalRefs[0].ObjectHash = flipHash(r.Turn.ExternalRefs[0].ObjectHash) },
	"content_external_refs.json_pointer": func(r *Record) { r.Turn.ExternalRefs[0].JSONPointer += "x" },
	"content_external_refs.ref_kind":     func(r *Record) { r.Turn.ExternalRefs[0].RefKind += "x" },
	"content_external_refs.value_hash":   func(r *Record) { r.Turn.ExternalRefs[0].ValueHash = flipHash(r.Turn.ExternalRefs[0].ValueHash) },
	"content_external_refs.value_enc":    func(r *Record) { r.Turn.ExternalRefs[0].Value += "x" },

	"audit_project_identity.audit_id":         func(r *Record) { r.Audit.AuditID += "x" },
	"audit_project_identity.identity_version": func(r *Record) { r.ProjectIdentity.IdentityVersion++ },
	"audit_project_identity.extracted_at_ns":  func(r *Record) { r.ProjectIdentity.ExtractedAtNS++ },
	"audit_project_identity.source":           func(r *Record) { r.ProjectIdentity.Source += "x" },
	"audit_project_identity.body_scanned":     func(r *Record) { r.ProjectIdentity.BodyScanned = !r.ProjectIdentity.BodyScanned },
	"audit_project_identity.identity_fpr":     func(r *Record) { r.ProjectIdentity.IdentityFPR = flipHash(r.ProjectIdentity.IdentityFPR) },
	"audit_project_identity.remote_fpr":       func(r *Record) { r.ProjectIdentity.RemoteFPR = flipHash(r.ProjectIdentity.RemoteFPR) },
	"audit_project_identity.repo_root_fpr":    func(r *Record) { r.ProjectIdentity.RepoRootFPR = flipHash(r.ProjectIdentity.RepoRootFPR) },
	"audit_project_identity.cwd_fpr":          func(r *Record) { r.ProjectIdentity.CwdFPR = flipHash(r.ProjectIdentity.CwdFPR) },
	"audit_project_identity.identity_enc":     func(r *Record) { r.ProjectIdentity.Identity = append(r.ProjectIdentity.Identity, ' ') },

	"integrity_events.sequence":       func(r *Record) { r.IntegrityEvents[1].Sequence++ },
	"integrity_events.audit_id":       func(r *Record) { r.Audit.AuditID += "x" },
	"integrity_events.event_type":     func(r *Record) { r.IntegrityEvents[0].EventType += "x" },
	"integrity_events.previous_mac":   func(r *Record) { r.IntegrityEvents[0].PreviousMAC = flipHash(r.IntegrityEvents[0].PreviousMAC) },
	"integrity_events.payload_digest": func(r *Record) { r.IntegrityEvents[0].PayloadDigest = flipHash(r.IntegrityEvents[0].PayloadDigest) },
	"integrity_events.event_mac":      func(r *Record) { r.IntegrityEvents[0].EventMAC = flipHash(r.IntegrityEvents[0].EventMAC) },
	"integrity_events.created_at_ns":  func(r *Record) { r.IntegrityEvents[0].CreatedAtNS++ },

	"audit_gaps.id":            nil,
	"audit_gaps.started_at_ns": nil,
	"audit_gaps.ended_at_ns":   nil,
	"audit_gaps.reason":        nil,
	"audit_gaps.request_count": nil,
	"audit_gaps.detail":        nil,
	"audit_gaps.created_at_ns": nil,
}

// deltaOps switches the record's turn to delta form (its materialised refs
// stay as they are) and returns the operations.
func deltaOps(r *Record) []ContextOp {
	if r.Turn.Context.Form != ContextDelta {
		slot := r.Turn.RequestRefs[0].Slot
		r.Turn.Context = RequestContext{Form: ContextDelta, Ops: []ContextOp{
			{OpIndex: 0, Operation: "insert", ItemCount: 1, Slot: &slot, ObjectHash: r.Turn.RequestRefs[0].ObjectHash, SemanticHash: r.Turn.RequestRefs[0].SemanticHash},
			{OpIndex: 1, Operation: "retain", ItemCount: 1},
		}}
	}
	return r.Turn.Context.Ops
}

func mustDigest(t *testing.T, record *Record) [32]byte {
	t.Helper()
	digest, err := Digest(record)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

// Every column of the specification is decided: a digest column changes the
// digest, an archived column does not, and the mutator table cannot drift
// from Columns in either direction.
func TestDigestCoversTheSpecification(t *testing.T) {
	baseline := mustDigest(t, fullRecord(t))
	seen := map[string]bool{}
	for _, column := range Columns {
		key := column.Table + "." + column.Name
		seen[key] = true
		mutate, ok := digestMutators[key]
		if !ok {
			t.Errorf("%s: no mutator; decide how the record carries it", key)
			continue
		}
		if mutate == nil {
			if column.Class == ClassDigest {
				t.Errorf("%s: digest column without a mutator", key)
			}
			continue
		}
		if column.Class == ClassExcluded {
			t.Errorf("%s: excluded column with a mutator", key)
			continue
		}
		record := fullRecord(t)
		if column.Class == ClassArchived {
			deltaOps(record)
		}
		before := mustDigest(t, record)
		mutate(record)
		_ = record.Canonicalize()
		after, err := Digest(record)
		if err != nil {
			t.Errorf("%s: mutated record rejected: %v", key, err)
			continue
		}
		switch column.Class {
		case ClassDigest:
			if after == before {
				t.Errorf("%s: digest column did not change the digest", key)
			}
		case ClassArchived:
			if after != before {
				t.Errorf("%s: column outside the digest changed it", key)
			}
		}
	}
	for key := range digestMutators {
		if !seen[key] {
			t.Errorf("%s: mutator for a column the specification does not have", key)
		}
	}
	if baseline != mustDigest(t, fullRecord(t)) {
		t.Fatal("digest is not deterministic")
	}
	record := fullRecord(t)
	record.Revision = 7
	if mustDigest(t, record) != baseline {
		t.Fatal("revision changed the digest")
	}
}

// NULL and an empty value give different digests (Q9 item 1).
func TestDigestSeparatesNullFromEmpty(t *testing.T) {
	cases := map[string][2]func(*Record){
		"blocked_by":        {func(r *Record) { r.Audit.BlockedBy = nil }, func(r *Record) { r.Audit.BlockedBy = text("") }},
		"status_code":       {func(r *Record) { r.Audit.StatusCode = nil }, func(r *Record) { r.Audit.StatusCode = integer(0) }},
		"api_key_fpr":       {func(r *Record) { r.Audit.APIKeyFPR = nil }, func(r *Record) { r.Audit.APIKeyFPR = []byte{} }},
		"block_stages":      {func(r *Record) { r.Headers.BlockStages = nil }, func(r *Record) { r.Headers.BlockStages = []string{} }},
		"body sha256":       {func(r *Record) { r.Bodies[0].SHA256 = nil }, func(r *Record) { r.Bodies[0].SHA256 = []byte{} }},
		"timeline":          {func(r *Record) { r.Timelines[0].Plaintext = nil }, func(r *Record) { r.Timelines[0].Plaintext = []byte{} }},
		"parsed_json":       {func(r *Record) { r.ParsedResult.ParsedJSON = nil }, func(r *Record) { r.ParsedResult.ParsedJSON = []byte{} }},
		"requested_stream":  {func(r *Record) { r.ParsedResult.RequestedStream = nil }, func(r *Record) { r.ParsedResult.RequestedStream = boolPtr(false) }},
		"quota_per_unit":    {func(r *Record) { r.TokenLink.QuotaPerUnit = nil }, func(r *Record) { zero := 0.0; r.TokenLink.QuotaPerUnit = &zero }},
		"parent_turn_id":    {func(r *Record) { r.Turn.Row.ParentTurnID = nil }, func(r *Record) { r.Turn.Row.ParentTurnID = text("") }},
		"key_hash":          {func(r *Record) { r.Conversation.KeyHash = nil }, func(r *Record) { r.Conversation.KeyHash = []byte{} }},
		"identity":          {func(r *Record) { r.ProjectIdentity.Identity = nil }, func(r *Record) { r.ProjectIdentity.Identity = []byte{} }},
		"previous_mac":      {func(r *Record) { r.IntegrityEvents[0].PreviousMAC = nil }, func(r *Record) { r.IntegrityEvents[0].PreviousMAC = []byte{} }},
		"stage error_code":  {func(r *Record) { r.Stages[0].ErrorCode = nil }, func(r *Record) { r.Stages[0].ErrorCode = text("") }},
		"parsed_results":    {func(r *Record) { r.ParsedResult = nil }, func(r *Record) {}},
		"token_links":       {func(r *Record) { r.TokenLink = nil }, func(r *Record) {}},
		"user_agent absent": {func(r *Record) { r.Audit.UserAgent = nil }, func(r *Record) { r.Audit.UserAgent = r.Audit.UserAgent[:1] }},
	}
	for name, pair := range cases {
		null, empty := fullRecord(t), fullRecord(t)
		pair[0](null)
		pair[1](empty)
		if mustDigest(t, null) == mustDigest(t, empty) {
			t.Errorf("%s: NULL and empty have the same digest", name)
		}
	}
	// A credential and a plain value with the same bytes differ.
	plain, credential := fullRecord(t), fullRecord(t)
	plain.Headers.Values[1].Value = ProjectedValue{Value: ""}
	credential.Headers.Values[1].Value = ProjectedValue{Omitted: true, Fingerprint: newTestKeys().CredentialFingerprint(nil)}
	if mustDigest(t, plain) == mustDigest(t, credential) {
		t.Error("plain and credential forms have the same digest")
	}
}

// Digest refuses a record it cannot cover exactly: unmaterialised turns and
// lists out of canonical order.
func TestDigestRejectsIncompleteRecords(t *testing.T) {
	record := fullRecord(t)
	record.Turn.RequestRefs = nil
	if _, err := Digest(record); err == nil {
		t.Fatal("unmaterialised turn accepted")
	}
	record = fullRecord(t)
	record.Stages[0], record.Stages[1] = record.Stages[1], record.Stages[0]
	if _, err := Digest(record); err == nil {
		t.Fatal("stages out of order accepted")
	}
	record = fullRecord(t)
	record.Headers.Values = append(record.Headers.Values, record.Headers.Values[0])
	if err := record.Canonicalize(); err == nil {
		t.Fatal("duplicate header value accepted")
	}
	record = fullRecord(t)
	record.ParsedResult.ParsedJSONRef = &ParsedJSONRef{}
	if _, err := Digest(record); err == nil {
		t.Fatal("parsed_json inline and by reference accepted")
	}
}

// handDigestInput spells out E.2 for minimalRecord with one stage, one
// credential header, one plain and one credential User-Agent, and a
// Request-URI with one segment of each kind, independently of digestEncoder:
// a field written out of order or with the wrong primitive differs here.
func handDigestInput(r *Record) []byte {
	var out bytes.Buffer
	u64 := func(v uint64) { var b [8]byte; binary.BigEndian.PutUint64(b[:], v); out.Write(b[:]) }
	B := func(x []byte) { u64(uint64(len(x))); out.Write(x) }
	T := func(s string) { B([]byte(s)) }
	I := func(v int64) { var b [8]byte; binary.BigEndian.PutUint64(b[:], uint64(v)); B(b[:]) }
	H := func(p []byte) { sum := sha256.Sum256(p); B(sum[:]) }
	null := func() { out.WriteByte(0) }
	some := func() { out.WriteByte(1) }
	V := func(value ProjectedValue) {
		if value.Omitted {
			out.WriteByte(1)
			I(value.Length)
			B(value.Fingerprint[:])
		} else {
			out.WriteByte(0)
			H([]byte(value.Value))
		}
	}
	a := r.Audit
	out.WriteString("llmapi-logger/archive-record/v0\x00")
	T(a.AuditID)
	T("audit_records")
	I(a.SchemaGeneration)
	I(a.StartedAtNS)
	I(a.EndedAtNS)
	T(a.RouteID)
	T(a.Protocol)
	T(a.ParserName)
	T(a.Method)
	T(a.Path)
	T("request_uri")
	T(a.RequestURI.Path)
	I(1)
	I(2)
	out.WriteByte(0)
	T(a.RequestURI.Segments[0].Raw)
	out.WriteByte(1)
	T(a.RequestURI.Segments[1].RawName)
	I(1)
	I(a.RequestURI.Segments[1].Length)
	B(a.RequestURI.Segments[1].Fingerprint[:])
	T(a.Mode)
	some()
	I(*a.StatusCode)
	null() // ttft_ns
	T(a.ForwardStatus)
	T(a.CaptureStatus)
	T(a.ParseStatus)
	null() // blocked_by
	null() // block_code
	null() // error_code
	null() // newapi_request_id
	T(a.CallerStatus)
	I(a.CallerAttempts)
	null() // caller_next_at_ns
	null() // caller_updated_at_ns
	null() // api_key_fpr
	I(a.ParseSaveFailures)
	null() // parse_next_at_ns
	I(a.CaptureVersion)
	some()
	I(2)
	V(a.UserAgent[0])
	V(a.UserAgent[1])
	T("http_stages")
	I(1)
	s := r.Stages[0]
	T(s.Stage)
	T(s.State)
	T(s.Proto)
	T(s.Method)
	T(s.Host)
	null() // status_code
	null() // content_length
	I(s.StartedAtNS)
	null() // ended_at_ns
	null() // error_code
	some()
	T(*s.ContentType)
	null() // content_encoding
	T("headers")
	I(r.Headers.CaptureVersion)
	I(1)
	some()
	I(1)
	T(r.Headers.BlockStages[0])
	I(1)
	h := r.Headers.Values[0]
	T(h.Stage)
	T(h.Kind)
	T(h.Name)
	I(h.ValueIndex)
	V(h.Value)
	T("body_streams")
	I(0)
	T("body_chunks")
	I(0)
	T("stream_timelines")
	I(0)
	T("parsed_results")
	null()
	T("token_links")
	null()
	T("turn")
	null()
	T("conversation")
	null()
	T("audit_project_identity")
	null()
	T("integrity_events")
	I(0)
	return out.Bytes()
}

func handRecord() *Record {
	keys := newTestKeys()
	record := minimalRecord()
	record.Audit.CaptureVersion = storage.CaptureVersion2
	record.Audit.StatusCode = integer(429)
	record.Audit.RequestURI = ProjectRequestURI(keys, []byte("/v1beta/models/x:generateContent?alt=sse&key=AIza-example"))
	record.Audit.UserAgent = ProjectUserAgent(keys, []string{"client/3", "Bearer sk-ua"})
	record.Stages = []Stage{{HTTPStage: storage.HTTPStage{Stage: storage.StageRequestReceived, State: storage.StageStateComplete,
		Proto: "HTTP/2.0", Method: "POST", Host: "api.example.com", StartedAtNS: 150}, ContentType: text("application/json")}}
	record.Headers = Headers{CaptureVersion: storage.CaptureVersion2, BlockPresent: true, BlockStages: []string{storage.StageRequestReceived},
		Values: ProjectHeaders(keys, []headerblock.Value{{Stage: storage.StageRequestReceived, Kind: storage.HeaderKindHeader, Name: "X-Goog-Api-Key", Value: []byte("AIza-example")}})}
	return record
}

func TestDigestMatchesTheHandWrittenSequence(t *testing.T) {
	record := handRecord()
	if !record.Audit.RequestURI.Segments[1].Credential || !record.Audit.UserAgent[1].Omitted || !record.Headers.Values[0].Value.Omitted {
		t.Fatal("fixture lost its credentials")
	}
	var encoded bytes.Buffer
	if err := writeDigestInput(&encoded, record); err != nil {
		t.Fatal(err)
	}
	if want := handDigestInput(record); !bytes.Equal(encoded.Bytes(), want) {
		t.Fatalf("digest input differs from E.2\n got  %x\n want %x", encoded.Bytes(), want)
	}
	if mustDigest(t, record) != sha256.Sum256(handDigestInput(record)) {
		t.Fatal("digest is not SHA-256 of its input")
	}
}

// The fixed vectors: the full record's line and digest, and the hand-built
// record's digest, pinned in testdata for the format document.
func TestDigestVectors(t *testing.T) {
	vectors := map[string]*Record{"record_full_v0": fullRecord(t), "record_hand_v0": handRecord()}
	for name, record := range vectors {
		line, digest, parts, err := EncodeLine(record)
		if err != nil || len(parts) != 0 {
			t.Fatalf("%s: %v parts=%d", name, err, len(parts))
		}
		checkVector(t, name+".jsonl", append(line, '\n'))
		checkVector(t, name+".digest", []byte(hex.EncodeToString(digest[:])+"\n"))
	}
}

func checkVector(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(got, want) {
		t.Fatalf("%s differs from the pinned vector:\n got  %s\n want %s", name, strings.TrimSpace(string(got)), strings.TrimSpace(string(want)))
	}
}
