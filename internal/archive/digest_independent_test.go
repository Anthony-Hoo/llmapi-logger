package archive_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math"
	"testing"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/storage"
)

// An independent check of the record digest (design E.1, E.2; R.4 item 11):
// one record with every one of the twelve sections non-empty, and the E.2
// byte sequence written out by hand from the design's text, with nothing
// from the archive package but the record type and Digest. The encoder
// helpers below are this file's own reading of E.1.

// e1 writes the E.1 notation.
type e1 struct{ bytes.Buffer }

func (w *e1) raw(data []byte) { w.Write(data) }

// B(x) = u64be(len(x)) || x
func (w *e1) B(data []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(data)))
	w.Write(length[:])
	w.Write(data)
}

// T(s) = B(the bytes of s)
func (w *e1) T(text string) { w.B([]byte(text)) }

// I(v) = B(the 8-byte big-endian two's complement of v)
func (w *e1) I(value int64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(value))
	w.B(encoded[:])
}

// N(e): 0x00 for NULL, 0x01 followed by e otherwise.
func (w *e1) null()    { w.WriteByte(0x00) }
func (w *e1) present() { w.WriteByte(0x01) }

// H(p) = B(SHA-256(p))
func (w *e1) H(plaintext []byte) {
	sum := sha256.Sum256(plaintext)
	w.B(sum[:])
}

// L(n) = I(n)
func (w *e1) L(count int) { w.I(int64(count)) }

// M(s) = T(s)
func (w *e1) M(name string) { w.T(name) }

// V(value): 0x00 H(value) for a value that is not a credential,
// 0x01 I(length) B(value_fpr) for a credential.
func (w *e1) Vplain(value string) {
	w.WriteByte(0x00)
	w.H([]byte(value))
}

func (w *e1) Vcredential(length int64, fpr []byte) {
	w.WriteByte(0x01)
	w.I(length)
	w.B(fpr)
}

func fixedBytes(seed byte, size int) []byte {
	out := make([]byte, size)
	for index := range out {
		out[index] = seed + byte(index)
	}
	return out
}

func fixed32(seed byte) [32]byte {
	var out [32]byte
	copy(out[:], fixedBytes(seed, 32))
	return out
}

func text(value string) *string { return &value }
func number(value int64) *int64 { return &value }
func small(value int) *int      { return &value }
func truth(value bool) *bool    { return &value }

// Literal field values of the record, shared by the record and the hand
// sequence.
var (
	vAuditID         = "audit-vector-0001"
	vStageIn         = storage.StageRequestReceived
	vStageOut        = storage.StageRequestSent
	vStageUp         = storage.StageResponseReceived
	vStageDown       = storage.StageResponseSent
	vAPIKeyFPR       = fixedBytes(0x10, 32)
	vUAFpr           = fixed32(0x20)
	vURIFpr          = fixed32(0x30)
	vAuthFpr         = fixed32(0x40)
	vBodySHA         = fixedBytes(0x50, 32)
	vChunk0          = []byte("{\"model\":\"m\",")
	vChunk1          = []byte("\"messages\":[]}")
	vTimeline        = []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	vParsedJSON      = []byte(`{"status":"ok","conversation":{"messages":[]}}`)
	vRequestEnvelope = fixedBytes(0x60, 32)
	vResponseEnv     = fixedBytes(0x61, 32)
	vReqSeq          = fixedBytes(0x62, 32)
	vRespSeq         = fixedBytes(0x63, 32)
	vReqRecon        = fixedBytes(0x64, 32)
	vRespRecon       = fixedBytes(0x65, 32)
	vObjectA         = append([]byte{0x01}, fixedBytes(0x70, 31)...)
	vObjectB         = append([]byte{0x02}, fixedBytes(0x71, 31)...)
	vSemanticA       = fixedBytes(0x72, 32)
	vSemanticB       = fixedBytes(0x73, 32)
	vBinary          = fixedBytes(0x74, 32)
	vValueHash       = fixedBytes(0x75, 32)
	vKeyHash         = fixedBytes(0x76, 32)
	vIdentityFPR     = fixedBytes(0x77, 32)
	vRemoteFPR       = fixedBytes(0x78, 32)
	vRepoRootFPR     = fixedBytes(0x79, 32)
	vCwdFPR          = fixedBytes(0x7a, 32)
	vIdentity        = []byte(`{"remote":"example.com/repo"}`)
	vMAC1            = fixedBytes(0x80, 32)
	vMAC2            = fixedBytes(0x81, 32)
	vPayload1        = fixedBytes(0x82, 32)
	vPayload2        = fixedBytes(0x83, 32)
	// A header value that is not valid UTF-8: T writes its bytes as they are.
	vOddValue  = "\xff\xfeodd"
	vQuota     = 0.002
	vParentID  = "turn-parent-0001"
	vPrevResp  = "resp-prev"
	vRespID    = "resp-this"
	vTurnID    = "turn-vector-0001"
	vConvID    = "conversation-vector"
	vExternal  = "file-example-0001"
	vMediaType = "image/png"
)

// independentRecord is canonical: every list in the order E.2 names, and
// the turn in delta form with its materialised refs set as the exporter
// sets them (the operations do not enter the digest, Q6).
func independentRecord() *archive.Record {
	slotUser := auditmodel.SlotMessages
	return &archive.Record{
		Revision: 3,
		Audit: archive.AuditRow{
			AuditID: vAuditID, SchemaGeneration: 2, StartedAtNS: 1_000, EndedAtNS: 9_000,
			RouteID: "openai-chat-completions", Protocol: "openai", ParserName: "openai.chat_completions",
			Method: "POST", Path: "/v1/chat/completions",
			RequestURI: archive.RequestURI{Path: "/v1/chat/completions", HasQuery: true, Segments: []archive.QuerySegment{
				{Raw: "alt=sse"},
				{Raw: ""},
				{Credential: true, RawName: "key", HasEquals: true, Length: 11, Fingerprint: vURIFpr},
			}},
			Mode: "available", StatusCode: number(200), TTFTNS: number(321),
			ForwardStatus: storage.ForwardCompleted, CaptureStatus: storage.CaptureComplete, ParseStatus: storage.ParseOK,
			BlockedBy: text("rule-x"), BlockCode: text("code-y"), ErrorCode: text("err-z"), NewAPIRequestID: text("req-0001"),
			CallerStatus: "resolved", CallerAttempts: 2, CallerNextAtNS: number(5_000), CallerUpdatedAtNS: number(6_000),
			APIKeyFPR: vAPIKeyFPR, ParseSaveFailures: 1, ParseNextAtNS: number(7_000), CaptureVersion: 2,
			UserAgent: []archive.ProjectedValue{
				{Value: "client-example/1.0"},
				{Omitted: true, Length: 14, Fingerprint: vUAFpr},
			},
		},
		Stages: []archive.Stage{
			{HTTPStage: storage.HTTPStage{Stage: vStageIn, State: storage.StageStateComplete, Proto: "HTTP/1.1", Method: "POST", Host: "proxy.example.com",
				StatusCode: nil, ContentLength: number(27), StartedAtNS: 1_001, EndedAtNS: number(1_101), ErrorCode: nil},
				ContentType: text("application/json"), ContentEncoding: nil},
			{HTTPStage: storage.HTTPStage{Stage: vStageUp, State: storage.StageStatePartial, Proto: "HTTP/2.0", Method: "POST", Host: "upstream.example.com",
				StatusCode: small(200), ContentLength: nil, StartedAtNS: 1_200, EndedAtNS: nil, ErrorCode: text("cut")},
				ContentType: text("text/event-stream"), ContentEncoding: text("gzip")},
		},
		Headers: archive.Headers{
			CaptureVersion: 2, BlockPresent: true, BlockStages: []string{vStageIn, vStageUp},
			Values: []archive.HeaderValue{
				{Stage: vStageIn, Kind: storage.HeaderKindHeader, Name: "Authorization", ValueIndex: 0,
					Value: archive.ProjectedValue{Omitted: true, Length: 20, Fingerprint: vAuthFpr}},
				{Stage: vStageIn, Kind: storage.HeaderKindHeader, Name: "X-Odd", ValueIndex: 0, Value: archive.ProjectedValue{Value: vOddValue}},
				{Stage: vStageIn, Kind: storage.HeaderKindHeader, Name: "X-Odd", ValueIndex: 1, Value: archive.ProjectedValue{Value: ""}},
				{Stage: vStageUp, Kind: storage.HeaderKindTrailer, Name: "X-Trailer", ValueIndex: 0, Value: archive.ProjectedValue{Value: "done"}},
			},
		},
		Bodies: []storage.BodyStream{
			{Stage: vStageIn, SourceStage: vStageIn, ObservedLength: 27, StoredLength: 27, SHA256: vBodySHA, HashComplete: true, EOFSeen: true,
				State: storage.StageStateComplete, RetentionState: storage.RetentionFull, FirstObservedAtNS: number(1_010), LastObservedAtNS: number(1_020),
				ChunkCount: 2, StreamEventCount: 0, StreamTimelineComplete: false, ErrorCode: nil},
			{Stage: vStageOut, SourceStage: vStageIn, ObservedLength: 27, StoredLength: 0, SHA256: nil, HashComplete: false, EOFSeen: false,
				State: storage.StageStatePartial, RetentionState: storage.RetentionMetadata, FirstObservedAtNS: nil, LastObservedAtNS: nil,
				ChunkCount: 0, StreamEventCount: 4, StreamTimelineComplete: true, ErrorCode: text("body-err")},
		},
		RawChunks: []archive.RawChunk{
			{Stage: vStageIn, Seq: 0, Offset: 0, PlaintextLength: int64(len(vChunk0)), ObservedAtNS: 1_011, SHA256: sha256.Sum256(vChunk0)},
			{Stage: vStageIn, Seq: 1, Offset: int64(len(vChunk0)), PlaintextLength: int64(len(vChunk1)), ObservedAtNS: 1_012, SHA256: sha256.Sum256(vChunk1)},
		},
		Timelines: []archive.Timeline{
			{Stage: vStageIn, EventCount: 0, FirstEventAtNS: nil, LastEventAtNS: nil, Complete: false, PlaintextLength: 0, Plaintext: nil},
			{Stage: vStageUp, EventCount: 3, FirstEventAtNS: number(1_300), LastEventAtNS: number(1_400), Complete: true,
				PlaintextLength: int64(len(vTimeline)), Plaintext: vTimeline},
		},
		ParsedResult: &archive.ParsedResult{
			ParserName: "openai.chat_completions", ParserVersion: "2", Status: storage.ParseOK,
			RequestModel: text("model-in"), ResponseModel: text("model-out"), RequestedStream: truth(true), ObservedStream: truth(false),
			ResponseID: text(vRespID), UsageInput: number(11), UsageOutput: number(22), UsageTotal: number(33),
			ErrorType: text("type-a"), ErrorCode: text("code-b"), UpstreamErrorClass: text("class-c"),
			MessageCount: number(4), ToolCallCount: number(1), HasToolCall: truth(true),
			ParsedJSON: vParsedJSON, ParsedAtNS: 8_000,
		},
		TokenLink: &archive.TokenLink{
			NewAPIUserID: 7, Username: "user-example", NewAPITokenID: 9, TokenName: "token-example", LinkedAtNS: 8_100,
			BillingState: "billed", Quota: number(1234), QuotaPerUnit: &vQuota, BilledPromptTokens: number(10), BilledCompletionTokens: number(20),
			BillingAttempts: 1,
		},
		Turn: &archive.Turn{
			Row: archive.TurnRow{
				TurnID: vTurnID, ConversationID: vConvID, ParentTurnID: text(vParentID), ParentBase: "post_turn", LinkReason: "previous_response_id",
				LinkConfidence: 100, RequestLayout: auditmodel.LayoutMarkerEnvelope, ResponseLayout: auditmodel.LayoutMarkerEnvelope,
				RequestEnvelopeHash: vRequestEnvelope, ResponseEnvelopeHash: vResponseEnv, RequestItemCount: 2, ResponseItemCount: 1,
				RequestSequenceHash: vReqSeq, ResponseSequenceHash: vRespSeq, RequestReconstructionHash: vReqRecon, ResponseReconstructionHash: vRespRecon,
				ReconstructionStatus: "verified", PreviousResponseID: text(vPrevResp), ResponseID: text(vRespID), CreatedAtNS: 8_500,
			},
			Context: archive.RequestContext{Form: archive.ContextDelta, Ops: []archive.ContextOp{
				{OpIndex: 0, Operation: "base", ItemCount: 1},
				{OpIndex: 1, Operation: "append", ItemCount: 1, Slot: &slotUser, ObjectHash: vObjectB, SemanticHash: vSemanticB},
			}},
			RequestRefs: []auditmodel.ObjectRef{
				{Slot: auditmodel.SlotMessages, ObjectHash: vObjectB, SemanticHash: vSemanticB},
				{Slot: auditmodel.SlotMessages, ObjectHash: vObjectA, SemanticHash: vSemanticA},
			},
			ResponseItems: []archive.ResponseItem{{Ordinal: 0, Slot: auditmodel.SlotMessages, ObjectHash: vObjectA, SemanticHash: vSemanticA}},
			Objects: []archive.ObjectMeta{
				{Hash: vObjectA, SemanticHash: vSemanticA, Kind: "message", PlaintextLength: 120},
				{Hash: vObjectB, SemanticHash: vSemanticB, Kind: "image", PlaintextLength: 240},
			},
			BinaryRefs:   []archive.BinaryRef{{ObjectHash: vObjectB, JSONPointer: "/image_url", BinaryHash: vBinary, MediaType: vMediaType, Encoding: "base64"}},
			ExternalRefs: []archive.ExternalRef{{ObjectHash: vObjectA, JSONPointer: "/file_id", RefKind: "file_id", ValueHash: vValueHash, Value: vExternal}},
			Binaries:     []archive.BinaryMeta{{Hash: vBinary, MediaType: vMediaType, PlaintextLength: 68}},
		},
		Conversation: &archive.Conversation{ConversationID: vConvID, Protocol: "openai", KeyHash: vKeyHash, CreatedAtNS: 500},
		ProjectIdentity: &archive.ProjectIdentity{
			IdentityVersion: 1, ExtractedAtNS: 8_200, Source: "body", BodyScanned: true,
			IdentityFPR: vIdentityFPR, RemoteFPR: vRemoteFPR, RepoRootFPR: vRepoRootFPR, CwdFPR: vCwdFPR, Identity: vIdentity,
		},
		IntegrityEvents: []archive.IntegrityEvent{
			{Sequence: 41, EventType: "capture_finalized", PreviousMAC: nil, PayloadDigest: vPayload1, EventMAC: vMAC1, CreatedAtNS: 9_001},
			{Sequence: 42, EventType: "semantic_compacted", PreviousMAC: vMAC1, PayloadDigest: vPayload2, EventMAC: vMAC2, CreatedAtNS: 9_002},
		},
	}
}

// independentSequence is E.2 for independentRecord, field by field from the
// design text.
func independentSequence() []byte {
	w := &e1{}
	w.raw([]byte("llmapi-logger/archive-record/v0\x00"))
	w.T(vAuditID)

	w.M("audit_records")
	w.I(2)     // schema_generation
	w.I(1_000) // started_at_ns
	w.I(9_000) // ended_at_ns
	w.T("openai-chat-completions")
	w.T("openai")
	w.T("openai.chat_completions")
	w.T("POST")
	w.T("/v1/chat/completions")
	// U
	w.M("request_uri")
	w.T("/v1/chat/completions")
	w.I(1) // has_query
	w.L(3)
	w.WriteByte(0x00)
	w.T("alt=sse")
	w.WriteByte(0x00)
	w.T("")
	w.WriteByte(0x01)
	w.T("key")
	w.I(1) // has_equals
	w.I(11)
	w.B(vURIFpr[:])
	w.T("available")
	w.present()
	w.I(200) // status_code
	w.present()
	w.I(321) // ttft_ns
	w.T(storage.ForwardCompleted)
	w.T(storage.CaptureComplete)
	w.T(storage.ParseOK)
	w.present()
	w.T("rule-x")
	w.present()
	w.T("code-y")
	w.present()
	w.T("err-z")
	w.present()
	w.T("req-0001")
	w.T("resolved")
	w.I(2)
	w.present()
	w.I(5_000)
	w.present()
	w.I(6_000)
	w.present()
	w.B(vAPIKeyFPR)
	w.I(1) // parse_save_failures
	w.present()
	w.I(7_000)
	w.I(2) // capture_version
	w.present()
	w.L(2)
	w.Vplain("client-example/1.0")
	w.Vcredential(14, vUAFpr[:])

	w.M("http_stages")
	w.L(2)
	w.T(vStageIn)
	w.T(storage.StageStateComplete)
	w.T("HTTP/1.1")
	w.T("POST")
	w.T("proxy.example.com")
	w.null() // status_code
	w.present()
	w.I(27) // content_length
	w.I(1_001)
	w.present()
	w.I(1_101)
	w.null() // error_code
	w.present()
	w.T("application/json")
	w.null() // content_encoding
	w.T(vStageUp)
	w.T(storage.StageStatePartial)
	w.T("HTTP/2.0")
	w.T("POST")
	w.T("upstream.example.com")
	w.present()
	w.I(200)
	w.null() // content_length
	w.I(1_200)
	w.null() // ended_at_ns
	w.present()
	w.T("cut")
	w.present()
	w.T("text/event-stream")
	w.present()
	w.T("gzip")

	w.M("headers")
	w.I(2) // capture_version
	w.I(1) // block_present
	w.present()
	w.L(2)
	w.T(vStageIn)
	w.T(vStageUp)
	w.L(4)
	w.T(vStageIn)
	w.T("header")
	w.T("Authorization")
	w.I(0)
	w.Vcredential(20, vAuthFpr[:])
	w.T(vStageIn)
	w.T("header")
	w.T("X-Odd")
	w.I(0)
	w.Vplain(vOddValue)
	w.T(vStageIn)
	w.T("header")
	w.T("X-Odd")
	w.I(1)
	w.Vplain("")
	w.T(vStageUp)
	w.T("trailer")
	w.T("X-Trailer")
	w.I(0)
	w.Vplain("done")

	w.M("body_streams")
	w.L(2)
	w.T(vStageIn)
	w.T(vStageIn)
	w.I(27)
	w.I(27)
	w.present()
	w.B(vBodySHA)
	w.I(1) // hash_complete
	w.I(1) // eof_seen
	w.T(storage.StageStateComplete)
	w.T(storage.RetentionFull)
	w.present()
	w.I(1_010)
	w.present()
	w.I(1_020)
	w.I(2) // chunk_count
	w.I(0) // stream_event_count
	w.I(0) // stream_timeline_complete
	w.null()
	w.T(vStageOut)
	w.T(vStageIn)
	w.I(27)
	w.I(0)
	w.null() // sha256
	w.I(0)
	w.I(0)
	w.T(storage.StageStatePartial)
	w.T(storage.RetentionMetadata)
	w.null()
	w.null()
	w.I(0)
	w.I(4)
	w.I(1)
	w.present()
	w.T("body-err")

	w.M("body_chunks")
	w.L(2)
	w.T(vStageIn)
	w.I(0)
	w.I(0)
	w.I(int64(len(vChunk0)))
	w.I(1_011)
	w.H(vChunk0)
	w.T(vStageIn)
	w.I(1)
	w.I(int64(len(vChunk0)))
	w.I(int64(len(vChunk1)))
	w.I(1_012)
	w.H(vChunk1)

	w.M("stream_timelines")
	w.L(2)
	w.T(vStageIn)
	w.I(0)
	w.null()
	w.null()
	w.I(0)
	w.I(0)
	w.null() // timeline_enc NULL
	w.T(vStageUp)
	w.I(3)
	w.present()
	w.I(1_300)
	w.present()
	w.I(1_400)
	w.I(1)
	w.I(int64(len(vTimeline)))
	w.present()
	w.H(vTimeline)

	w.M("parsed_results")
	w.present()
	w.T("openai.chat_completions")
	w.T("2")
	w.T(storage.ParseOK)
	for _, value := range []string{"model-in", "model-out"} {
		w.present()
		w.T(value)
	}
	w.present()
	w.I(1) // requested_stream
	w.present()
	w.I(0) // observed_stream
	w.present()
	w.T(vRespID)
	for _, value := range []int64{11, 22, 33} {
		w.present()
		w.I(value)
	}
	for _, value := range []string{"type-a", "code-b", "class-c"} {
		w.present()
		w.T(value)
	}
	w.present()
	w.I(4)
	w.present()
	w.I(1)
	w.present()
	w.I(1) // has_tool_call
	w.present()
	w.H(vParsedJSON)
	w.I(8_000)

	w.M("token_links")
	w.present()
	w.I(7)
	w.T("user-example")
	w.I(9)
	w.T("token-example")
	w.I(8_100)
	w.T("billed")
	w.present()
	w.I(1234)
	w.present()
	var bits [8]byte
	binary.BigEndian.PutUint64(bits[:], math.Float64bits(vQuota))
	w.B(bits[:])
	w.present()
	w.I(10)
	w.present()
	w.I(20)
	w.I(1)

	w.M("turn")
	w.present()
	w.T(vTurnID)
	w.T(vConvID)
	w.present()
	w.T(vParentID)
	w.T("post_turn")
	w.T("previous_response_id")
	w.I(100)
	w.T(auditmodel.LayoutMarkerEnvelope)
	w.T(auditmodel.LayoutMarkerEnvelope)
	w.B(vRequestEnvelope)
	w.B(vResponseEnv)
	w.I(2)
	w.I(1)
	w.B(vReqSeq)
	w.B(vRespSeq)
	w.B(vReqRecon)
	w.B(vRespRecon)
	w.T("verified")
	w.present()
	w.T(vPrevResp)
	w.present()
	w.T(vRespID)
	w.I(8_500)
	w.M("request_refs")
	w.L(2)
	w.T(auditmodel.SlotMessages)
	w.B(vObjectB)
	w.B(vSemanticB)
	w.T(auditmodel.SlotMessages)
	w.B(vObjectA)
	w.B(vSemanticA)
	w.M("response_items")
	w.L(1)
	w.I(0)
	w.T(auditmodel.SlotMessages)
	w.B(vObjectA)
	w.B(vSemanticA)
	w.M("content_objects")
	w.L(2)
	w.B(vObjectA)
	w.B(vSemanticA)
	w.T("message")
	w.I(120)
	w.B(vObjectB)
	w.B(vSemanticB)
	w.T("image")
	w.I(240)
	w.M("binary_refs")
	w.L(1)
	w.B(vObjectB)
	w.T("/image_url")
	w.B(vBinary)
	w.T(vMediaType)
	w.T("base64")
	w.M("external_refs")
	w.L(1)
	w.B(vObjectA)
	w.T("/file_id")
	w.T("file_id")
	w.B(vValueHash)
	w.H([]byte(vExternal))
	w.M("binary_objects")
	w.L(1)
	w.B(vBinary)
	w.T(vMediaType)
	w.I(68)

	w.M("conversation")
	w.present()
	w.T(vConvID)
	w.T("openai")
	w.present()
	w.B(vKeyHash)
	w.I(500)

	w.M("audit_project_identity")
	w.present()
	w.I(1)
	w.I(8_200)
	w.T("body")
	w.I(1) // body_scanned
	for _, fpr := range [][]byte{vIdentityFPR, vRemoteFPR, vRepoRootFPR, vCwdFPR} {
		w.present()
		w.B(fpr)
	}
	w.present()
	w.H(vIdentity)

	w.M("integrity_events")
	w.L(2)
	w.I(41)
	w.T("capture_finalized")
	w.null() // previous_mac
	w.B(vPayload1)
	w.B(vMAC1)
	w.I(9_001)
	w.I(42)
	w.T("semantic_compacted")
	w.present()
	w.B(vMAC1)
	w.B(vPayload2)
	w.B(vMAC2)
	w.I(9_002)
	return w.Bytes()
}

// pinnedIndependentDigest freezes the digest of independentRecord; the
// format document can cite it beside the hand-written sequence.
const pinnedIndependentDigest = "8e50300a767d596dd1e678968f13755774ec7fc3aff137afa481537bf40c3b6a"

func TestDigestEqualsIndependentE2Sequence(t *testing.T) {
	record := independentRecord()
	if err := record.CheckCanonical(); err != nil {
		t.Fatalf("the vector record is not canonical: %v", err)
	}
	// Every one of the twelve sections is non-empty.
	switch {
	case len(record.Stages) == 0, len(record.Headers.Values) == 0, len(record.Bodies) == 0, len(record.RawChunks) == 0,
		len(record.Timelines) == 0, record.ParsedResult == nil, record.TokenLink == nil, record.Turn == nil,
		record.Conversation == nil, record.ProjectIdentity == nil, len(record.IntegrityEvents) == 0,
		len(record.Turn.RequestRefs) == 0, len(record.Turn.ResponseItems) == 0, len(record.Turn.Objects) == 0,
		len(record.Turn.BinaryRefs) == 0, len(record.Turn.ExternalRefs) == 0, len(record.Turn.Binaries) == 0:
		t.Fatal("the vector record leaves a section empty")
	}
	got, err := archive.Digest(record)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(independentSequence())
	if got != want {
		t.Fatalf("archive.Digest = %x, SHA-256 of the hand-written E.2 sequence = %x", got, want)
	}
	if hex.EncodeToString(got[:]) != pinnedIndependentDigest {
		t.Fatalf("pinned digest %s, now %x", pinnedIndependentDigest, got)
	}
	// The line carries the same digest and decodes to a record with it.
	line, lineDigest, parts, err := archive.EncodeLine(record)
	if err != nil || len(parts) != 0 || lineDigest != want {
		t.Fatalf("EncodeLine digest %x, parts %d: %v", lineDigest, len(parts), err)
	}
	decoded, decodedDigest, err := archive.DecodeLine(line)
	if err != nil || decodedDigest != want {
		t.Fatalf("DecodeLine digest %x: %v", decodedDigest, err)
	}
	// A delta line carries no materialised refs; the parent supplies them.
	decoded.Turn.RequestRefs = record.Turn.RequestRefs
	if again, err := archive.Digest(decoded); err != nil || again != want {
		t.Fatalf("decoded record digest %x: %v", again, err)
	}
}

// The request context operations do not enter the digest (Q6): two records
// that differ only in their operations, or in form, have the same digest.
func TestDigestIgnoresTheContextForm(t *testing.T) {
	delta := independentRecord()
	materialized := independentRecord()
	materialized.Turn.Context = archive.RequestContext{Form: archive.ContextMaterialized, Refs: materialized.Turn.RequestRefs}
	left, err := archive.Digest(delta)
	if err != nil {
		t.Fatal(err)
	}
	right, err := archive.Digest(materialized)
	if err != nil || left != right {
		t.Fatalf("delta %x, materialized %x (%v)", left, right, err)
	}
}
