package archive

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/headerblock"
	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/openai"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// testKeys stands in for security.ArchiveKeys: the same constructions under
// fixed test keys.
type testKeys struct {
	fingerprint [32]byte
	signing     [32]byte
}

func newTestKeys() testKeys {
	var keys testKeys
	for index := range keys.fingerprint {
		keys.fingerprint[index] = byte(index + 1)
		keys.signing[index] = byte(0x80 + index)
	}
	return keys
}

func hmacSum(key []byte, parts ...[]byte) [32]byte {
	mac := hmac.New(sha256.New, key)
	for _, part := range parts {
		_, _ = mac.Write(part)
	}
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func (keys testKeys) CredentialFingerprint(value []byte) [32]byte {
	return hmacSum(keys.fingerprint[:], []byte("llmapi-logger/archive-credential-value/v1\x00"), value)
}

func (keys testKeys) SignManifest(message []byte) [32]byte { return hmacSum(keys.signing[:], message) }

func (keys testKeys) VerifyManifest(message []byte, mac []byte) bool {
	want := keys.SignManifest(message)
	return hmac.Equal(want[:], mac)
}

func (keys testKeys) KeyFingerprint() [32]byte {
	return hmacSum(keys.signing[:], []byte("llmapi-logger/archive-key-fingerprint/v1\x00"))
}

func hashOf(seed byte) []byte { return bytes.Repeat([]byte{seed}, 32) }

func sumOf(seed byte) [32]byte {
	var out [32]byte
	copy(out[:], hashOf(seed))
	return out
}

func text(value string) *string  { return &value }
func integer(value int64) *int64 { return &value }
func small(value int) *int       { return &value }
func boolPtr(value bool) *bool   { return &value }

// fullRecord is a version 2 record with every column set to a non-NULL
// value, a materialized-form turn, and one credential in every projected
// place. Its lists are canonical.
func fullRecord(t *testing.T) *Record {
	t.Helper()
	keys := newTestKeys()
	refs := []auditmodel.ObjectRef{
		{Slot: auditmodel.SlotMessages, ObjectHash: hashOf(0x11), SemanticHash: hashOf(0x21)},
		{Slot: auditmodel.SlotMessages, ObjectHash: hashOf(0x12), SemanticHash: hashOf(0x22)},
	}
	responses := []auditmodel.ObjectRef{{Slot: auditmodel.SlotChoice, ObjectHash: hashOf(0x13), SemanticHash: hashOf(0x23)}}
	quotaPerUnit := 500000.25
	record := &Record{
		Revision: 1,
		Audit: AuditRow{
			AuditID: "audit-full", SchemaGeneration: 2, StartedAtNS: 1764300000123456789, EndedAtNS: 1764300001123456789,
			RouteID: "route-example", Protocol: "openai", ParserName: "openai.chat", Method: "POST", Path: "/v1/chat/completions",
			RequestURI: ProjectRequestURI(keys, []byte("/v1/chat/completions?trace=a%20b&key=sk-query-secret&&x")),
			Mode:       "strict", StatusCode: integer(200), TTFTNS: integer(1500),
			ForwardStatus: storage.ForwardCompleted, CaptureStatus: storage.CaptureComplete, ParseStatus: storage.ParseOK,
			BlockedBy: text("blocker"), BlockCode: text("block-code"), ErrorCode: text("error-code"),
			NewAPIRequestID: text("request-example"), CallerStatus: storage.CallerResolved, CallerAttempts: 2,
			CallerNextAtNS: integer(1764300002000000000), CallerUpdatedAtNS: integer(1764300003000000000),
			APIKeyFPR: hashOf(0x31), ParseSaveFailures: 1, ParseNextAtNS: integer(1764300004000000000),
			CaptureVersion: storage.CaptureVersion2,
			UserAgent:      ProjectUserAgent(keys, []string{"client/1.0", "sk-ua-secret"}),
		},
		Stages: []Stage{
			{HTTPStage: storage.HTTPStage{Stage: storage.StageRequestReceived, State: storage.StageStateComplete, Proto: "HTTP/1.1",
				Method: "POST", Host: "api.example.com", StatusCode: small(200), ContentLength: integer(120),
				StartedAtNS: 1764300000123456790, EndedAtNS: integer(1764300000123456800), ErrorCode: text("stage-error")},
				ContentType: text("application/json"), ContentEncoding: text("gzip")},
			{HTTPStage: storage.HTTPStage{Stage: storage.StageResponseReceived, State: storage.StageStateComplete, Proto: "HTTP/1.1",
				Method: "POST", Host: "newapi.example.com", StatusCode: small(200), ContentLength: integer(-1),
				StartedAtNS: 1764300000223456790, EndedAtNS: integer(1764300000323456800), ErrorCode: text("stage-error-2")},
				ContentType: text("text/event-stream"), ContentEncoding: text("br")},
		},
		Headers: Headers{
			CaptureVersion: storage.CaptureVersion2, BlockPresent: true,
			BlockStages: []string{storage.StageRequestReceived, storage.StageResponseReceived},
			Values: ProjectHeaders(keys, []headerblock.Value{
				{Stage: storage.StageRequestReceived, Kind: storage.HeaderKindHeader, Name: "Authorization", ValueIndex: 0, Value: []byte("Bearer sk-header-secret")},
				{Stage: storage.StageRequestReceived, Kind: storage.HeaderKindHeader, Name: "User-Agent", ValueIndex: 0, Value: []byte("client/1.0")},
				{Stage: storage.StageRequestReceived, Kind: storage.HeaderKindTrailer, Name: "X-Sum", ValueIndex: 0, Value: []byte("1")},
				{Stage: storage.StageResponseReceived, Kind: storage.HeaderKindHeader, Name: "Content-Type", ValueIndex: 0, Value: []byte("text/event-stream")},
			}),
		},
		Bodies: []storage.BodyStream{{
			Stage: storage.StageResponseReceived, SourceStage: storage.StageResponseReceived, ObservedLength: 10, StoredLength: 10,
			SHA256: hashOf(0x41), HashComplete: true, EOFSeen: true, State: storage.StageStateComplete,
			RetentionState: storage.RetentionFull, FirstObservedAtNS: integer(1764300000223456791),
			LastObservedAtNS: integer(1764300000323456799), ChunkCount: 1, StreamEventCount: 3,
			StreamTimelineComplete: true, ErrorCode: text("body-error"),
		}},
		RawChunks: []RawChunk{{Stage: storage.StageResponseReceived, Seq: 0, Offset: 0, PlaintextLength: 10,
			ObservedAtNS: 1764300000223456795, SHA256: sha256.Sum256([]byte("0123456789"))}},
		Timelines: []Timeline{{Stage: storage.StageResponseReceived, EventCount: 3, FirstEventAtNS: integer(1764300000223456792),
			LastEventAtNS: integer(1764300000323456798), Complete: true, PlaintextLength: 4, Plaintext: []byte{1, 2, 3, 4}}},
		ParsedResult: &ParsedResult{
			ParserName: "openai.chat", ParserVersion: "3", Status: storage.ParseOK, RequestModel: text("model-a"),
			ResponseModel: text("model-b"), RequestedStream: boolPtr(true), ObservedStream: boolPtr(true), ResponseID: text("resp-1"),
			UsageInput: integer(10), UsageOutput: integer(20), UsageTotal: integer(30), ErrorType: text("error-type"),
			ErrorCode: text("parsed-error"), UpstreamErrorClass: text("rate_limited"), MessageCount: integer(3),
			ToolCallCount: integer(1), HasToolCall: boolPtr(true), ParsedJSON: []byte(`{"protocol":"openai"}`),
			ParsedAtNS: 1764300005000000000,
		},
		TokenLink: &TokenLink{NewAPIUserID: 7, Username: "user-example", NewAPITokenID: 9, TokenName: "token-example",
			LinkedAtNS: 1764300006000000000, BillingState: storage.BillingBilled, Quota: integer(1500), QuotaPerUnit: &quotaPerUnit,
			BilledPromptTokens: integer(11), BilledCompletionTokens: integer(21), BillingAttempts: 1},
		Turn: &Turn{
			Row: TurnRow{TurnID: "turn-full", ConversationID: "conv_full", ParentTurnID: text("turn-parent"),
				ParentBase: auditmodel.ParentBaseRequest, LinkReason: "conversation_key", LinkConfidence: 90,
				RequestLayout: auditmodel.LayoutOpenAIChatRequest, ResponseLayout: auditmodel.LayoutMarkerEnvelope,
				RequestEnvelopeHash: hashOf(0x51), ResponseEnvelopeHash: hashOf(0x52), RequestItemCount: 2, ResponseItemCount: 1,
				RequestSequenceHash: auditmodel.SequenceHash(refs), ResponseSequenceHash: auditmodel.SequenceHash(responses),
				RequestReconstructionHash: hashOf(0x53), ResponseReconstructionHash: hashOf(0x54), ReconstructionStatus: "verified",
				PreviousResponseID: text("resp-0"), ResponseID: text("resp-1"), CreatedAtNS: 1764300005000000001},
			Context:       RequestContext{Form: ContextMaterialized, Refs: cloneRefs(refs)},
			RequestRefs:   cloneRefs(refs),
			ResponseItems: []ResponseItem{{Ordinal: 0, Slot: auditmodel.SlotChoice, ObjectHash: hashOf(0x13), SemanticHash: hashOf(0x23)}},
			Objects: []ObjectMeta{
				{Hash: hashOf(0x11), SemanticHash: hashOf(0x21), Kind: "message", PlaintextLength: 40},
				{Hash: hashOf(0x12), SemanticHash: hashOf(0x22), Kind: "message", PlaintextLength: 41},
				{Hash: hashOf(0x13), SemanticHash: hashOf(0x23), Kind: "choice", PlaintextLength: 42},
				{Hash: hashOf(0x51), SemanticHash: hashOf(0x61), Kind: "envelope", PlaintextLength: 43},
				{Hash: hashOf(0x52), SemanticHash: hashOf(0x62), Kind: "envelope", PlaintextLength: 44},
			},
			BinaryRefs:   []BinaryRef{{ObjectHash: hashOf(0x11), JSONPointer: "/content/0/image_url", BinaryHash: hashOf(0x71), MediaType: "image/png", Encoding: "data_url"}},
			ExternalRefs: []ExternalRef{{ObjectHash: hashOf(0x12), JSONPointer: "/file_id", RefKind: "file_id", ValueHash: hashOf(0x72), Value: "file-example"}},
			Binaries:     []BinaryMeta{{Hash: hashOf(0x71), MediaType: "image/png", PlaintextLength: 99}},
		},
		Conversation: &Conversation{ConversationID: "conv_full", Protocol: "openai", KeyHash: hashOf(0x81), CreatedAtNS: 1764300005000000002},
		ProjectIdentity: &ProjectIdentity{IdentityVersion: 2, ExtractedAtNS: 1764300007000000000, Source: "declared", BodyScanned: true,
			IdentityFPR: hashOf(0x91), RemoteFPR: hashOf(0x92), RepoRootFPR: hashOf(0x93), CwdFPR: hashOf(0x94),
			Identity: []byte(`{"remote":"example.com/repo"}`)},
		IntegrityEvents: []IntegrityEvent{
			{Sequence: 5, EventType: "capture_finalized", PreviousMAC: hashOf(0xa1), PayloadDigest: hashOf(0xa2), EventMAC: hashOf(0xa3), CreatedAtNS: 1764300001200000000},
			{Sequence: 9, EventType: "semantic_compacted", PreviousMAC: hashOf(0xa4), PayloadDigest: hashOf(0xa5), EventMAC: hashOf(0xa6), CreatedAtNS: 1764300005100000000},
		},
	}
	if err := record.Canonicalize(); err != nil {
		t.Fatal(err)
	}
	return record
}

// minimalRecord is a version 1 record without optional rows.
func minimalRecord() *Record {
	return &Record{
		Revision: 1,
		Audit: AuditRow{AuditID: "audit-min", SchemaGeneration: 2, StartedAtNS: 100, EndedAtNS: 200, RouteID: "r", Protocol: "gemini",
			ParserName: "gemini", Method: "POST", Path: "/v1beta/models/x:generateContent",
			RequestURI: RequestURI{Path: "/v1beta/models/x:generateContent", Segments: []QuerySegment{}}, Mode: "available",
			ForwardStatus: storage.ForwardRejected, CaptureStatus: storage.CaptureComplete, ParseStatus: storage.ParseSkipped,
			CallerStatus: storage.CallerNone, CaptureVersion: storage.CaptureVersion1},
		Stages:          []Stage{},
		Headers:         Headers{CaptureVersion: storage.CaptureVersion1, Values: []HeaderValue{}},
		Bodies:          []storage.BodyStream{},
		RawChunks:       []RawChunk{},
		Timelines:       []Timeline{},
		IntegrityEvents: []IntegrityEvent{},
	}
}

// fixedObjects is an ObjectSource over maps.
type fixedObjects struct {
	contents map[string][]byte
	binaries map[string][]byte
}

func (objects fixedObjects) ContentPlaintext(hash []byte) ([]byte, error) {
	if data, ok := objects.contents[string(hash)]; ok {
		return data, nil
	}
	return nil, errors.New("missing content object")
}

func (objects fixedObjects) BinaryData(hash []byte) ([]byte, error) {
	if data, ok := objects.binaries[string(hash)]; ok {
		return data, nil
	}
	return nil, errors.New("missing binary object")
}

func testCipher(t *testing.T) security.Cipher {
	t.Helper()
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{7}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

// preparedResponsesTurn normalises one OpenAI Responses exchange with an
// inline image, as the parser does, and returns the prepared turn with its
// object plaintexts and the provider request and response bodies.
func preparedResponsesTurn(t *testing.T, cipher security.Cipher, auditID string) (auditmodel.PreparedTurn, fixedObjects, []byte, []byte) {
	t.Helper()
	implementation, err := openai.New(openai.Responses)
	if err != nil {
		t.Fatal(err)
	}
	png := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0x62, 0x19}, 64)...)
	requestBody, err := auditmodel.CanonicalJSON(map[string]any{
		"model": "model-example",
		"input": []any{map[string]any{"type": "message", "role": "user", "content": []any{
			map[string]any{"type": "input_text", "text": "inspect the image"},
			map[string]any{"type": "input_image", "image_url": "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)},
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err := auditmodel.CanonicalJSON(map[string]any{
		"id": "response-current", "object": "response", "model": "model-result",
		"output": []any{map[string]any{"type": "message", "id": "message-current", "role": "assistant",
			"content": []any{map[string]any{"type": "output_text", "text": "It looks valid."}}}},
		"usage": map[string]any{"input_tokens": 12, "output_tokens": 4, "total_tokens": 16},
	})
	if err != nil {
		t.Fatal(err)
	}
	input := base.Input{AuditID: auditID, Protocol: "openai", Endpoint: "/v1/responses",
		Request:  base.BodySource{Present: true, Complete: true, ContentType: "application/json", Data: requestBody},
		Response: base.BodySource{Present: true, Complete: true, ContentType: "application/json", Data: responseBody}}
	turn, err := implementation.NormalizeAudit(context.Background(), input, implementation.Parse(context.Background(), input))
	if err != nil {
		t.Fatal(err)
	}
	turn.CreatedAtNS = 40
	prepared, err := auditmodel.Prepare(turn, cipher)
	if err != nil {
		t.Fatal(err)
	}
	objects := fixedObjects{contents: map[string][]byte{}, binaries: map[string][]byte{}}
	for _, object := range prepared.Objects {
		decoded, err := auditmodel.OpenObject(cipher, auditmodel.StoredContent{Hash: object.Hash, SemanticHash: object.SemanticHash,
			Kind: object.Kind, Compression: object.Compression, PlaintextLength: object.PlaintextLength,
			EncodedLength: object.EncodedLength, DataEnc: object.DataEnc})
		if err != nil {
			t.Fatal(err)
		}
		canonical, err := auditmodel.CanonicalJSON(decoded)
		if err != nil {
			t.Fatal(err)
		}
		objects.contents[string(object.Hash)] = canonical
	}
	for _, binary := range prepared.Binaries {
		data, err := auditmodel.OpenBinary(cipher, auditmodel.StoredBinary{Hash: binary.Hash, MediaType: binary.MediaType,
			Compression: binary.Compression, PlaintextLength: binary.PlaintextLength, EncodedLength: binary.EncodedLength, DataEnc: binary.DataEnc})
		if err != nil {
			t.Fatal(err)
		}
		objects.binaries[string(binary.Hash)] = data
	}
	return prepared, objects, requestBody, responseBody
}

// turnFromPrepared builds the record's turn as the snapshot reader would:
// a root turn, delta form, its objects and binary refs.
func turnFromPrepared(prepared auditmodel.PreparedTurn, conversationID string) *Turn {
	turn := &Turn{
		Row: TurnRow{TurnID: prepared.AuditID, ConversationID: conversationID, ParentBase: auditmodel.ParentBaseRoot, LinkReason: "root",
			LinkConfidence: 100, RequestLayout: prepared.RequestLayout, ResponseLayout: prepared.ResponseLayout,
			RequestEnvelopeHash: prepared.RequestEnvelopeHash, ResponseEnvelopeHash: prepared.ResponseEnvelopeHash,
			RequestItemCount: int64(len(prepared.RequestRefs)), ResponseItemCount: int64(len(prepared.ResponseRefs)),
			RequestSequenceHash: prepared.RequestSequenceHash, ResponseSequenceHash: prepared.ResponseSequenceHash,
			RequestReconstructionHash: prepared.RequestReconstructionHash, ResponseReconstructionHash: prepared.ResponseReconstructionHash,
			ReconstructionStatus: "verified", CreatedAtNS: prepared.CreatedAtNS},
		Context:     RequestContext{Form: ContextDelta, Ops: ContextOpsFrom(auditmodel.BuildDelta(nil, prepared.RequestRefs))},
		RequestRefs: cloneRefs(prepared.RequestRefs),
	}
	if prepared.ResponseID != "" {
		turn.Row.ResponseID = text(prepared.ResponseID)
	}
	for index, ref := range prepared.ResponseRefs {
		turn.ResponseItems = append(turn.ResponseItems, ResponseItem{Ordinal: int64(index), Slot: ref.Slot, ObjectHash: ref.ObjectHash, SemanticHash: ref.SemanticHash})
	}
	for _, object := range prepared.Objects {
		turn.Objects = append(turn.Objects, ObjectMeta{Hash: object.Hash, SemanticHash: object.SemanticHash, Kind: object.Kind, PlaintextLength: object.PlaintextLength})
		for _, ref := range object.BinaryRefs {
			turn.BinaryRefs = append(turn.BinaryRefs, BinaryRef{ObjectHash: object.Hash, JSONPointer: ref.JSONPointer, BinaryHash: ref.BinaryHash, MediaType: ref.MediaType, Encoding: ref.Encoding})
		}
	}
	for _, binary := range prepared.Binaries {
		turn.Binaries = append(turn.Binaries, BinaryMeta{Hash: binary.Hash, MediaType: binary.MediaType, PlaintextLength: binary.PlaintextLength})
	}
	return turn
}

// The record converts to the query layer's plaintext input: the rebuilt
// provider request and response equal the originals, the list row carries
// the joined fields, and the projected detail equals the projection of the
// detail the hot path builds from the same plaintext.
func TestRecordPlainDetailRebuildsTheTurn(t *testing.T) {
	keys := newTestKeys()
	cipher := testCipher(t)
	prepared, objects, requestBody, responseBody := preparedResponsesTurn(t, cipher, "audit-plain")
	record := minimalRecord()
	record.Audit.AuditID, record.Audit.Protocol, record.Audit.ParserName = "audit-plain", "openai", openai.Responses
	record.Audit.ForwardStatus, record.Audit.ParseStatus = storage.ForwardCompleted, storage.ParseOK
	record.Audit.NewAPIRequestID, record.Audit.CallerStatus, record.Audit.CallerAttempts = text("request-1"), storage.CallerResolved, 1
	record.Audit.CallerUpdatedAtNS = integer(300)
	rawURI := []byte("/v1/responses?key=sk-plain&trace=1")
	record.Audit.RequestURI = ProjectRequestURI(keys, rawURI)
	rawHeaders := []headerblock.Value{
		{Stage: storage.StageRequestReceived, Kind: storage.HeaderKindHeader, Name: "Authorization", Value: []byte("Bearer sk-plain")},
		{Stage: storage.StageRequestReceived, Kind: storage.HeaderKindHeader, Name: "User-Agent", Value: []byte("client/2")},
	}
	record.Headers.Values = ProjectHeaders(keys, rawHeaders)
	record.Stages = []Stage{{HTTPStage: storage.HTTPStage{Stage: storage.StageRequestReceived, State: storage.StageStateComplete, StartedAtNS: 101}}}
	record.ParsedResult = &ParsedResult{ParserName: openai.Responses, ParserVersion: "1", Status: storage.ParseOK, RequestModel: text("model-example"), ParsedAtNS: 150}
	record.TokenLink = &TokenLink{NewAPIUserID: 7, Username: "u", NewAPITokenID: 9, TokenName: "t", LinkedAtNS: 160, BillingState: storage.BillingUnbilled}
	record.Turn = turnFromPrepared(prepared, "conv_plain")
	if err := record.Canonicalize(); err != nil {
		t.Fatal(err)
	}

	plain, err := record.PlainDetail(objects, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plain.Audit.ConversationID == nil || *plain.Audit.ConversationID != "conv_plain" || *plain.Audit.Username != "u" ||
		*plain.Audit.RequestModel != "model-example" || plain.TokenLink.NewAPIRequestID != "request-1" || plain.Audit.ConversationTurns != nil {
		t.Fatalf("list row = %+v token = %+v", plain.Audit, plain.TokenLink)
	}
	rebuilt, err := query.ReconstructPlainTurn(plain)
	if err != nil {
		t.Fatal(err)
	}
	canonical := func(value any) string {
		encoded, err := auditmodel.CanonicalJSON(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded)
	}
	if canonical(rebuilt.Request) != string(requestBody) || canonical(rebuilt.Response) != string(responseBody) {
		t.Fatal("rebuilt provider values differ from the originals")
	}

	archived, err := record.Detail(objects, nil)
	if err != nil {
		t.Fatal(err)
	}
	hotPlain := plain
	hotPlain.RequestURI = rawURI
	hotPlain.Headers = rawHeaders
	hotDetail, err := query.BuildDetail(hotPlain)
	if err != nil {
		t.Fatal(err)
	}
	if projected := ProjectDetail(keys, hotDetail); !reflect.DeepEqual(projected, archived) {
		t.Fatalf("projected details differ:\n hot     %+v\n archive %+v", projected, archived)
	}
	for _, header := range archived.Headers {
		if header.Name == "Authorization" && (!header.Value.Omitted || header.Value.Length != int64(len("Bearer sk-plain"))) {
			t.Fatalf("authorization header = %+v", header)
		}
	}

	if _, err := record.PlainDetail(fixedObjects{}, nil); err == nil {
		t.Fatal("missing objects accepted")
	}
	record.Turn.RequestRefs = nil
	if _, err := record.PlainDetail(objects, nil); !errors.Is(err, ErrNotMaterialized) {
		t.Fatalf("unmaterialised turn err=%v", err)
	}
}

// Summary takes the User-Agent from user_agent for version 2 and from the
// inbound headers for version 1, as the store's two list paths do, and
// equals ProjectSummary of the hot side's list row.
func TestRecordSummaryUserAgent(t *testing.T) {
	keys := newTestKeys()
	v1 := minimalRecord()
	v1.Headers.Values = ProjectHeaders(keys, []headerblock.Value{
		{Stage: storage.StageRequestReceived, Kind: storage.HeaderKindHeader, Name: "User-Agent", ValueIndex: 0, Value: []byte("sk-looks-like-a-key")},
		{Stage: storage.StageRequestReceived, Kind: storage.HeaderKindHeader, Name: "User-Agent", ValueIndex: 1, Value: []byte("second")},
		{Stage: storage.StageRequestSent, Kind: storage.HeaderKindHeader, Name: "User-Agent", ValueIndex: 0, Value: []byte("proxy")},
	})
	summary := v1.Summary()
	hot := query.BuildSummary(v1.listRow(), []string{"sk-looks-like-a-key", "second"})
	if want := ProjectSummary(keys, hot); !reflect.DeepEqual(summary, want) {
		t.Fatalf("version 1 summary %+v want %+v", summary, want)
	}
	if summary.UserAgent == nil || !summary.UserAgent.Omitted {
		t.Fatalf("credential-like User-Agent not projected: %+v", summary.UserAgent)
	}

	v2 := fullRecord(t)
	summary = v2.Summary()
	hot = query.BuildSummary(v2.listRow(), []string{"client/1.0", "sk-ua-secret"})
	if want := ProjectSummary(keys, hot); !reflect.DeepEqual(summary, want) {
		t.Fatalf("version 2 summary %+v want %+v", summary, want)
	}
	v2.Audit.UserAgent = nil
	if v2.Summary().UserAgent != nil {
		t.Fatal("NULL user_agent produced a User-Agent")
	}
}

// Raw, timeline and metadata selection follow the store: the body row of
// the preferred stage, chunks and timeline of its source stage, the
// observed length of the selected row.
func TestRecordBodySelection(t *testing.T) {
	record := fullRecord(t)
	merged := record.Bodies[0]
	merged.Stage, merged.ObservedLength = storage.StageResponseSent, 11
	record.Stages = append(record.Stages, Stage{HTTPStage: storage.HTTPStage{Stage: storage.StageResponseSent, State: storage.StageStateComplete}})
	record.Bodies = append(record.Bodies, merged)
	if err := record.Canonicalize(); err != nil {
		t.Fatal(err)
	}
	body, ok, err := record.SelectBody(query.SideResponse)
	if err != nil || !ok || body.Stage != storage.StageResponseReceived {
		t.Fatalf("response body = %+v %v %v", body, ok, err)
	}
	if _, ok, _ := record.SelectBody(query.SideRequest); ok {
		t.Fatal("request side found a body")
	}
	if chunks := record.OwningChunks(merged); len(chunks) != 1 || chunks[0].Stage != storage.StageResponseReceived {
		t.Fatalf("chunks of the merged stage = %+v", chunks)
	}
	stored, plaintext, ok := record.StoredTimeline(merged)
	if !ok || stored.Stage != storage.StageResponseReceived || stored.ObservedLength != 11 || !bytes.Equal(plaintext, []byte{1, 2, 3, 4}) {
		t.Fatalf("timeline = %+v %v %v", stored, plaintext, ok)
	}
	metadata := record.RawMetadata(merged)
	if metadata.AuditID != record.Audit.AuditID || metadata.SourceStage != storage.StageResponseReceived || metadata.ObservedLength != 11 {
		t.Fatalf("metadata = %+v", metadata)
	}
}

// A delta-form chain materialises from its parents, for both parent bases,
// and a wrong parent is rejected.
func TestTurnMaterialize(t *testing.T) {
	ref := func(seed byte) auditmodel.ObjectRef {
		return auditmodel.ObjectRef{Slot: auditmodel.SlotMessages, ObjectHash: hashOf(seed), SemanticHash: hashOf(seed + 0x40)}
	}
	rootRefs := []auditmodel.ObjectRef{ref(1), ref(2)}
	rootResponse := []auditmodel.ObjectRef{{Slot: auditmodel.SlotChoice, ObjectHash: hashOf(3), SemanticHash: hashOf(0x43)}}
	newTurn := func(parent *string, parentBase string, refs []auditmodel.ObjectRef, base []auditmodel.ObjectRef) *Turn {
		return &Turn{Row: TurnRow{ParentTurnID: parent, ParentBase: parentBase, RequestItemCount: int64(len(refs)), RequestSequenceHash: auditmodel.SequenceHash(refs)},
			Context: RequestContext{Form: ContextDelta, Ops: ContextOpsFrom(auditmodel.BuildDelta(base, refs))}}
	}
	root := newTurn(nil, auditmodel.ParentBaseRoot, rootRefs, nil)
	if err := root.Materialize(nil, nil); err != nil || !reflect.DeepEqual(root.RequestRefs, rootRefs) {
		t.Fatalf("root = %v %v", root.RequestRefs, err)
	}
	requestChild := append(cloneRefs(rootRefs), ref(4))
	child := newTurn(text("root"), auditmodel.ParentBaseRequest, requestChild, rootRefs)
	if err := child.Materialize(rootRefs, rootResponse); err != nil || len(child.RequestRefs) != 3 {
		t.Fatalf("request child = %v %v", child.RequestRefs, err)
	}
	postTurn := append(append(cloneRefs(rootRefs), rootResponse...), ref(5))
	post := newTurn(text("root"), auditmodel.ParentBasePostTurn, postTurn, append(cloneRefs(rootRefs), rootResponse...))
	if err := post.Materialize(rootRefs, rootResponse); err != nil || len(post.RequestRefs) != 4 {
		t.Fatalf("post_turn child = %v %v", post.RequestRefs, err)
	}
	if err := post.Materialize(rootRefs, nil); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("post_turn without the parent's response err=%v", err)
	}
	if err := child.Materialize(requestChild, nil); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("wrong parent err=%v", err)
	}
	materialized := &Turn{Row: child.Row, Context: RequestContext{Form: ContextMaterialized, Refs: requestChild}}
	if err := materialized.Materialize(nil, nil); err != nil {
		t.Fatal(err)
	}
	materialized.Context.Refs = rootRefs
	if err := materialized.Materialize(nil, nil); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("materialised refs that do not match err=%v", err)
	}
}

// The archive format package must stay readable without the database: no
// store package and no PostgreSQL driver in its dependencies.
func TestArchiveDependsOnNoStore(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not available")
	}
	output, err := exec.Command(goTool, "list", "-deps", "llmapi-logger/internal/archive").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, output)
	}
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "llmapi-logger/internal/storage/postgres" || line == "llmapi-logger/internal/storage/sqlite" || strings.HasPrefix(line, "github.com/jackc/pgx") {
			t.Fatalf("internal/archive depends on %s", line)
		}
	}
}
