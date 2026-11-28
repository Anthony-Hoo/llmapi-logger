package query

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"testing"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/bodycodec"
	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/headerblock"
	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/openai"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/sqlite"
	"llmapi-logger/internal/streamtimeline"
)

// The tests in this file build one audit twice: encrypted, as the store
// hands it to Service, and as plaintext, as a reader outside the database
// would hold it. The plaintext side is built from the source values (the
// request URI, the header map, the parsed JSON, the points, the chunks) and,
// for turn objects, from the canonical object text the content address is
// taken over, never by running Service's own decryption. Each test requires
// the two paths to return the same outputs and the same errors.

// plainSample is one audit in both forms.
type plainSample struct {
	stored sqlite.AuditQueryDetail
	plain  PlainDetail
}

const plainSampleURI = "/v1/responses?trace=example"

// plainHeaderStages is the Header evidence of every sample.
var plainHeaderStages = []headerblock.Stage{
	{
		Name:     sqlite.StageRequestReceived,
		Headers:  headerblock.Snapshot(http.Header{"Authorization": {"Bearer example-secret"}, "User-Agent": {"client/1"}, "X-Multi": {"a", "b"}}),
		Trailers: headerblock.Snapshot(http.Header{"X-Sum": {"1"}}),
	},
	{Name: sqlite.StageResponseReceived, Headers: headerblock.Snapshot(http.Header{"Content-Type": {"application/json"}})},
}

// newPlainSample stores the request URI and the headers of plainHeaderStages
// under captureVersion, with no parsed result and no turn.
func newPlainSample(t *testing.T, cipher security.Cipher, auditID string, captureVersion int) plainSample {
	t.Helper()
	uriAAD, err := security.AAD(auditID, "request_uri")
	if err != nil {
		t.Fatal(err)
	}
	uriEnc, err := cipher.Encrypt(uriAAD, []byte(plainSampleURI))
	if err != nil {
		t.Fatal(err)
	}
	status, quota, perUnit, prompt := 200, int64(1500), 500000.0, int64(12)
	audit := sqlite.AuditListRow{
		AuditID: auditID, StartedAtNS: 10, Protocol: "openai", ParserName: openai.Responses, Method: "POST", Path: "/v1/responses",
		StatusCode: &status, ForwardStatus: sqlite.ForwardCompleted, CaptureStatus: sqlite.CaptureComplete,
		ParseStatus: sqlite.ParseOK, CaptureVersion: captureVersion,
	}
	sample := plainSample{
		stored: sqlite.AuditQueryDetail{Audit: audit, RequestURIEnc: uriEnc},
		plain:  PlainDetail{Audit: audit, RequestURI: []byte(plainSampleURI), Headers: headerblock.Flatten(plainHeaderStages)},
	}
	token := &sqlite.TokenLinkSummary{
		NewAPIRequestID: "request-example", NewAPIUserID: 7, Username: "user-example", NewAPITokenID: 9, TokenName: "token-example",
		LinkedAtNS: 20, BillingState: storage.BillingBilled, Quota: &quota, QuotaPerUnit: &perUnit, BilledPromptTokens: &prompt,
	}
	sample.stored.TokenLink, sample.plain.TokenLink = token, token
	for _, stage := range plainHeaderStages {
		row := sqlite.HTTPStage{AuditID: auditID, Stage: stage.Name, State: sqlite.StageStateComplete, StartedAtNS: 11}
		sample.stored.Stages = append(sample.stored.Stages, row)
		sample.plain.Stages = append(sample.plain.Stages, row)
	}
	body := sqlite.BodyStream{AuditID: auditID, Stage: sqlite.StageRequestSent, ObservedLength: 5, StoredLength: 5,
		SHA256: bytes.Repeat([]byte{1}, 32), State: sqlite.StageStateComplete, RetentionState: sqlite.RetentionFull}
	sample.stored.Bodies, sample.plain.Bodies = []sqlite.BodyStream{body}, []sqlite.BodyStream{body}
	switch captureVersion {
	case storage.CaptureVersion1:
		for _, stage := range plainHeaderStages {
			for kind, fields := range map[string][]headerblock.Field{sqlite.HeaderKindHeader: stage.Headers, sqlite.HeaderKindTrailer: stage.Trailers} {
				for _, field := range fields {
					for index, value := range field.Values {
						aad, err := security.AAD(auditID, "header", stage.Name, kind, field.Name, strconv.Itoa(index))
						if err != nil {
							t.Fatal(err)
						}
						encrypted, err := cipher.Encrypt(aad, value)
						if err != nil {
							t.Fatal(err)
						}
						sample.stored.Headers = append(sample.stored.Headers, sqlite.HeaderEvidence{
							Stage: stage.Name, Kind: kind, Name: field.Name, ValueIndex: index, ValueLength: len(value), ValueEnc: encrypted,
						})
					}
				}
			}
		}
	case storage.CaptureVersion2:
		block, err := headerblock.SealBlock(cipher, auditID, plainHeaderStages)
		if err != nil {
			t.Fatal(err)
		}
		sample.stored.HeaderBlock = &sqlite.HeaderBlockEvidence{Compression: block.Compression, PlaintextLength: block.PlaintextLength, DataEnc: block.DataEnc}
	}
	return sample
}

// withParsed stores parsedJSON as the parsed result's payload.
func (sample *plainSample) withParsed(t *testing.T, cipher security.Cipher, parsedJSON []byte) {
	t.Helper()
	summary := sqlite.ParsedResultSummary{ParserName: sample.stored.Audit.ParserName, ParserVersion: "2", Status: sqlite.ParseOK, ParsedAtNS: 30}
	sample.plain.ParsedResult = &PlainParsedResult{Summary: summary, ParsedJSON: parsedJSON}
	if parsedJSON != nil {
		sealed, err := auditmodel.SealParsedResult(cipher, sample.stored.Audit.AuditID, summary.ParserName, parsedJSON)
		if err != nil {
			t.Fatal(err)
		}
		summary.ParsedJSONEnc = sealed
	}
	sample.stored.ParsedResult = &summary
}

// withTurn stores prepared as the audit's turn. The plaintext objects are the
// canonical text of each decoded object, which is what the content address
// covers; decodePlainObject checks every one against its address, so a
// difference would fail the test rather than pass unnoticed.
func (sample *plainSample) withTurn(t *testing.T, cipher security.Cipher, prepared auditmodel.PreparedTurn) {
	t.Helper()
	graph := graphFromPrepared(prepared)
	sample.stored.TurnGraph = graph
	plain := &PlainTurnGraph{TurnGraph: *graph}
	plain.TurnGraph.Objects, plain.TurnGraph.Binaries = nil, nil
	for _, object := range graph.Objects {
		decoded, err := auditmodel.OpenObject(cipher, object)
		if err != nil {
			t.Fatal(err)
		}
		canonical, err := auditmodel.CanonicalJSON(decoded)
		if err != nil {
			t.Fatal(err)
		}
		plain.Objects = append(plain.Objects, PlainObject{
			Hash: object.Hash, SemanticHash: object.SemanticHash, Kind: object.Kind,
			PlaintextLength: object.PlaintextLength, Plaintext: canonical,
		})
	}
	for _, binary := range graph.Binaries {
		data, err := auditmodel.OpenBinary(cipher, binary)
		if err != nil {
			t.Fatal(err)
		}
		plain.Binaries = append(plain.Binaries, PlainBinary{Hash: binary.Hash, MediaType: binary.MediaType, PlaintextLength: binary.PlaintextLength, Data: data})
	}
	sample.plain.TurnGraph = plain
}

func sameError(t *testing.T, what string, hot, plain error) bool {
	t.Helper()
	if (hot == nil) != (plain == nil) || hot != nil && hot.Error() != plain.Error() {
		t.Fatalf("%s: database path error %v, plaintext path error %v", what, hot, plain)
	}
	return hot == nil
}

func canonicalOf(t *testing.T, value any) string {
	t.Helper()
	encoded, err := auditmodel.CanonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// assertSameOutputs compares every per-audit output of the two paths.
func assertSameOutputs(t *testing.T, cipher security.Cipher, sample plainSample) Detail {
	t.Helper()
	ctx := context.Background()
	auditID := sample.stored.Audit.AuditID
	service, err := New(&fakeStore{healthy: true, detail: sample.stored}, cipher)
	if err != nil {
		t.Fatal(err)
	}

	hotDetail, hotErr := service.Get(ctx, auditID, nil)
	plainDetail, plainErr := BuildDetail(sample.plain)
	if sameError(t, "Get", hotErr, plainErr) && !reflect.DeepEqual(hotDetail, plainDetail) {
		t.Fatalf("Get differs:\n database  %+v\n plaintext %+v", hotDetail, plainDetail)
	}

	hotMetadata, hotErr := service.GetMetadata(ctx, auditID, nil)
	sameError(t, "GetMetadata", hotErr, nil)
	if plainMetadata := BuildMetadata(sample.plain); !reflect.DeepEqual(hotMetadata, plainMetadata) {
		t.Fatalf("GetMetadata differs:\n database  %+v\n plaintext %+v", hotMetadata, plainMetadata)
	}

	hotTurn, hotErr := service.ReconstructTurn(ctx, auditID)
	plainTurn, plainErr := ReconstructPlainTurn(sample.plain)
	if errors.Is(hotErr, ErrNoTurnGraph) != errors.Is(plainErr, ErrNoTurnGraph) {
		t.Fatalf("ReconstructTurn: %v, %v", hotErr, plainErr)
	}
	if sameError(t, "ReconstructTurn", hotErr, plainErr) {
		if !reflect.DeepEqual(hotTurn.Turn, plainTurn.Turn) || !reflect.DeepEqual(hotTurn.Conversation, plainTurn.Conversation) ||
			canonicalOf(t, hotTurn.Request) != canonicalOf(t, plainTurn.Request) || canonicalOf(t, hotTurn.Response) != canonicalOf(t, plainTurn.Response) {
			t.Fatalf("ReconstructTurn differs:\n database  %+v\n plaintext %+v", hotTurn, plainTurn)
		}
	}

	hotSession, hotErr := service.SessionConversation(ctx, auditID)
	plainSession, plainErr := PlainSessionConversation(sample.plain)
	if sameError(t, "SessionConversation", hotErr, plainErr) && !reflect.DeepEqual(hotSession, plainSession) {
		t.Fatalf("SessionConversation differs:\n database  %+v\n plaintext %+v", hotSession, plainSession)
	}
	return plainDetail
}

func plainResponsesTurn(t *testing.T, cipher security.Cipher, auditID string) (auditmodel.PreparedTurn, []byte, []byte) {
	t.Helper()
	implementation, err := openai.New(openai.Responses)
	if err != nil {
		t.Fatal(err)
	}
	png := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0x62, 0x19}, 256)...)
	fileBytes := bytes.Repeat([]byte("reusable file text\n"), 40)
	requestBody, err := auditmodel.CanonicalJSON(map[string]any{
		"model": "model-example",
		"input": []any{
			map[string]any{"type": "message", "role": "user", "content": []any{
				map[string]any{"type": "input_text", "text": "inspect both attachments"},
				map[string]any{"type": "input_image", "image_url": "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)},
				map[string]any{"type": "input_file", "filename": "facts.txt", "mime_type": "text/plain", "file_data": base64.StdEncoding.EncodeToString(fileBytes)},
			}},
			map[string]any{"type": "function_call", "id": "function-one", "call_id": "call-one", "name": "lookup", "arguments": `{"id":1}`},
			map[string]any{"type": "function_call_output", "call_id": "call-one", "output": `{"value":"one"}`},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err := auditmodel.CanonicalJSON(map[string]any{
		"id": "response-current", "object": "response", "model": "model-result",
		"output": []any{map[string]any{"type": "message", "id": "message-current", "role": "assistant",
			"content": []any{map[string]any{"type": "output_text", "text": "Both look valid."}}}},
		"usage": map[string]any{"input_tokens": 123, "output_tokens": 45, "total_tokens": 168},
	})
	if err != nil {
		t.Fatal(err)
	}
	input := base.Input{
		AuditID: auditID, Protocol: "openai", Endpoint: "/v1/responses",
		Request:  base.BodySource{Present: true, Complete: true, ContentType: "application/json", Data: requestBody},
		Response: base.BodySource{Present: true, Complete: true, ContentType: "application/json", Data: responseBody},
	}
	turn, err := implementation.NormalizeAudit(context.Background(), input, implementation.Parse(context.Background(), input))
	if err != nil {
		t.Fatal(err)
	}
	turn.CreatedAtNS = 40
	prepared, err := auditmodel.Prepare(turn, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.Binaries) != 2 {
		t.Fatalf("fixture has %d binaries, want 2", len(prepared.Binaries))
	}
	return prepared, requestBody, responseBody
}

// An audit with a turn, under both capture versions: the detail, the
// rebuilt provider request and response, the conversation and the headers
// come out the same from plaintext, and the plaintext input is left as it was.
func TestPlainAssemblyRebuildsATurnLikeTheDatabasePath(t *testing.T) {
	t.Parallel()
	cipher := testCipher(t)
	for _, version := range []int{storage.CaptureVersion1, storage.CaptureVersion2} {
		t.Run("capture version "+strconv.Itoa(version), func(t *testing.T) {
			t.Parallel()
			auditID := "audit-plain-turn-v" + strconv.Itoa(version)
			sample := newPlainSample(t, cipher, auditID, version)
			prepared, requestBody, responseBody := plainResponsesTurn(t, cipher, auditID)
			sample.withParsed(t, cipher, nil)
			sample.withTurn(t, cipher, prepared)
			binaryBefore := append([]byte(nil), sample.plain.TurnGraph.Binaries[0].Data...)

			detail := assertSameOutputs(t, cipher, sample)
			if detail.Turn == nil || detail.Conversation == nil || len(detail.Headers) != 6 || detail.RequestURI != plainSampleURI ||
				detail.TokenLink == nil || detail.TokenLink.CostUSD == nil {
				t.Fatalf("detail = %+v", detail)
			}
			rebuilt, err := ReconstructPlainTurn(sample.plain)
			if err != nil {
				t.Fatal(err)
			}
			if canonicalOf(t, rebuilt.Request) != string(requestBody) || canonicalOf(t, rebuilt.Response) != string(responseBody) {
				t.Fatalf("rebuilt provider values differ from the originals")
			}
			if !bytes.Equal(sample.plain.TurnGraph.Binaries[0].Data, binaryBefore) {
				t.Fatal("assembly changed a caller's binary bytes")
			}
			// Assembly mutates what it opens; a second run from the same input
			// must still see fresh objects.
			again, err := BuildDetail(sample.plain)
			if err != nil || !reflect.DeepEqual(again, detail) {
				t.Fatalf("second BuildDetail differs: %v", err)
			}
		})
	}
}

// An audit without a turn reads its fallback conversation from the parsed
// result; the payload is large enough that the database row is gzip
// compressed, while the plaintext side holds the JSON itself.
func TestPlainAssemblyReadsTheFallbackConversationWithoutATurn(t *testing.T) {
	t.Parallel()
	cipher := testCipher(t)
	sample := newPlainSample(t, cipher, "audit-plain-fallback", storage.CaptureVersion1)
	parsedJSON, err := json.Marshal(map[string]any{"status": "ok", "conversation": largeFallbackConversation()})
	if err != nil {
		t.Fatal(err)
	}
	sample.withParsed(t, cipher, parsedJSON)
	detail := assertSameOutputs(t, cipher, sample)
	if detail.Turn != nil || !reflect.DeepEqual(detail.Conversation, largeFallbackConversation()) {
		t.Fatalf("fallback conversation = %+v", detail.Conversation)
	}
	if _, err := ReconstructPlainTurn(sample.plain); !errors.Is(err, ErrNoTurnGraph) {
		t.Fatalf("ReconstructPlainTurn = %v, want ErrNoTurnGraph", err)
	}

	// No payload at all: no conversation in the detail, and not found for
	// the session view, on both paths.
	empty := newPlainSample(t, cipher, "audit-plain-no-payload", storage.CaptureVersion2)
	empty.withParsed(t, cipher, nil)
	assertSameOutputs(t, cipher, empty)
	if _, err := PlainSessionConversation(empty.plain); !errors.Is(err, ErrNotFound) {
		t.Fatalf("PlainSessionConversation = %v, want ErrNotFound", err)
	}

	// A payload that is not the parsed envelope fails the same way.
	broken := newPlainSample(t, cipher, "audit-plain-broken-payload", storage.CaptureVersion1)
	broken.withParsed(t, cipher, []byte(`{"conversation":{"schema_version":99}}`))
	assertSameOutputs(t, cipher, broken)
	if _, err := BuildDetail(broken.plain); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("BuildDetail = %v, want ErrIntegrity", err)
	}
}

// A request-only turn rebuilds the request messages from the graph and
// appends the response-phase messages kept in the parsed result.
func TestPlainAssemblyMergesPartialResponseMessages(t *testing.T) {
	t.Parallel()
	cipher := testCipher(t)
	auditID := "audit-plain-request-only"
	sample := newPlainSample(t, cipher, auditID, storage.CaptureVersion2)
	sample.stored.Audit.ParserName, sample.plain.Audit.ParserName = openai.ChatCompletions, openai.ChatCompletions
	message := map[string]any{"role": "user", "content": "question example"}
	prepared, err := auditmodel.Prepare(auditmodel.Turn{
		AuditID: auditID, Protocol: "openai", ParserName: openai.ChatCompletions,
		RequestLayout: auditmodel.LayoutOpenAIChatRequest, ResponseLayout: auditmodel.LayoutNone,
		RequestEnvelope: map[string]any{"model": "model-example"},
		RequestItems:    []auditmodel.Item{{Slot: auditmodel.SlotMessages, Kind: "user_message", Value: message}},
		RequestOriginal: map[string]any{"model": "model-example", "messages": []any{message}}, CreatedAtNS: 3,
	}, cipher)
	if err != nil {
		t.Fatal(err)
	}
	partial := []conversation.Message{{
		Index: 5, Role: conversation.RoleAssistant, Phase: conversation.PhaseResponse, Direction: conversation.DirectionUpstreamToClient,
		Content: []conversation.Part{conversation.Text("half an answer")},
	}}
	parsedJSON, err := json.Marshal(map[string]any{"status": "partial", base.PartialResponseMessagesKey: partial})
	if err != nil {
		t.Fatal(err)
	}
	sample.withParsed(t, cipher, parsedJSON)
	sample.withTurn(t, cipher, prepared)
	detail := assertSameOutputs(t, cipher, sample)
	if detail.Conversation == nil || len(detail.Conversation.Messages) != 2 ||
		detail.Conversation.Messages[1].Index != 1 || detail.Conversation.Messages[1].Content[0].Text != "half an answer" {
		t.Fatalf("merged conversation = %+v", detail.Conversation)
	}

	// A partial message that is not a response-phase message fails the same
	// way on both paths, with the same message.
	bad := sample
	badJSON, err := json.Marshal(map[string]any{base.PartialResponseMessagesKey: []conversation.Message{{
		Role: conversation.RoleUser, Phase: conversation.PhaseRequest, Direction: conversation.DirectionClientToUpstream,
		Content: []conversation.Part{conversation.Text("x")},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	bad.withParsed(t, cipher, badJSON)
	assertSameOutputs(t, cipher, bad)
	if _, err := ReconstructPlainTurn(bad.plain); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("ReconstructPlainTurn = %v, want ErrIntegrity", err)
	}
}

// Damaged plaintext is rejected at the stage the database path names for
// the same damage after decryption.
func TestPlainAssemblyRejectsObjectsThatDoNotMatchTheirAddress(t *testing.T) {
	t.Parallel()
	cipher := testCipher(t)
	sample := newPlainSample(t, cipher, "audit-plain-damaged", storage.CaptureVersion2)
	prepared, _, _ := plainResponsesTurn(t, cipher, "audit-plain-damaged")
	sample.withTurn(t, cipher, prepared)

	objects := append([]PlainObject(nil), sample.plain.TurnGraph.Objects...)
	for index, object := range objects {
		if object.Kind == "request_envelope" {
			damaged := append([]byte(nil), object.Plaintext...)
			damaged[len(damaged)-2] ^= 1
			objects[index].Plaintext = damaged
		}
	}
	damaged := sample.plain
	graph := *sample.plain.TurnGraph
	graph.Objects = objects
	damaged.TurnGraph = &graph
	if _, err := ReconstructPlainTurn(damaged); err == nil || err.Error() != integrityAt("request_envelope").Error() {
		t.Fatalf("damaged envelope: %v", err)
	}

	binaries := append([]PlainBinary(nil), sample.plain.TurnGraph.Binaries...)
	binaries[0].Data = append([]byte(nil), binaries[0].Data...)
	binaries[0].Data[0] ^= 1
	graph = *sample.plain.TurnGraph
	graph.Binaries = binaries
	damaged.TurnGraph = &graph
	if _, err := ReconstructPlainTurn(damaged); err == nil || err.Error() != integrityAt("request_binary_restore").Error() {
		t.Fatalf("damaged binary: %v", err)
	}
}

// The list row shows the same User-Agent as Service.List for a version 2 row.
func TestPlainSummaryMatchesTheList(t *testing.T) {
	t.Parallel()
	cipher := testCipher(t)
	for _, testCase := range userAgentCases {
		auditID := "audit-plain-summary"
		fields := headerblock.Snapshot(testCase.headers)
		values := headerblock.UserAgentValues(fields)
		sealed, err := headerblock.SealUserAgent(cipher, auditID, values)
		if err != nil {
			t.Fatal(err)
		}
		row := sqlite.AuditListRow{AuditID: auditID, StartedAtNS: 5, CaptureVersion: storage.CaptureVersion2, UserAgentEnc: sealed}
		service, err := New(&fakeStore{healthy: true, listPage: sqlite.AuditListPage{Rows: []sqlite.AuditListRow{row}}}, cipher)
		if err != nil {
			t.Fatal(err)
		}
		page, err := service.List(context.Background(), Filter{}, Cursor{}, 10)
		if err != nil || len(page.Items) != 1 {
			t.Fatalf("%s: List = %+v, %v", testCase.name, page, err)
		}
		if got := BuildSummary(row, values); !reflect.DeepEqual(got, page.Items[0]) {
			t.Fatalf("%s: summary differs:\n list      %+v\n plaintext %+v", testCase.name, page.Items[0], got)
		}
	}
}

// The timeline comes out the same from its plaintext, including the
// integrity failures that depend on the row.
func TestPlainTimelineMatchesTheDatabasePath(t *testing.T) {
	t.Parallel()
	cipher := testCipher(t)
	auditID := "audit-plain-timeline"
	stage := sqlite.StageResponseReceived
	points := []streamtimeline.Point{{Offset: 20, AtNS: 100}, {Offset: 50, AtNS: 110}, {Offset: 90, AtNS: 125}}
	plaintext, err := streamtimeline.Encode(points)
	if err != nil {
		t.Fatal(err)
	}
	compression, encoded, err := bodycodec.Encode(plaintext, "application/x-llmapi-stream-timeline")
	if err != nil {
		t.Fatal(err)
	}
	aad, err := security.AAD(auditID, "stream_timeline_v1", stage, compression)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := cipher.Encrypt(aad, encoded)
	if err != nil {
		t.Fatal(err)
	}
	first, last, early := points[0].AtNS, points[len(points)-1].AtNS, points[len(points)-1].AtNS-1
	valid := sqlite.StoredStreamTimeline{
		AuditID: auditID, Stage: stage, ObservedLength: 100,
		EventCount: int64(len(points)), FirstEventAtNS: &first, LastEventAtNS: &last,
		Complete: true, Compression: compression, PlaintextLength: int64(len(plaintext)), DataEnc: encrypted,
	}
	short, wrongLast, tooMany := valid, valid, valid
	short.ObservedLength = 80
	wrongLast.LastEventAtNS = &early
	tooMany.EventCount = 4
	for name, stored := range map[string]sqlite.StoredStreamTimeline{"valid": valid, "short body": short, "wrong last": wrongLast, "count": tooMany} {
		service, err := New(&fakeStore{healthy: true, timeline: stored, rawMetaByStage: map[string]sqlite.RawBodyMetadata{stage: {Stage: stage}}}, cipher)
		if err != nil {
			t.Fatal(err)
		}
		hot, hotErr := service.Timeline(context.Background(), auditID, SideResponse)
		plain, plainErr := TimelineFromPlain(stored, plaintext)
		if sameError(t, name, hotErr, plainErr) && (!reflect.DeepEqual(hot, plain) || len(plain.Points) != 3) {
			t.Fatalf("%s: timeline differs:\n database  %+v\n plaintext %+v", name, hot, plain)
		}
		if name != "valid" && !errors.Is(plainErr, ErrIntegrity) {
			t.Fatalf("%s: %v, want ErrIntegrity", name, plainErr)
		}
	}
	if _, err := TimelineFromPlain(valid, plaintext[:len(plaintext)-1]); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("short plaintext: %v", err)
	}
}

// A raw body comes out byte for byte the same with the same metadata, for a
// complete body, a body with a recorded chunk loss, and the failures.
func TestPlainRawMatchesTheDatabasePath(t *testing.T) {
	t.Parallel()
	cipher := testCipher(t)
	auditID := "audit-plain-raw"
	stage := sqlite.StageRequestSent
	parts := [][]byte{bytes.Repeat([]byte("compressible request text "), 64), []byte("tail")}
	var chunks []sqlite.BodyChunk
	var plainChunks []PlainChunk
	var offset int64
	for sequence, part := range parts {
		compression, encoded, err := bodycodec.Encode(part, "text/plain")
		if err != nil {
			t.Fatal(err)
		}
		aad, err := security.AAD(auditID, "body_chunk_v2", stage, strconv.Itoa(sequence), compression)
		if err != nil {
			t.Fatal(err)
		}
		encrypted, err := cipher.Encrypt(aad, encoded)
		if err != nil {
			t.Fatal(err)
		}
		chunks = append(chunks, sqlite.BodyChunk{AuditID: auditID, Stage: stage, Seq: int64(sequence), Offset: offset,
			PlaintextLength: len(part), EncodedLength: len(encoded), Compression: compression, DataEnc: encrypted})
		plainChunks = append(plainChunks, PlainChunk{Seq: int64(sequence), Offset: offset, PlaintextLength: len(part), Data: part})
		offset += int64(len(part))
	}
	whole := bytes.Join(parts, nil)
	digest := sha256.Sum256(whole)
	complete := sqlite.RawBodyMetadata{AuditID: auditID, Stage: stage, ObservedLength: offset, StoredLength: offset, SHA256: digest[:],
		HashComplete: true, EOFSeen: true, State: sqlite.StageStateComplete, RetentionState: sqlite.RetentionFull}
	missingCode := storage.CaptureChunkMissing
	missing := sqlite.RawBodyMetadata{AuditID: auditID, Stage: stage, ObservedLength: offset, StoredLength: int64(len(parts[1])),
		State: sqlite.StageStatePartial, RetentionState: sqlite.RetentionFull, ErrorCode: &missingCode}
	wrongDigest := complete
	wrongDigest.SHA256 = bytes.Repeat([]byte{9}, 32)
	notRetained := complete
	notRetained.RetentionState = sqlite.RetentionMetadata
	streaming := complete
	streaming.State = sqlite.StageStateStreaming

	cases := []struct {
		name       string
		metadata   sqlite.RawBodyMetadata
		chunks     []sqlite.BodyChunk
		plain      []PlainChunk
		want       []byte
		wantErr    error
		wantMetErr error
	}{
		{"complete", complete, chunks, plainChunks, whole, nil, nil},
		{"recorded loss", missing, chunks[1:], plainChunks[1:], parts[1], nil, nil},
		{"unrecorded gap", complete, chunks[1:], plainChunks[1:], nil, ErrIntegrity, nil},
		{"wrong digest", wrongDigest, chunks, plainChunks, nil, ErrIntegrity, nil},
		{"not retained", notRetained, chunks, plainChunks, nil, ErrNotRetained, ErrNotRetained},
		{"streaming", streaming, chunks, plainChunks, nil, ErrNotReady, ErrNotReady},
	}
	for _, testCase := range cases {
		store := &fakeStore{healthy: true, rawMetaByStage: map[string]sqlite.RawBodyMetadata{stage: testCase.metadata}, chunks: testCase.chunks}
		service, err := New(store, cipher)
		if err != nil {
			t.Fatal(err)
		}
		hotMeta, hotErr := service.RawMeta(context.Background(), auditID, SideRequest)
		plainMeta, plainErr := RawMetadataFromPlain(testCase.metadata)
		if sameError(t, testCase.name+" metadata", hotErr, plainErr) && !reflect.DeepEqual(hotMeta, plainMeta) {
			t.Fatalf("%s: metadata differs: %+v, %+v", testCase.name, hotMeta, plainMeta)
		}
		if !errors.Is(plainErr, testCase.wantMetErr) {
			t.Fatalf("%s: metadata error %v", testCase.name, plainErr)
		}

		var hotBody, plainBody bytes.Buffer
		hotErr = service.StreamRaw(context.Background(), auditID, SideRequest, &hotBody)
		plainErr = VerifyRaw(context.Background(), testCase.metadata, func(visit func(PlainChunk) error) error {
			for _, chunk := range testCase.plain {
				if err := visit(chunk); err != nil {
					return err
				}
			}
			return nil
		}, &plainBody)
		sameError(t, testCase.name+" body", hotErr, plainErr)
		if !errors.Is(plainErr, testCase.wantErr) || !bytes.Equal(hotBody.Bytes(), plainBody.Bytes()) {
			t.Fatalf("%s: body differs or wrong error %v", testCase.name, plainErr)
		}
		if testCase.wantErr == nil && !bytes.Equal(plainBody.Bytes(), testCase.want) {
			t.Fatalf("%s: body = %q", testCase.name, plainBody.Bytes())
		}
	}

	// A chunk whose bytes disagree with its recorded length is rejected
	// before anything of it is written.
	var written bytes.Buffer
	short := plainChunks[0]
	short.Data = short.Data[:len(short.Data)-1]
	err := VerifyRaw(context.Background(), complete, func(visit func(PlainChunk) error) error { return visit(short) }, &written)
	if !errors.Is(err, ErrIntegrity) || written.Len() != 0 {
		t.Fatalf("short chunk: %v, wrote %d", err, written.Len())
	}

	if stages, err := RawStages(SideResponse); err != nil || !reflect.DeepEqual(stages, []string{storage.StageResponseReceived, storage.StageResponseSent}) {
		t.Fatalf("RawStages = %v, %v", stages, err)
	}
}
