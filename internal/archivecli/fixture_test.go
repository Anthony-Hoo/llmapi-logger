package archivecli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/archive/bundle"
	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/headerblock"
	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/openai"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/streamtimeline"
)

const (
	runA       = "0123456789abcdef0123456789abcdef"
	runB       = "fedcba9876543210fedcba9876543210"
	baseTimeNS = int64(1764300000000000000) // 2025-11-28 UTC
	// Every synthetic credential starts with credentialMarker and never
	// appears in body content (design Q4 leaves content unprojected); every
	// piece of synthetic content carries contentMarker.
	credentialMarker = "sk-CREDMARK"
	contentMarker    = "PLAINMARK"
)

func minute(n int) int64 { return baseTimeNS + int64(n)*int64(time.Minute) }

func text(value string) *string  { return &value }
func integer(value int64) *int64 { return &value }
func small(value int) *int       { return &value }

type chunkID struct {
	auditID, stage string
	seq            int64
}

// payloads holds the objects and raw chunks of the fixture's records. It is
// the writer's bundle.Payloads and, for the expected values, an
// archive.ObjectSource.
type payloads struct {
	contents map[string]archive.ContentObject
	binaries map[string]archive.BinaryObject
	chunks   map[chunkID][]byte
}

func (p *payloads) ContentObject(hash []byte) (archive.ContentObject, error) {
	if object, ok := p.contents[string(hash)]; ok {
		return object, nil
	}
	return archive.ContentObject{}, errors.New("missing content object")
}

func (p *payloads) BinaryObject(hash []byte) (archive.BinaryObject, error) {
	if object, ok := p.binaries[string(hash)]; ok {
		return object, nil
	}
	return archive.BinaryObject{}, errors.New("missing binary object")
}

func (p *payloads) RawChunk(auditID, stage string, seq int64) ([]byte, error) {
	if data, ok := p.chunks[chunkID{auditID, stage, seq}]; ok {
		return data, nil
	}
	return nil, errors.New("missing raw chunk")
}

func (p *payloads) ContentPlaintext(hash []byte) ([]byte, error) {
	object, err := p.ContentObject(hash)
	return object.Data, err
}

func (p *payloads) BinaryData(hash []byte) ([]byte, error) {
	object, err := p.BinaryObject(hash)
	return object.Data, err
}

// exchange is what a real turn was built from.
type exchange struct {
	request, response []byte
	points            []streamtimeline.Point
}

type fixture struct {
	t        *testing.T
	master   []byte
	keys     *Keys
	keyPath  string
	root     string
	payloads *payloads
	signer   *security.IntegritySigner
	// exchanges by audit id; expected raw bodies by audit id and side.
	exchanges map[string]exchange
	raw       map[string][]byte
	// originals are the plaintext request URI and headers of each audit,
	// as the hot database holds them before the projection.
	originals map[string]original
}

type original struct {
	uri     []byte
	headers []headerblock.Value
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	master := bytes.Repeat([]byte{0x42}, security.KeySize)
	keys, err := NewKeys(master)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "audit.key")
	if err := os.WriteFile(keyPath, master, 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "archive")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return &fixture{t: t, master: master, keys: keys, keyPath: keyPath, root: root,
		payloads:  &payloads{contents: map[string]archive.ContentObject{}, binaries: map[string]archive.BinaryObject{}, chunks: map[chunkID][]byte{}},
		signer:    keys.Events,
		exchanges: map[string]exchange{}, raw: map[string][]byte{}, originals: map[string]original{}}
}

// otherKeyFile writes a different master key and returns its path.
func (f *fixture) otherKeyFile() string {
	path := filepath.Join(f.t.TempDir(), "other.key")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x24}, security.KeySize), 0o600); err != nil {
		f.t.Fatal(err)
	}
	return path
}

// credentials of one audit, as the fixture puts them in its headers, URI and
// User-Agent.
func authKey(id string) string  { return credentialMarker + "auth" + id }
func apiKey(id string) string   { return credentialMarker + "-xkey-" + id }
func queryKey(id string) string { return credentialMarker + "-query-" + id }

// audit returns a turnless record with credentials in two headers, a cookie,
// the query string and (version 2) a User-Agent value.
func (f *fixture) audit(id string, startedNS int64, version int64) *archive.Record {
	keys := f.keys.Archive
	uri := "/v1/responses?trace=" + contentMarker + "&key=" + queryKey(id) + "&&alt=sse"
	record := &archive.Record{
		Revision: 1,
		Audit: archive.AuditRow{
			AuditID: id, SchemaGeneration: 2, StartedAtNS: startedNS, EndedAtNS: startedNS + int64(time.Second),
			RouteID: "route-example", Protocol: "openai", ParserName: openai.Responses, Method: "POST", Path: "/v1/responses",
			RequestURI: archive.ProjectRequestURI(keys, []byte(uri)), Mode: "strict", StatusCode: integer(200),
			ForwardStatus: storage.ForwardCompleted, CaptureStatus: storage.CaptureComplete, ParseStatus: storage.ParseOK,
			CallerStatus: storage.CallerResolved, APIKeyFPR: f.keys.Credential.Fingerprint(authKey(id)), CaptureVersion: version,
		},
		Stages: []archive.Stage{{HTTPStage: storage.HTTPStage{Stage: storage.StageRequestReceived, State: storage.StageStateComplete,
			Proto: "HTTP/1.1", Method: "POST", Host: "api.example.com", StatusCode: small(200), StartedAtNS: startedNS + 1}}},
		Bodies: []storage.BodyStream{}, RawChunks: []archive.RawChunk{}, Timelines: []archive.Timeline{},
	}
	values := []headerblock.Value{
		{Stage: storage.StageRequestReceived, Kind: storage.HeaderKindHeader, Name: "Authorization", Value: []byte("Bearer " + authKey(id))},
		{Stage: storage.StageRequestReceived, Kind: storage.HeaderKindHeader, Name: "x-api-key", Value: []byte(apiKey(id))},
		{Stage: storage.StageRequestReceived, Kind: storage.HeaderKindHeader, Name: "Cookie", Value: []byte("session=" + credentialMarker + "-cookie-" + id)},
		{Stage: storage.StageRequestReceived, Kind: storage.HeaderKindHeader, Name: "X-Trace", Value: []byte(contentMarker + "-header")},
		{Stage: storage.StageRequestReceived, Kind: storage.HeaderKindHeader, Name: "User-Agent", Value: []byte("client/1.0")},
		{Stage: storage.StageResponseReceived, Kind: storage.HeaderKindHeader, Name: "Set-Cookie", Value: []byte("id=" + credentialMarker + "-set-" + id)},
	}
	record.Headers = archive.Headers{CaptureVersion: version, Values: archive.ProjectHeaders(keys, values)}
	f.originals[id] = original{uri: []byte(uri), headers: values}
	if version == storage.CaptureVersion2 {
		record.Headers.BlockPresent = true
		record.Headers.BlockStages = []string{storage.StageRequestReceived, storage.StageResponseReceived}
		record.Audit.UserAgent = archive.ProjectUserAgent(keys, []string{"client/1.0", credentialMarker + "-ua-" + id})
	}
	f.event(record, 1, "capture_finalized", startedNS+2)
	return record
}

// event appends an integrity event with a real MAC under the fixture's
// master key.
func (f *fixture) event(record *archive.Record, sequence int64, eventType string, createdNS int64) {
	f.t.Helper()
	previous := bytes.Repeat([]byte{byte(sequence)}, 32)
	digest := sha256.Sum256([]byte(record.Audit.AuditID + eventType))
	mac, err := f.signer.MAC(previous, record.Audit.AuditID, eventType, digest[:], createdNS)
	if err != nil {
		f.t.Fatal(err)
	}
	record.IntegrityEvents = append(record.IntegrityEvents, archive.IntegrityEvent{Sequence: sequence, EventType: eventType,
		PreviousMAC: previous, PayloadDigest: digest[:], EventMAC: mac, CreatedAtNS: createdNS})
}

// withRaw gives the record a body at stage cut into chunkSize pieces, and
// when paired is set the paired stage served from it (source_stage).
func (f *fixture) withRaw(record *archive.Record, stage, paired string, data []byte, chunkSize int, complete bool) {
	body := storage.BodyStream{Stage: stage, SourceStage: stage, ObservedLength: int64(len(data)), StoredLength: int64(len(data)),
		HashComplete: complete, EOFSeen: true, State: storage.StageStateComplete, RetentionState: storage.RetentionFull}
	if complete {
		sum := sha256.Sum256(data)
		body.SHA256 = sum[:]
	} else {
		body.State = storage.StageStatePartial
		body.HashComplete = false
		body.ErrorCode = text("capture_truncated")
		body.ObservedLength = int64(len(data)) + 100
	}
	for offset, seq := 0, int64(0); offset < len(data); seq++ {
		end := min(offset+chunkSize, len(data))
		piece := data[offset:end]
		record.RawChunks = append(record.RawChunks, archive.RawChunk{Stage: stage, Seq: seq, Offset: int64(offset), PlaintextLength: int64(len(piece)),
			ObservedAtNS: record.Audit.StartedAtNS + seq, SHA256: sha256.Sum256(piece)})
		f.payloads.chunks[chunkID{record.Audit.AuditID, stage, seq}] = piece
		body.ChunkCount++
		offset = end
	}
	record.Bodies = append(record.Bodies, body)
	if paired != "" {
		pair := body
		pair.Stage = paired
		record.Bodies = append(record.Bodies, pair)
	}
}

// withRealTurn gives the record a root turn that the OpenAI Responses
// parser and auditmodel.Prepare produce from a real exchange with an inline
// image, the raw request (received, and sent served from it) and response
// (received, and sent served from it), and a response stream timeline.
func (f *fixture) withRealTurn(record *archive.Record, conversationID string, createdNS int64, prompt string) {
	f.t.Helper()
	f.withRealChildTurn(record, conversationID, createdNS, prompt, nil, nil, false)
}

// userItem is the Responses input message of a prompt, with an inline image
// that depends on the prompt.
func userItem(prompt string) map[string]any {
	png := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0x62, byte(len(prompt))}, 64)...)
	return map[string]any{"type": "message", "role": "user", "content": []any{
		map[string]any{"type": "input_text", "text": prompt + " " + contentMarker},
		map[string]any{"type": "input_image", "image_url": "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)},
	}}
}

// answerItem is the Responses output message that answers prompt in audit
// auditID.
func answerItem(auditID, prompt string) map[string]any {
	return map[string]any{"type": "message", "id": "message-" + auditID, "role": "assistant",
		"content": []any{map[string]any{"type": "output_text", "text": "answer to " + prompt + " " + contentMarker}}}
}

// withRealChildTurn is withRealTurn for a turn whose request repeats history
// (the earlier input and output items) before the new prompt. With a parent
// it is the parent's child (parent_base post_turn), its context the delta
// against the parent's request and response. A requestOnly turn has no
// response: the exchange ended before the upstream answered.
func (f *fixture) withRealChildTurn(record *archive.Record, conversationID string, createdNS int64, prompt string, parent *archive.Record, history []any, requestOnly bool) {
	t := f.t
	t.Helper()
	auditID := record.Audit.AuditID
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{7}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	implementation, err := openai.New(openai.Responses)
	if err != nil {
		t.Fatal(err)
	}
	requestBody, err := auditmodel.CanonicalJSON(map[string]any{
		"model": "model-example",
		"input": append(append([]any(nil), history...), userItem(prompt)),
	})
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err := auditmodel.CanonicalJSON(map[string]any{
		"id": "response-" + auditID, "object": "response", "model": "model-result",
		"output": []any{answerItem(auditID, prompt)},
		"usage":  map[string]any{"input_tokens": 12, "output_tokens": 4, "total_tokens": 16},
	})
	if err != nil {
		t.Fatal(err)
	}
	input := base.Input{AuditID: auditID, Protocol: "openai", Endpoint: "/v1/responses",
		Request:  base.BodySource{Present: true, Complete: true, ContentType: "application/json", Data: requestBody},
		Response: base.BodySource{Present: true, Complete: true, ContentType: "application/json", Data: responseBody}}
	if requestOnly {
		responseBody, input.Response = nil, base.BodySource{}
	}
	normalized, err := implementation.NormalizeAudit(context.Background(), input, implementation.Parse(context.Background(), input))
	if err != nil {
		t.Fatal(err)
	}
	normalized.CreatedAtNS = createdNS
	prepared, err := auditmodel.Prepare(normalized, cipher)
	if err != nil {
		t.Fatal(err)
	}
	turn := &archive.Turn{
		Row: archive.TurnRow{TurnID: "turn-" + auditID, ConversationID: conversationID, ParentBase: auditmodel.ParentBaseRoot, LinkReason: "root",
			LinkConfidence: 100, RequestLayout: prepared.RequestLayout, ResponseLayout: prepared.ResponseLayout,
			RequestEnvelopeHash: prepared.RequestEnvelopeHash, ResponseEnvelopeHash: prepared.ResponseEnvelopeHash,
			RequestItemCount: int64(len(prepared.RequestRefs)), ResponseItemCount: int64(len(prepared.ResponseRefs)),
			RequestSequenceHash: prepared.RequestSequenceHash, ResponseSequenceHash: prepared.ResponseSequenceHash,
			RequestReconstructionHash: prepared.RequestReconstructionHash, ResponseReconstructionHash: prepared.ResponseReconstructionHash,
			ReconstructionStatus: "verified", CreatedAtNS: prepared.CreatedAtNS},
		RequestRefs: append([]auditmodel.ObjectRef(nil), prepared.RequestRefs...),
	}
	var parentRefs []auditmodel.ObjectRef
	if parent != nil {
		turn.Row.ParentTurnID = text(parent.Turn.Row.TurnID)
		turn.Row.ParentBase = auditmodel.ParentBasePostTurn
		turn.Row.LinkReason = "conversation_key"
		turn.Row.LinkConfidence = 90
		parentRefs = append(append([]auditmodel.ObjectRef(nil), parent.Turn.RequestRefs...), parent.Turn.ResponseRefs()...)
	}
	turn.Context = archive.RequestContext{Form: archive.ContextDelta, Ops: archive.ContextOpsFrom(auditmodel.BuildDelta(parentRefs, prepared.RequestRefs))}
	if prepared.ResponseID != "" {
		turn.Row.ResponseID = text(prepared.ResponseID)
	}
	for index, ref := range prepared.ResponseRefs {
		turn.ResponseItems = append(turn.ResponseItems, archive.ResponseItem{Ordinal: int64(index), Slot: ref.Slot, ObjectHash: ref.ObjectHash, SemanticHash: ref.SemanticHash})
	}
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
		f.payloads.contents[string(object.Hash)] = archive.ContentObject{Hash: object.Hash, SemanticHash: object.SemanticHash, Kind: object.Kind,
			PlaintextLength: object.PlaintextLength, CreatedAtNS: baseTimeNS, Data: canonical}
		turn.Objects = append(turn.Objects, archive.ObjectMeta{Hash: object.Hash, SemanticHash: object.SemanticHash, Kind: object.Kind, PlaintextLength: object.PlaintextLength})
		for _, ref := range object.BinaryRefs {
			turn.BinaryRefs = append(turn.BinaryRefs, archive.BinaryRef{ObjectHash: object.Hash, JSONPointer: ref.JSONPointer, BinaryHash: ref.BinaryHash, MediaType: ref.MediaType, Encoding: ref.Encoding})
		}
	}
	for _, binary := range prepared.Binaries {
		data, err := auditmodel.OpenBinary(cipher, auditmodel.StoredBinary{Hash: binary.Hash, MediaType: binary.MediaType,
			Compression: binary.Compression, PlaintextLength: binary.PlaintextLength, EncodedLength: binary.EncodedLength, DataEnc: binary.DataEnc})
		if err != nil {
			t.Fatal(err)
		}
		f.payloads.binaries[string(binary.Hash)] = archive.BinaryObject{Hash: binary.Hash, MediaType: binary.MediaType, PlaintextLength: binary.PlaintextLength, CreatedAtNS: baseTimeNS, Data: data}
		turn.Binaries = append(turn.Binaries, archive.BinaryMeta{Hash: binary.Hash, MediaType: binary.MediaType, PlaintextLength: binary.PlaintextLength})
	}
	record.Turn = turn
	record.Conversation = &archive.Conversation{ConversationID: conversationID, Protocol: "openai", KeyHash: bytes.Repeat([]byte{0x81}, 32), CreatedAtNS: baseTimeNS}
	record.ParsedResult = &archive.ParsedResult{ParserName: openai.Responses, ParserVersion: "1", Status: storage.ParseOK,
		RequestModel: text("model-example"), ResponseModel: text("model-result"), ParsedAtNS: record.Audit.EndedAtNS + 1}
	f.withRaw(record, storage.StageRequestReceived, storage.StageRequestSent, requestBody, 64, true)
	f.raw[auditID+"/request"] = requestBody
	if requestOnly {
		f.event(record, 2, "semantic_compacted", createdNS+1)
		f.exchanges[auditID] = exchange{request: requestBody}
		return
	}
	f.withRaw(record, storage.StageResponseReceived, storage.StageResponseSent, responseBody, 100, true)
	f.raw[auditID+"/response"] = responseBody
	points := []streamtimeline.Point{{Offset: 10, AtNS: record.Audit.StartedAtNS + 10}, {Offset: 40, AtNS: record.Audit.StartedAtNS + 20}, {Offset: int64(len(responseBody)), AtNS: record.Audit.StartedAtNS + 35}}
	encoded, err := streamtimeline.Encode(points)
	if err != nil {
		t.Fatal(err)
	}
	record.Timelines = append(record.Timelines, archive.Timeline{Stage: storage.StageResponseReceived, EventCount: int64(len(points)),
		FirstEventAtNS: integer(points[0].AtNS), LastEventAtNS: integer(points[len(points)-1].AtNS), Complete: true,
		PlaintextLength: int64(len(encoded)), Plaintext: encoded})
	for index := range record.Bodies {
		if record.Bodies[index].SourceStage == storage.StageResponseReceived {
			record.Bodies[index].StreamEventCount = int64(len(points))
			record.Bodies[index].StreamTimelineComplete = true
		}
	}
	f.event(record, 2, "semantic_compacted", createdNS+1)
	f.exchanges[auditID] = exchange{request: requestBody, response: responseBody, points: points}
}

func (f *fixture) canonical(record *archive.Record) *archive.Record {
	f.t.Helper()
	if err := record.Canonicalize(); err != nil {
		f.t.Fatal(err)
	}
	return record
}

// writeSegment writes records as one published segment and returns its
// manifest path.
func (f *fixture) writeSegment(encrypt bool, runID string, spec bundle.Spec, records ...*archive.Record) string {
	f.t.Helper()
	options := bundle.Options{Root: f.root, Signer: f.keys.Archive, Encrypt: encrypt, SourceSchemaVersion: "8", RunID: runID,
		Now: func() time.Time { return time.Unix(0, baseTimeNS+int64(time.Hour)) }}
	if encrypt {
		options.EncryptionKey = f.keys.Archive.EncryptionKey()
	}
	writer, err := bundle.NewSegment(options, spec, f.payloads)
	if err != nil {
		f.t.Fatal(err)
	}
	for _, record := range records {
		if err := writer.Add(record); err != nil {
			f.t.Fatalf("add %s: %v (%v)", record.Audit.AuditID, err, errors.Unwrap(err))
		}
	}
	sealed, err := writer.Seal()
	if err != nil {
		f.t.Fatalf("seal: %v (%v)", err, errors.Unwrap(err))
	}
	if err := sealed.Publish(); err != nil {
		f.t.Fatalf("publish: %v (%v)", err, errors.Unwrap(err))
	}
	return sealed.ManifestPath()
}

func (f *fixture) writeGaps(encrypt bool) string {
	f.t.Helper()
	options := bundle.Options{Root: f.root, Signer: f.keys.Archive, Encrypt: encrypt, SourceSchemaVersion: "8", RunID: runA}
	if encrypt {
		options.EncryptionKey = f.keys.Archive.EncryptionKey()
	}
	writer, err := bundle.NewGapSegment(options)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := writer.Add(archive.Gap{ID: 7, StartedAtNS: minute(50), EndedAtNS: minute(51), Reason: "writer_down", RequestCount: 3, Detail: "{}", CreatedAtNS: minute(52)}); err != nil {
		f.t.Fatal(err)
	}
	sealed, err := writer.Seal()
	if err != nil {
		f.t.Fatal(err)
	}
	if err := sealed.Publish(); err != nil {
		f.t.Fatal(err)
	}
	return sealed.ManifestPath()
}

// scenario is the archive most tests read: conversation conv_main spread
// over a conversation bundle (c1, c2), a bucket (c3 and the turnless loose)
// and a second bucket of a later run with revision 2 of c2; and a gap
// bundle. c4 is a version 1 audit of another conversation in the first
// bucket.
type scenario struct {
	*fixture
	encrypt      bool
	records      map[string]*archive.Record // highest revisions
	c2r1         *archive.Record
	conversation string
	bundles      map[string]string // name → manifest path
}

func newScenario(t *testing.T, encrypt bool) *scenario {
	f := newFixture(t)
	s := &scenario{fixture: f, encrypt: encrypt, records: map[string]*archive.Record{}, conversation: "conv_main", bundles: map[string]string{}}

	c1 := f.audit("c1", minute(0), storage.CaptureVersion2)
	f.withRealTurn(c1, s.conversation, minute(0)+500, "first question")
	c2 := f.audit("c2", minute(1), storage.CaptureVersion2)
	f.withRealTurn(c2, s.conversation, minute(1)+500, "second question")
	s.bundles["conversation"] = f.writeSegment(encrypt, runA, bundle.Spec{Kind: archive.BundleConversation, Protocol: "openai", ConversationID: s.conversation, Index: 1},
		f.canonical(c1), f.canonical(c2))

	c3 := f.audit("c3", minute(2), storage.CaptureVersion2)
	f.withRealTurn(c3, s.conversation, minute(2)+500, "third question")
	c4 := f.audit("c4", minute(3), storage.CaptureVersion1)
	f.withRealTurn(c4, "conv_other", minute(3)+500, "other question")
	loose := f.audit("loose", minute(4), storage.CaptureVersion2)
	loose.Audit.ParseStatus = storage.ParseError
	// The turnless record's fallback conversation is c1's rebuilt one,
	// padded past the inline limit so the line splits it into the objects
	// file.
	plain, err := c1.PlainDetail(f.payloads, nil)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := query.ReconstructPlainTurn(plain)
	if err != nil {
		t.Fatal(err)
	}
	fallback, err := auditmodel.CanonicalJSON(map[string]any{"conversation": rebuilt.Conversation, "pad": strings.Repeat("p", archive.ParsedJSONInlineLimit+1000)})
	if err != nil {
		t.Fatal(err)
	}
	loose.ParsedResult = &archive.ParsedResult{ParserName: openai.Responses, ParserVersion: "1", Status: storage.ParseError,
		ErrorCode: text("normalization_failed"), ParsedJSON: fallback, ParsedAtNS: loose.Audit.EndedAtNS + 1}
	f.withRaw(loose, storage.StageRequestReceived, "", []byte("partial request "+contentMarker+strings.Repeat("r", 300)), 128, false)
	loose.Bodies = append(loose.Bodies, storage.BodyStream{Stage: storage.StageResponseReceived, SourceStage: storage.StageResponseReceived,
		ObservedLength: 10, State: storage.StageStateComplete, HashComplete: true, EOFSeen: true, RetentionState: storage.RetentionMetadata,
		SHA256: bytes.Repeat([]byte{1}, 32)})
	f.raw["loose/request"] = []byte("partial request " + contentMarker + strings.Repeat("r", 300))
	s.bundles["bucket"] = f.writeSegment(encrypt, runA, bundle.Spec{Kind: archive.BundleBucket, Protocol: "openai", Index: 1},
		f.canonical(c3), f.canonical(c4), f.canonical(loose))

	// Revision 2 of c2: the caller was resolved and billed after the first
	// export.
	revised := f.audit("c2", minute(1), storage.CaptureVersion2)
	f.withRealTurn(revised, s.conversation, minute(1)+500, "second question")
	revised.Revision = 2
	revised.TokenLink = &archive.TokenLink{NewAPIUserID: 7, Username: "user-example", NewAPITokenID: 9, TokenName: "token-example",
		LinkedAtNS: minute(30), BillingState: "billed", Quota: integer(100), BillingAttempts: 1}
	s.bundles["revision"] = f.writeSegment(encrypt, runB, bundle.Spec{Kind: archive.BundleBucket, Protocol: "openai", Index: 1}, f.canonical(revised))
	s.bundles["gaps"] = f.writeGaps(encrypt)

	s.c2r1 = c2
	for _, record := range []*archive.Record{c1, revised, c3, c4, loose} {
		s.records[record.Audit.AuditID] = record
	}
	return s
}

func bundleSpecBucket() bundle.Spec {
	return bundle.Spec{Kind: archive.BundleBucket, Protocol: "openai", Index: 1}
}
