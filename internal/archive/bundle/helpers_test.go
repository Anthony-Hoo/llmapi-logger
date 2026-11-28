package bundle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/headerblock"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

const (
	testRunID  = "0123456789abcdef0123456789abcdef"
	baseTimeNS = int64(1764300000000000000) // 2025-11-28 UTC
	// Every synthetic credential starts with credentialMarker, every piece of
	// synthetic content carries contentMarker.
	credentialMarker = "sk-CREDMARK"
	contentMarker    = "PLAINMARK"
)

func testKeys(t *testing.T, seed byte) *security.ArchiveKeys {
	t.Helper()
	keys, err := security.DeriveArchiveKeys(bytes.Repeat([]byte{seed}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func hashOf(seed byte) []byte    { return bytes.Repeat([]byte{seed}, 32) }
func text(value string) *string  { return &value }
func integer(value int64) *int64 { return &value }
func small(value int) *int       { return &value }

type chunkID struct {
	auditID, stage string
	seq            int64
}

// memPayloads is a Payloads over maps; generate, when set, produces raw
// chunks on demand instead of storing them.
type memPayloads struct {
	contents map[string]archive.ContentObject
	binaries map[string]archive.BinaryObject
	chunks   map[chunkID][]byte
	generate func(auditID, stage string, seq int64) []byte
	calls    int
}

func newPayloads() *memPayloads {
	return &memPayloads{contents: map[string]archive.ContentObject{}, binaries: map[string]archive.BinaryObject{}, chunks: map[chunkID][]byte{}}
}

func (payloads *memPayloads) ContentObject(hash []byte) (archive.ContentObject, error) {
	payloads.calls++
	if object, ok := payloads.contents[string(hash)]; ok {
		return object, nil
	}
	return archive.ContentObject{}, errors.New("missing content object")
}

func (payloads *memPayloads) BinaryObject(hash []byte) (archive.BinaryObject, error) {
	payloads.calls++
	if object, ok := payloads.binaries[string(hash)]; ok {
		return object, nil
	}
	return archive.BinaryObject{}, errors.New("missing binary object")
}

func (payloads *memPayloads) RawChunk(auditID, stage string, seq int64) ([]byte, error) {
	payloads.calls++
	if payloads.generate != nil {
		return payloads.generate(auditID, stage, seq), nil
	}
	if data, ok := payloads.chunks[chunkID{auditID, stage, seq}]; ok {
		return data, nil
	}
	return nil, errors.New("missing raw chunk")
}

// fixture builds synthetic records whose objects are real content objects.
type fixture struct {
	t        *testing.T
	keys     *security.ArchiveKeys
	payloads *memPayloads
}

func newFixture(t *testing.T) *fixture {
	return &fixture{t: t, keys: testKeys(t, 0x42), payloads: newPayloads()}
}

func (f *fixture) object(kind string, value any, envelope bool) archive.ObjectMeta {
	f.t.Helper()
	canonical, err := auditmodel.CanonicalJSON(auditmodel.DecodedObject{SchemaVersion: auditmodel.SchemaVersion, Kind: kind, Value: value})
	if err != nil {
		f.t.Fatal(err)
	}
	hash := auditmodel.ContentHash(canonical)
	semantic := hash
	if !envelope {
		var decoded auditmodel.DecodedObject
		if err := auditmodel.DecodeJSON(canonical, &decoded); err != nil {
			f.t.Fatal(err)
		}
		if semantic, err = auditmodel.SemanticHash(kind, decoded.Value); err != nil {
			f.t.Fatal(err)
		}
	}
	meta := archive.ObjectMeta{Hash: hash, SemanticHash: semantic, Kind: kind, PlaintextLength: int64(len(canonical))}
	f.payloads.contents[string(hash)] = archive.ContentObject{Hash: hash, SemanticHash: semantic, Kind: kind, PlaintextLength: meta.PlaintextLength, CreatedAtNS: baseTimeNS, Data: canonical}
	return meta
}

// audit returns a turnless record of the given capture version, with one
// credential in a header, the User-Agent (version 2) and the query string.
func (f *fixture) audit(id, protocol string, startedNS int64, version int64) *archive.Record {
	keys := f.keys
	uri := "/v1/chat/completions?trace=" + contentMarker + "&key=" + credentialMarker + "-query-" + id
	record := &archive.Record{
		Revision: 1,
		Audit: archive.AuditRow{
			AuditID: id, SchemaGeneration: 2, StartedAtNS: startedNS, EndedAtNS: startedNS + int64(time.Second),
			RouteID: "route-example", Protocol: protocol, ParserName: protocol + ".chat", Method: "POST", Path: "/v1/chat/completions",
			RequestURI: archive.ProjectRequestURI(keys, []byte(uri)), Mode: "strict", StatusCode: integer(200),
			ForwardStatus: storage.ForwardCompleted, CaptureStatus: storage.CaptureComplete, ParseStatus: storage.ParseOK,
			CallerStatus: storage.CallerResolved, APIKeyFPR: hashOf(0x31), CaptureVersion: version,
		},
		Stages: []archive.Stage{{HTTPStage: storage.HTTPStage{Stage: storage.StageRequestReceived, State: storage.StageStateComplete,
			Proto: "HTTP/1.1", Method: "POST", Host: "api.example.com", StatusCode: small(200), StartedAtNS: startedNS + 1}}},
		Bodies: []storage.BodyStream{}, RawChunks: []archive.RawChunk{}, Timelines: []archive.Timeline{},
		IntegrityEvents: []archive.IntegrityEvent{{Sequence: 1, EventType: "capture_finalized", PreviousMAC: hashOf(0xa1),
			PayloadDigest: hashOf(0xa2), EventMAC: hashOf(0xa3), CreatedAtNS: startedNS + 2}},
	}
	values := []headerblock.Value{
		{Stage: storage.StageRequestReceived, Kind: storage.HeaderKindHeader, Name: "Authorization", Value: []byte("Bearer " + credentialMarker + "-auth-" + id)},
		{Stage: storage.StageRequestReceived, Kind: storage.HeaderKindHeader, Name: "x-api-key", Value: []byte(credentialMarker + "-xkey-" + id)},
		{Stage: storage.StageRequestReceived, Kind: storage.HeaderKindHeader, Name: "X-Trace", Value: []byte(contentMarker + "-header")},
		{Stage: storage.StageRequestReceived, Kind: storage.HeaderKindHeader, Name: "User-Agent", Value: []byte("client/1.0")},
	}
	record.Headers = archive.Headers{CaptureVersion: version, Values: archive.ProjectHeaders(keys, values)}
	if version == storage.CaptureVersion2 {
		record.Headers.BlockPresent = true
		record.Headers.BlockStages = []string{storage.StageRequestReceived}
		record.Audit.UserAgent = archive.ProjectUserAgent(keys, []string{"client/1.0", credentialMarker + "-ua-" + id})
	}
	return record
}

type turnOptions struct {
	parent    *archive.Record
	messages  []string
	response  string // "" for a request-only turn
	createdNS int64
	binary    bool
}

// withTurn gives the record a turn in delta form: a root turn, or a child of
// parent with parent_base post_turn whose request is the parent's request
// and response followed by the new messages.
func (f *fixture) withTurn(record *archive.Record, conversationID string, options turnOptions) *archive.Record {
	f.t.Helper()
	requestEnvelope := f.object("request_envelope", map[string]any{"model": "model-example", "stream": true}, true)
	objects := []archive.ObjectMeta{requestEnvelope}
	var base []auditmodel.ObjectRef
	row := archive.TurnRow{
		TurnID: "turn-" + record.Audit.AuditID, ConversationID: conversationID, ParentBase: auditmodel.ParentBaseRoot, LinkReason: "root",
		LinkConfidence: 100, RequestLayout: auditmodel.LayoutOpenAIChatRequest, ResponseLayout: "none",
		RequestEnvelopeHash: requestEnvelope.Hash, RequestReconstructionHash: hashOf(0x53), ReconstructionStatus: "verified",
		CreatedAtNS: options.createdNS,
	}
	if parent := options.parent; parent != nil {
		row.ParentTurnID = text(parent.Turn.Row.TurnID)
		row.ParentBase = auditmodel.ParentBasePostTurn
		row.LinkReason = "conversation_key"
		row.LinkConfidence = 90
		base = append(append([]auditmodel.ObjectRef(nil), parent.Turn.RequestRefs...), parent.Turn.ResponseRefs()...)
		objects = append(objects, parent.Turn.Objects...)
	}
	refs := append([]auditmodel.ObjectRef(nil), base...)
	var binaryRefs []archive.BinaryRef
	var binaries []archive.BinaryMeta
	var externals []archive.ExternalRef
	for index, message := range options.messages {
		value := map[string]any{"role": "user", "content": message + " " + contentMarker}
		meta := f.object("message", value, false)
		objects = append(objects, meta)
		refs = append(refs, auditmodel.ObjectRef{Slot: auditmodel.SlotMessages, ObjectHash: meta.Hash, SemanticHash: meta.SemanticHash})
		if options.binary && index == 0 {
			data := append([]byte("\x89PNG"+contentMarker), bytes.Repeat([]byte{byte(index)}, 64)...)
			hash := auditmodel.BinaryHash(data)
			f.payloads.binaries[string(hash)] = archive.BinaryObject{Hash: hash, MediaType: "image/png", PlaintextLength: int64(len(data)), CreatedAtNS: baseTimeNS, Data: data}
			binaryRefs = append(binaryRefs, archive.BinaryRef{ObjectHash: meta.Hash, JSONPointer: "/content", BinaryHash: hash, MediaType: "image/png", Encoding: "base64"})
			binaries = append(binaries, archive.BinaryMeta{Hash: hash, MediaType: "image/png", PlaintextLength: int64(len(data))})
			externals = append(externals, archive.ExternalRef{ObjectHash: meta.Hash, JSONPointer: "/file_id", RefKind: "file_id",
				ValueHash: auditmodel.ExternalValueHash("file_id", "file-example"), Value: "file-example"})
		}
	}
	turn := &archive.Turn{Row: row, BinaryRefs: binaryRefs, ExternalRefs: externals, Binaries: binaries}
	if options.response != "" {
		responseEnvelope := f.object("response_envelope", map[string]any{"id": "response-" + record.Audit.AuditID}, true)
		choice := f.object("choice", map[string]any{"role": "assistant", "content": options.response + " " + contentMarker}, false)
		objects = append(objects, responseEnvelope, choice)
		turn.Row.ResponseLayout = auditmodel.LayoutMarkerEnvelope
		turn.Row.ResponseEnvelopeHash = responseEnvelope.Hash
		turn.Row.ResponseReconstructionHash = hashOf(0x54)
		turn.ResponseItems = []archive.ResponseItem{{Ordinal: 0, Slot: auditmodel.SlotChoice, ObjectHash: choice.Hash, SemanticHash: choice.SemanticHash}}
		turn.Row.ResponseItemCount = 1
		turn.Row.ResponseSequenceHash = auditmodel.SequenceHash(turn.ResponseRefs())
		turn.Row.ResponseID = text("response-" + record.Audit.AuditID)
	} else {
		// A request-only turn still has a response envelope (the column is
		// NOT NULL), with layout none and no items.
		responseEnvelope := f.object("response_envelope", map[string]any{}, true)
		objects = append(objects, responseEnvelope)
		turn.Row.ResponseEnvelopeHash = responseEnvelope.Hash
		turn.Row.ResponseSequenceHash = auditmodel.SequenceHash(nil)
	}
	turn.Row.RequestItemCount = int64(len(refs))
	turn.Row.RequestSequenceHash = auditmodel.SequenceHash(refs)
	turn.RequestRefs = refs
	turn.Context = archive.RequestContext{Form: archive.ContextDelta, Ops: archive.ContextOpsFrom(auditmodel.BuildDelta(base, refs))}
	turn.Objects = uniqueObjects(objects, refs, turn.ResponseRefs(), row.RequestEnvelopeHash, turn.Row.ResponseEnvelopeHash)
	record.Turn = turn
	record.Conversation = &archive.Conversation{ConversationID: conversationID, Protocol: record.Audit.Protocol, KeyHash: hashOf(0x81), CreatedAtNS: baseTimeNS}
	record.IntegrityEvents = append(record.IntegrityEvents, archive.IntegrityEvent{Sequence: 2, EventType: "semantic_compacted",
		PreviousMAC: hashOf(0xa4), PayloadDigest: hashOf(0xa5), EventMAC: hashOf(0xa6), CreatedAtNS: options.createdNS + 1})
	return record
}

// uniqueObjects keeps the objects the turn references: its envelopes and its
// request and response refs, each once.
func uniqueObjects(candidates []archive.ObjectMeta, request, response []auditmodel.ObjectRef, envelopes ...[]byte) []archive.ObjectMeta {
	used := map[string]bool{}
	for _, envelope := range envelopes {
		if envelope != nil {
			used[string(envelope)] = true
		}
	}
	for _, ref := range append(append([]auditmodel.ObjectRef(nil), request...), response...) {
		used[string(ref.ObjectHash)] = true
	}
	var out []archive.ObjectMeta
	seen := map[string]bool{}
	for _, object := range candidates {
		if used[string(object.Hash)] && !seen[string(object.Hash)] {
			seen[string(object.Hash)] = true
			out = append(out, object)
		}
	}
	return out
}

// withRaw gives the record a full body at stage whose chunks are data cut
// into chunkSize pieces; complete selects a complete body with its SHA-256.
func (f *fixture) withRaw(record *archive.Record, stage string, data []byte, chunkSize int, complete bool) *archive.Record {
	body := storage.BodyStream{Stage: stage, SourceStage: stage, ObservedLength: int64(len(data)), StoredLength: int64(len(data)),
		HashComplete: complete, EOFSeen: true, State: storage.StageStateComplete, RetentionState: storage.RetentionFull}
	if complete {
		sum := sha256.Sum256(data)
		body.SHA256 = sum[:]
	} else {
		body.State = storage.StageStatePartial
		body.ErrorCode = text("capture_truncated")
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
	return record
}

func (f *fixture) withParsed(record *archive.Record, parsed []byte) *archive.Record {
	record.ParsedResult = &archive.ParsedResult{ParserName: record.Audit.ParserName, ParserVersion: "3", Status: storage.ParseOK,
		ParsedJSON: parsed, ParsedAtNS: record.Audit.EndedAtNS + 1}
	return record
}

func canonical(t *testing.T, record *archive.Record) *archive.Record {
	t.Helper()
	if err := record.Canonicalize(); err != nil {
		t.Fatal(err)
	}
	return record
}

func (f *fixture) options(root string, encrypt bool) Options {
	options := Options{Root: root, Signer: f.keys, Encrypt: encrypt, SourceSchemaVersion: "8", RunID: testRunID,
		Now: func() time.Time { return time.Unix(0, baseTimeNS+int64(time.Hour)) }}
	if encrypt {
		options.EncryptionKey = f.keys.EncryptionKey()
	}
	return options
}

func (f *fixture) readOptions(encrypt bool) ReadOptions {
	options := ReadOptions{Signer: f.keys}
	if encrypt {
		options.EncryptionKey = f.keys.EncryptionKey()
	}
	return options
}

// writeSegment writes records as one sealed and published segment.
func (f *fixture) writeSegment(options Options, spec Spec, records ...*archive.Record) *Sealed {
	f.t.Helper()
	writer, err := NewSegment(options, spec, f.payloads)
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
	return sealed
}

func (f *fixture) verify(path string, encrypt bool) (*Bundle, *Report) {
	f.t.Helper()
	bundle, err := Open(path, f.readOptions(encrypt))
	if err != nil {
		f.t.Fatalf("open: %v (%v)", err, errors.Unwrap(err))
	}
	report, err := bundle.Verify(context.Background())
	if err != nil {
		f.t.Fatalf("verify: %v (%v)", err, errors.Unwrap(err))
	}
	return bundle, report
}

func wantReason(t *testing.T, err error, reason string) {
	t.Helper()
	if got := ReasonOf(err); got != reason {
		t.Fatalf("reason = %q (%v, cause %v), want %q", got, err, errors.Unwrap(err), reason)
	}
	if err != nil && strings.Contains(err.Error(), string(filepath.Separator)) {
		t.Fatalf("error message %q carries a path", err.Error())
	}
}

// listFiles returns every regular file under root, relative, sorted.
func listFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			relative, _ := filepath.Rel(root, path)
			out = append(out, filepath.ToSlash(relative))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func countSuffix(files []string, suffix string) int {
	count := 0
	for _, file := range files {
		if strings.HasSuffix(file, suffix) {
			count++
		}
	}
	return count
}

func describe(files []string) string { return fmt.Sprintf("%q", files) }
