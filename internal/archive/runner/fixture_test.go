package runner

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/headerblock"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// Synthetic records for the host tests, built like the bundle package's
// test fixture: real content objects, projected credentials, fake events
// (the runner tests do not check event MACs).

const baseTimeNS = int64(1764300000000000000) // 2025-11-28 UTC

func testKeys(t *testing.T) *security.ArchiveKeys {
	t.Helper()
	keys, err := security.DeriveArchiveKeys(bytes.Repeat([]byte{0x42}, security.KeySize))
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

// payloads is a bundle.Payloads over maps.
type payloads struct {
	contents map[string]archive.ContentObject
	binaries map[string]archive.BinaryObject
	chunks   map[chunkID][]byte
}

func newPayloads() *payloads {
	return &payloads{contents: map[string]archive.ContentObject{}, binaries: map[string]archive.BinaryObject{}, chunks: map[chunkID][]byte{}}
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

type fixture struct {
	t        *testing.T
	keys     *security.ArchiveKeys
	payloads *payloads
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

// audit is a turnless version 2 record with a credential header.
func (f *fixture) audit(id, protocol string, startedNS int64) *archive.Record {
	keys := f.keys
	record := &archive.Record{
		Revision: 1,
		Audit: archive.AuditRow{
			AuditID: id, SchemaGeneration: 2, StartedAtNS: startedNS, EndedAtNS: startedNS + int64(time.Second),
			RouteID: "route-example", Protocol: protocol, ParserName: protocol + ".chat", Method: "POST", Path: "/v1/chat/completions",
			RequestURI: archive.ProjectRequestURI(keys, []byte("/v1/chat/completions?key=sk-example-"+id)), Mode: "strict", StatusCode: integer(200),
			ForwardStatus: storage.ForwardCompleted, CaptureStatus: storage.CaptureComplete, ParseStatus: storage.ParseOK,
			CallerStatus: storage.CallerResolved, APIKeyFPR: hashOf(0x31), CaptureVersion: storage.CaptureVersion2,
		},
		Stages: []archive.Stage{{HTTPStage: storage.HTTPStage{Stage: storage.StageRequestReceived, State: storage.StageStateComplete,
			Proto: "HTTP/1.1", Method: "POST", Host: "api.example.com", StatusCode: small(200), StartedAtNS: startedNS + 1}}},
		Bodies: []storage.BodyStream{}, RawChunks: []archive.RawChunk{}, Timelines: []archive.Timeline{},
		IntegrityEvents: []archive.IntegrityEvent{{Sequence: 1, EventType: "capture_finalized", PreviousMAC: hashOf(0xa1),
			PayloadDigest: hashOf(0xa2), EventMAC: hashOf(0xa3), CreatedAtNS: startedNS + 2}},
	}
	values := []headerblock.Value{
		{Stage: storage.StageRequestReceived, Kind: storage.HeaderKindHeader, Name: "Authorization", Value: []byte("Bearer sk-example-" + id)},
		{Stage: storage.StageRequestReceived, Kind: storage.HeaderKindHeader, Name: "User-Agent", Value: []byte("client/1.0")},
	}
	record.Headers = archive.Headers{CaptureVersion: storage.CaptureVersion2, Values: archive.ProjectHeaders(keys, values),
		BlockPresent: true, BlockStages: []string{storage.StageRequestReceived}}
	record.Audit.UserAgent = archive.ProjectUserAgent(keys, []string{"client/1.0"})
	return record
}

// withTurn gives the record a turn: a root, or a child of parent (post_turn)
// whose request is the parent's request and response plus messages.
func (f *fixture) withTurn(record *archive.Record, conversationID string, parent *archive.Record, createdNS int64, messages ...string) *archive.Record {
	f.t.Helper()
	requestEnvelope := f.object("request_envelope", map[string]any{"model": "model-example"}, true)
	objects := []archive.ObjectMeta{requestEnvelope}
	var base []auditmodel.ObjectRef
	row := archive.TurnRow{
		TurnID: "turn-" + record.Audit.AuditID, ConversationID: conversationID, ParentBase: auditmodel.ParentBaseRoot, LinkReason: "root",
		LinkConfidence: 100, RequestLayout: auditmodel.LayoutOpenAIChatRequest, ResponseLayout: "none",
		RequestEnvelopeHash: requestEnvelope.Hash, RequestReconstructionHash: hashOf(0x53), ReconstructionStatus: "verified",
		CreatedAtNS: createdNS,
	}
	if parent != nil {
		row.ParentTurnID = text(parent.Turn.Row.TurnID)
		row.ParentBase = auditmodel.ParentBasePostTurn
		row.LinkReason = "conversation_key"
		row.LinkConfidence = 90
		base = append(append([]auditmodel.ObjectRef(nil), parent.Turn.RequestRefs...), parent.Turn.ResponseRefs()...)
		objects = append(objects, parent.Turn.Objects...)
	}
	refs := append([]auditmodel.ObjectRef(nil), base...)
	for _, message := range messages {
		meta := f.object("message", map[string]any{"role": "user", "content": message}, false)
		objects = append(objects, meta)
		refs = append(refs, auditmodel.ObjectRef{Slot: auditmodel.SlotMessages, ObjectHash: meta.Hash, SemanticHash: meta.SemanticHash})
	}
	turn := &archive.Turn{Row: row}
	responseEnvelope := f.object("response_envelope", map[string]any{"id": "response-" + record.Audit.AuditID}, true)
	choice := f.object("choice", map[string]any{"role": "assistant", "content": "answer " + record.Audit.AuditID}, false)
	objects = append(objects, responseEnvelope, choice)
	turn.Row.ResponseLayout = auditmodel.LayoutMarkerEnvelope
	turn.Row.ResponseEnvelopeHash = responseEnvelope.Hash
	turn.Row.ResponseReconstructionHash = hashOf(0x54)
	turn.ResponseItems = []archive.ResponseItem{{Ordinal: 0, Slot: auditmodel.SlotChoice, ObjectHash: choice.Hash, SemanticHash: choice.SemanticHash}}
	turn.Row.ResponseItemCount = 1
	turn.Row.ResponseSequenceHash = auditmodel.SequenceHash(turn.ResponseRefs())
	turn.Row.ResponseID = text("response-" + record.Audit.AuditID)
	turn.Row.RequestItemCount = int64(len(refs))
	turn.Row.RequestSequenceHash = auditmodel.SequenceHash(refs)
	turn.RequestRefs = refs
	turn.Context = archive.RequestContext{Form: archive.ContextDelta, Ops: archive.ContextOpsFrom(auditmodel.BuildDelta(base, refs))}
	used := map[string]bool{string(row.RequestEnvelopeHash): true, string(turn.Row.ResponseEnvelopeHash): true}
	for _, ref := range append(append([]auditmodel.ObjectRef(nil), refs...), turn.ResponseRefs()...) {
		used[string(ref.ObjectHash)] = true
	}
	seen := map[string]bool{}
	for _, object := range objects {
		if used[string(object.Hash)] && !seen[string(object.Hash)] {
			seen[string(object.Hash)] = true
			turn.Objects = append(turn.Objects, object)
		}
	}
	record.Turn = turn
	record.Conversation = &archive.Conversation{ConversationID: conversationID, Protocol: record.Audit.Protocol, KeyHash: hashOf(0x81), CreatedAtNS: baseTimeNS}
	record.IntegrityEvents = append(record.IntegrityEvents, archive.IntegrityEvent{Sequence: 2, EventType: "semantic_compacted",
		PreviousMAC: hashOf(0xa4), PayloadDigest: hashOf(0xa5), EventMAC: hashOf(0xa6), CreatedAtNS: createdNS + 1})
	return record
}

// withRaw gives the record a complete full body at stage.
func (f *fixture) withRaw(record *archive.Record, stage string, data []byte, chunkSize int) *archive.Record {
	sum := sha256.Sum256(data)
	body := storage.BodyStream{Stage: stage, SourceStage: stage, ObservedLength: int64(len(data)), StoredLength: int64(len(data)),
		HashComplete: true, EOFSeen: true, State: storage.StageStateComplete, RetentionState: storage.RetentionFull, SHA256: sum[:]}
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
