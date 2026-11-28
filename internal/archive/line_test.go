package archive

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/headerblock"
	"llmapi-logger/internal/storage"
)

// roundTrip encodes, decodes, materialises a delta turn from parent, and
// requires the same record and the same digest.
func roundTrip(t *testing.T, name string, record *Record, parentRequest, parentResponse []auditmodel.ObjectRef) *Record {
	t.Helper()
	if err := record.Canonicalize(); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	want, err := Digest(record)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	line, digest, parts, err := EncodeLine(record)
	if err != nil || digest != want {
		t.Fatalf("%s: encode: %v", name, err)
	}
	if bytes.ContainsAny(line, "\n\r") {
		t.Fatalf("%s: line contains a newline", name)
	}
	decoded, stored, err := DecodeLine(line)
	if err != nil {
		t.Fatalf("%s: decode: %v\n%s", name, err, line)
	}
	if stored != want {
		t.Fatalf("%s: record_digest differs", name)
	}
	if decoded.Turn != nil && decoded.Turn.Context.Form == ContextDelta {
		if err := decoded.Turn.Materialize(parentRequest, parentResponse); err != nil {
			t.Fatalf("%s: materialize: %v", name, err)
		}
	}
	if len(parts) > 0 {
		joined, err := JoinParsedJSON(*decoded.ParsedResult.ParsedJSONRef, parts)
		if err != nil || !bytes.Equal(joined, record.ParsedResult.ParsedJSON) {
			t.Fatalf("%s: parts do not join: %v", name, err)
		}
	}
	got, err := Digest(decoded)
	if err != nil || got != want {
		t.Fatalf("%s: digest(decode(encode(r))) != digest(r): %v", name, err)
	}
	if len(parts) == 0 {
		expected := *record
		expected.Turn = cloneTurnForCompare(record.Turn)
		if !reflect.DeepEqual(normalizeForCompare(decoded), normalizeForCompare(&expected)) {
			t.Fatalf("%s: decoded record differs\n got  %+v\n want %+v", name, decoded, record)
		}
	}
	again, _, _, err := EncodeLine(decoded)
	if err != nil || (len(parts) == 0 && !bytes.Equal(again, line)) {
		t.Fatalf("%s: re-encoding differs: %v", name, err)
	}
	return decoded
}

func cloneTurnForCompare(turn *Turn) *Turn {
	if turn == nil {
		return nil
	}
	copied := *turn
	return &copied
}

// normalizeForCompare fills the audit ids the decoder sets and turns empty
// lists into nil, so DeepEqual compares content.
func normalizeForCompare(record *Record) *Record {
	copied := *record
	copied.Stages = nil
	for _, stage := range record.Stages {
		stage.AuditID = record.Audit.AuditID
		copied.Stages = append(copied.Stages, stage)
	}
	copied.Bodies = nil
	for _, body := range record.Bodies {
		body.AuditID = record.Audit.AuditID
		copied.Bodies = append(copied.Bodies, body)
	}
	if len(copied.RawChunks) == 0 {
		copied.RawChunks = nil
	}
	if len(copied.Timelines) == 0 {
		copied.Timelines = nil
	}
	if len(copied.IntegrityEvents) == 0 {
		copied.IntegrityEvents = nil
	}
	if len(copied.Headers.Values) == 0 {
		copied.Headers.Values = nil
	}
	if len(copied.Audit.RequestURI.Segments) == 0 {
		copied.Audit.RequestURI.Segments = nil
	}
	if turn := record.Turn; turn != nil {
		t := *turn
		for _, list := range []*[]ResponseItem{&t.ResponseItems} {
			if len(*list) == 0 {
				*list = nil
			}
		}
		if len(t.Objects) == 0 {
			t.Objects = nil
		}
		if len(t.BinaryRefs) == 0 {
			t.BinaryRefs = nil
		}
		if len(t.ExternalRefs) == 0 {
			t.ExternalRefs = nil
		}
		if len(t.Binaries) == 0 {
			t.Binaries = nil
		}
		if len(t.Context.Ops) == 0 {
			t.Context.Ops = nil
		}
		if len(t.RequestRefs) == 0 {
			t.RequestRefs = nil
		}
		copied.Turn = &t
	}
	return &copied
}

func TestLineRoundTripShapes(t *testing.T) {
	keys := newTestKeys()

	roundTrip(t, "full, version 2, materialized turn", fullRecord(t), nil, nil)
	roundTrip(t, "minimal, version 1, no turn", minimalRecord(), nil, nil)

	v1 := fullRecord(t)
	v1.Audit.CaptureVersion, v1.Audit.UserAgent = storage.CaptureVersion1, nil
	v1.Headers.CaptureVersion, v1.Headers.BlockPresent, v1.Headers.BlockStages = storage.CaptureVersion1, false, nil
	for index := range v1.Stages {
		v1.Stages[index].ContentType, v1.Stages[index].ContentEncoding = nil, nil
	}
	roundTrip(t, "version 1 with a turn", v1, nil, nil)

	// A delta chain: root, a request-base child and a post_turn child.
	ref := func(seed byte) auditmodel.ObjectRef {
		return auditmodel.ObjectRef{Slot: auditmodel.SlotMessages, ObjectHash: hashOf(seed), SemanticHash: hashOf(seed + 0x40)}
	}
	rootRefs := []auditmodel.ObjectRef{ref(1), ref(2)}
	rootResponse := []auditmodel.ObjectRef{{Slot: auditmodel.SlotChoice, ObjectHash: hashOf(3), SemanticHash: hashOf(0x43)}}
	chain := func(id string, parent *string, parentBase string, refs, base []auditmodel.ObjectRef) *Record {
		record := fullRecord(t)
		record.Audit.AuditID = id
		row := &record.Turn.Row
		row.TurnID, row.ParentTurnID, row.ParentBase = id, parent, parentBase
		row.RequestItemCount, row.RequestSequenceHash = int64(len(refs)), auditmodel.SequenceHash(refs)
		record.Turn.Context = RequestContext{Form: ContextDelta, Ops: ContextOpsFrom(auditmodel.BuildDelta(base, refs))}
		record.Turn.RequestRefs = cloneRefs(refs)
		return record
	}
	root := roundTrip(t, "delta root", chain("audit-root", nil, auditmodel.ParentBaseRoot, rootRefs, nil), nil, nil)
	childRefs := append(cloneRefs(rootRefs), ref(4))
	roundTrip(t, "delta child, request base", chain("audit-child", text("audit-root"), auditmodel.ParentBaseRequest, childRefs, rootRefs), root.Turn.RequestRefs, rootResponse)
	postBase := append(cloneRefs(rootRefs), rootResponse...)
	postRefs := append(cloneRefs(postBase[:1]), ref(5))
	roundTrip(t, "delta child, post_turn base", chain("audit-post", text("audit-root"), auditmodel.ParentBasePostTurn, postRefs, postBase), root.Turn.RequestRefs, rootResponse)
	emptyRoot := chain("audit-empty", nil, auditmodel.ParentBaseRoot, nil, nil)
	emptyRoot.Turn.Context.Ops = []ContextOp{}
	roundTrip(t, "delta root without request items", emptyRoot, nil, nil)

	// A request-only turn: response layout none, the half answer in
	// parsed_json's partial_response_messages.
	requestOnly := fullRecord(t)
	requestOnly.Turn.Row.ResponseLayout, requestOnly.Turn.Row.ResponseItemCount = auditmodel.LayoutNone, 0
	requestOnly.Turn.Row.ResponseSequenceHash = auditmodel.SequenceHash(nil)
	requestOnly.Turn.ResponseItems = []ResponseItem{}
	requestOnly.ParsedResult.Status = storage.ParsePartial
	requestOnly.ParsedResult.ParsedJSON = []byte(`{"protocol":"openai","partial_response_messages":[{"role":"assistant","content":[{"type":"text","text":"half"}]}]}`)
	roundTrip(t, "request-only turn", requestOnly, nil, nil)

	// A failed capture: the block has a section for a stage without a row,
	// a stage row without a section; partial body, no hash, chunk missing.
	failed := minimalRecord()
	failed.Audit.CaptureVersion, failed.Headers.CaptureVersion = storage.CaptureVersion2, storage.CaptureVersion2
	failed.Audit.CaptureStatus, failed.Audit.ForwardStatus, failed.Audit.ParseStatus = storage.CaptureFailed, storage.ForwardProxyError, storage.ParseError
	failed.Stages = []Stage{{HTTPStage: storage.HTTPStage{Stage: storage.StageRequestReceived, State: storage.StageStatePartial, StartedAtNS: 101}}}
	failed.Headers.BlockPresent, failed.Headers.BlockStages = true, []string{storage.StageRequestSent}
	failed.Headers.Values = ProjectHeaders(keys, []headerblock.Value{{Stage: storage.StageRequestSent, Kind: storage.HeaderKindHeader, Name: "X-Api-Key", Value: []byte("k")}})
	failed.Bodies = []storage.BodyStream{{Stage: storage.StageRequestReceived, SourceStage: storage.StageRequestReceived, ObservedLength: 3 << 20,
		StoredLength: 2 << 20, State: storage.StageStatePartial, RetentionState: storage.RetentionFull, ChunkCount: 2,
		ErrorCode: text(storage.CaptureChunkMissing), StreamTimelineComplete: true}}
	failed.RawChunks = []RawChunk{
		{Stage: storage.StageRequestReceived, Seq: 0, Offset: 0, PlaintextLength: 1 << 20, ObservedAtNS: 102, SHA256: sumOf(1)},
		{Stage: storage.StageRequestReceived, Seq: 2, Offset: 2 << 20, PlaintextLength: 1 << 20, ObservedAtNS: 104, SHA256: sumOf(2)},
	}
	failed.IntegrityEvents = []IntegrityEvent{{Sequence: 1, EventType: "capture_finalized", PayloadDigest: hashOf(1), EventMAC: hashOf(2), CreatedAtNS: 5}}
	roundTrip(t, "failed capture with a partial body", failed, nil, nil)

	interrupted := minimalRecord()
	interrupted.Audit.ForwardStatus, interrupted.Audit.CaptureStatus = storage.ForwardInterrupted, storage.CapturePartial
	interrupted.Audit.CaptureVersion, interrupted.Headers.CaptureVersion = storage.CaptureVersion2, storage.CaptureVersion2
	interrupted.Stages = []Stage{{HTTPStage: storage.HTTPStage{Stage: storage.StageRequestReceived, State: storage.StageStateStreaming, StartedAtNS: 101}}}
	roundTrip(t, "interrupted capture without a block", interrupted, nil, nil)

	// Text that is not UTF-8 and NULL next to empty values.
	odd := fullRecord(t)
	odd.Audit.Path = "/v1/\xff\xfe"
	odd.Audit.RequestURI = ProjectRequestURI(keys, []byte("/v1/\xff?x=\xc3&&key=\xff"))
	odd.Headers.Values[1].Value.Value = "client/\x80"
	odd.Audit.BlockedBy, odd.Audit.ErrorCode = text(""), nil
	odd.Audit.APIKeyFPR = []byte{}
	odd.Timelines[0].Plaintext = []byte{}
	odd.ParsedResult.ParsedJSON = []byte{}
	odd.Conversation.KeyHash = nil
	odd.ProjectIdentity.Identity = []byte("\xff")
	odd.Turn.ExternalRefs[0].Value = "\xfe"
	decoded := roundTrip(t, "non-UTF-8 text and NULL next to empty", odd, nil, nil)
	if decoded.Audit.BlockedBy == nil || decoded.Audit.ErrorCode != nil || decoded.Audit.APIKeyFPR == nil || decoded.Conversation.KeyHash != nil ||
		decoded.Timelines[0].Plaintext == nil || decoded.ParsedResult.ParsedJSON == nil {
		t.Fatal("NULL and empty collapsed")
	}
	line, _, _, _ := EncodeLine(odd)
	if !bytes.Contains(line, []byte(`"path":{"b64":"L3YxL//+"}`)) {
		t.Fatalf("non-UTF-8 path not written as b64: %s", line)
	}
}

// parsed_json over 1 MiB moves to the objects file in parts cut at UTF-8
// boundaries; exactly 1 MiB stays in the line.
func TestParsedJSONSplit(t *testing.T) {
	record := fullRecord(t)
	record.ParsedResult.ParsedJSON = []byte(`"` + strings.Repeat("a", ParsedJSONInlineLimit-2) + `"`)
	if _, _, parts, err := EncodeLine(record); err != nil || len(parts) != 0 {
		t.Fatalf("1 MiB split: %v %d", err, len(parts))
	}
	large := []byte(`{"text":"` + strings.Repeat("a", ParsedJSONInlineLimit-11) + strings.Repeat("你", 400000) + `"}`)
	record.ParsedResult.ParsedJSON = large
	line, _, parts, err := EncodeLine(record)
	if err != nil || len(parts) != 3 {
		t.Fatalf("split: %v %d", err, len(parts))
	}
	for index, part := range parts {
		if len(part.Data) > ParsedJSONInlineLimit {
			t.Fatalf("part %d too large", index)
		}
		if !utf8Valid(part.Data) {
			t.Fatalf("part %d cut inside a UTF-8 sequence", index)
		}
		encoded := EncodeParsedJSONPart(part)
		entry, err := DecodeObjectEntry(encoded)
		if err != nil || entry.ParsedJSONPart == nil || !bytes.Equal(entry.ParsedJSONPart.Data, part.Data) || entry.ParsedJSONPart.Part != int64(index) {
			t.Fatalf("part %d round trip: %v", index, err)
		}
	}
	if len(line) > 64<<10 {
		t.Fatalf("line still carries the parsed_json: %d bytes", len(line))
	}
	decoded := roundTrip(t, "split parsed_json", record, nil, nil)
	if decoded.ParsedResult.ParsedJSON != nil || decoded.ParsedResult.ParsedJSONRef == nil || decoded.ParsedResult.ParsedJSONRef.Parts != 3 {
		t.Fatalf("decoded = %+v", decoded.ParsedResult)
	}
	if _, err := JoinParsedJSON(*decoded.ParsedResult.ParsedJSONRef, parts[:2]); err == nil {
		t.Fatal("missing part accepted")
	}
	parts[1].Data = append([]byte(nil), parts[1].Data...)
	parts[1].Data[0] ^= 1
	if _, err := JoinParsedJSON(*decoded.ParsedResult.ParsedJSONRef, parts); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("tampered part err=%v", err)
	}
	if _, err := decoded.PlainDetail(fixedObjects{}, large[:10]); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("PlainDetail with wrong parsed_json err=%v", err)
	}
	// Invalid UTF-8 never moves a cut.
	_, raw := SplitParsedJSON("a", bytes.Repeat([]byte{0xff}, ParsedJSONInlineLimit+1))
	if len(raw) != 2 || len(raw[0].Data) != ParsedJSONInlineLimit {
		t.Fatalf("invalid UTF-8 split = %d parts", len(raw))
	}
}

func utf8Valid(data []byte) bool { return strings.ToValidUTF8(string(data), "\uFFFD") == string(data) }

// The decoder accepts exactly the documented shape.
func TestDecodeLineRejects(t *testing.T) {
	line, _, _, err := EncodeLine(fullRecord(t))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(string) string{
		"unknown top-level key": func(s string) string { return strings.Replace(s, `{"type":"audit",`, `{"type":"audit","extra":1,`, 1) },
		"missing key":           func(s string) string { return strings.Replace(s, `"revision":"1",`, ``, 1) },
		"duplicate key": func(s string) string {
			return strings.Replace(s, `"revision":"1",`, `"revision":"1","revision":"1",`, 1)
		},
		"unknown nested key": func(s string) string {
			return strings.Replace(s, `"chunk_count":"1",`, `"chunk_count":"1","x":null,`, 1)
		},
		"omitted null":      func(s string) string { return strings.Replace(s, `"content_encoding":"br"`, `"x":"br"`, 1) },
		"leading zero":      func(s string) string { return strings.Replace(s, `"revision":"1"`, `"revision":"01"`, 1) },
		"number not string": func(s string) string { return strings.Replace(s, `"revision":"1"`, `"revision":1`, 1) },
		"flag out of range": func(s string) string { return strings.Replace(s, `"hash_complete":"1"`, `"hash_complete":"2"`, 1) },
		"uppercase hex":     func(s string) string { return strings.Replace(s, `"api_key_fpr":"3131`, `"api_key_fpr":"3A31`, 1) },
		"b64 for UTF-8": func(s string) string {
			return strings.Replace(s, `"route_id":"route-example"`, `"route_id":{"b64":"cm91dGU="}`, 1)
		},
		"unpadded base64": func(s string) string {
			return strings.Replace(s, `"timeline_b64":"AQIDBA=="`, `"timeline_b64":"AQIDBA"`, 1)
		},
		"head mismatch": func(s string) string {
			return strings.Replace(s, `"protocol":"openai","started_at_ns"`, `"protocol":"gemini","started_at_ns"`, 1)
		},
		"conversation mismatch": func(s string) string {
			return strings.Replace(s, `"conversation_id":"conv_full","protocol"`, `"conversation_id":null,"protocol"`, 1)
		},
		"null ended_at_ns": func(s string) string {
			return strings.Replace(s, `"ended_at_ns":"1764300001123456789","revision"`, `"ended_at_ns":null,"revision"`, 1)
		},
		"mixed value shape": func(s string) string {
			return strings.Replace(s, `{"value":"client/1.0"}`, `{"value":"client/1.0","length":"3"}`, 1)
		},
		"empty user_agent": func(s string) string { return replaceUserAgent(s, `[]`) },
		"wrong type":       func(s string) string { return strings.Replace(s, `{"type":"audit"`, `{"type":"gap"`, 1) },
		"trailing data":    func(s string) string { return s + `{}` },
		"wrong form":       func(s string) string { return strings.Replace(s, `"form":"materialized"`, `"form":"delta"`, 1) },
		"bad omission reason": func(s string) string {
			return strings.Replace(s, `"value_omitted":"credential"`, `"value_omitted":"other"`, 1)
		},
	}
	for name, mutate := range cases {
		mutated := mutate(string(line))
		if mutated == string(line) {
			t.Errorf("%s: mutation did not apply", name)
			continue
		}
		if _, _, err := DecodeLine([]byte(mutated)); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: err=%v", name, err)
		}
	}
	if _, _, err := DecodeLine(append([]byte(nil), 0xff)); !errors.Is(err, ErrFormat) {
		t.Fatalf("invalid UTF-8 line err=%v", err)
	}
	// Key order does not matter.
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(line, &generic); err != nil {
		t.Fatal(err)
	}
	reordered, err := json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := DecodeLine(reordered); err != nil {
		t.Fatalf("reordered keys: %v", err)
	}
}

func replaceUserAgent(line, replacement string) string {
	start := strings.Index(line, `"user_agent":[`)
	end := strings.Index(line[start:], `]},"http_stages"`)
	return line[:start] + `"user_agent":` + replacement + line[start+end+1:]
}

func TestObjectEntriesAndGaps(t *testing.T) {
	content := ContentObject{Hash: hashOf(1), SemanticHash: hashOf(2), Kind: "message", PlaintextLength: 13, CreatedAtNS: 9, Data: []byte(`{"a":"\u003c"}`)}
	binary := BinaryObject{Hash: hashOf(3), MediaType: "image/png", PlaintextLength: 3, CreatedAtNS: 10, Data: []byte{0, 0xff, 1}}
	chunk := RawChunkData{AuditID: "a", Stage: storage.StageResponseReceived, Seq: 4, Data: []byte("raw\x00bytes")}
	part := ParsedJSONPart{AuditID: "a", Part: 1, Data: []byte("\xff")}
	for name, pair := range map[string]struct {
		encoded []byte
		want    ObjectEntry
	}{
		"content":   {EncodeContentObject(content), ObjectEntry{Content: &content}},
		"binary":    {EncodeBinaryObject(binary), ObjectEntry{Binary: &binary}},
		"raw chunk": {EncodeRawChunk(chunk), ObjectEntry{RawChunk: &chunk}},
		"json part": {EncodeParsedJSONPart(part), ObjectEntry{ParsedJSONPart: &part}},
	} {
		got, err := DecodeObjectEntry(pair.encoded)
		if err != nil || !reflect.DeepEqual(got, pair.want) {
			t.Errorf("%s: %+v %v", name, got, err)
		}
	}
	if !bytes.Contains(EncodeContentObject(content), []byte(`"data":"{\"a\":\"\\u003c\"}"`)) {
		t.Fatalf("content object data not kept as a JSON string: %s", EncodeContentObject(content))
	}
	if _, err := DecodeObjectEntry([]byte(`{"type":"other"}`)); !errors.Is(err, ErrFormat) {
		t.Fatalf("unknown entry err=%v", err)
	}
	if _, err := DecodeObjectEntry([]byte(`{"type":"raw_chunk","audit_id":"a","stage":"s","seq":"1","data_b64":"","x":1}`)); !errors.Is(err, ErrFormat) {
		t.Fatalf("unknown key err=%v", err)
	}
	gap := Gap{ID: 12, StartedAtNS: 1, EndedAtNS: 2, Reason: storage.GapReasonQueueFull, RequestCount: 3, Detail: storage.GapDetailQueueFull, CreatedAtNS: 4}
	encoded := EncodeGap(gap)
	if string(encoded) != `{"type":"gap","id":"12","started_at_ns":"1","ended_at_ns":"2","reason":"queue_full","request_count":"3","detail":"audit_writer_queue_full","created_at_ns":"4"}` {
		t.Fatalf("gap = %s", encoded)
	}
	if decoded, err := DecodeGap(encoded); err != nil || decoded != gap {
		t.Fatalf("gap round trip %+v %v", decoded, err)
	}
	if _, err := DecodeGap([]byte(strings.Replace(string(encoded), `"gap"`, `"audit"`, 1))); !errors.Is(err, ErrFormat) {
		t.Fatalf("gap type err=%v", err)
	}
}
