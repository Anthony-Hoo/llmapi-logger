package storage

import (
	"errors"
	"reflect"
	"testing"
)

const testAuditID = "aud_validation"

func ptr[T any](value T) *T { return &value }

func testStage(name string) HTTPStage {
	return HTTPStage{AuditID: testAuditID, Stage: name, State: StageStateStreaming, Proto: "HTTP/1.1", Method: "POST", Host: "example.com", StartedAtNS: 10}
}

func testHeader(stage, kind, name string, index int) HTTPHeader {
	return HTTPHeader{AuditID: testAuditID, Stage: stage, Kind: kind, Name: name, ValueIndex: index, ValueLength: 3, ValueEnc: []byte("ciphertext")}
}

func testBlock() *HeaderBlock {
	return &HeaderBlock{Compression: ChunkCompressionGZIP, PlaintextLength: 400, DataEnc: []byte("ciphertext")}
}

func testBody(stage, source string) BodyStream {
	body := BodyStream{AuditID: testAuditID, Stage: stage, SourceStage: source}
	body.Defaults()
	return body
}

func validCheckpointV1() AuditCheckpoint {
	return AuditCheckpoint{
		AuditID:        testAuditID,
		CaptureVersion: CaptureVersion1,
		Stages:         []HTTPStage{testStage(StageRequestReceived), testStage(StageRequestSent)},
		Headers: []HTTPHeader{
			testHeader(StageRequestReceived, HeaderKindHeader, "Content-Type", 0),
			testHeader(StageRequestSent, HeaderKindTrailer, "X-Trailer", 0),
		},
		Bodies: []BodyStream{testBody(StageRequestReceived, StageRequestReceived), testBody(StageRequestSent, StageRequestReceived)},
		Chunks: ChunkList{{AuditID: testAuditID, Stage: StageRequestReceived, ObservedAtNS: 11, DataEnc: []byte("x")}},
	}
}

func validCheckpointV2() AuditCheckpoint {
	checkpoint := validCheckpointV1()
	checkpoint.CaptureVersion = CaptureVersion2
	checkpoint.Headers = nil
	checkpoint.HeaderBlock = testBlock()
	checkpoint.Contents = []StageContent{{Stage: StageRequestReceived, ContentType: ptr("application/json")}}
	return checkpoint
}

func validFinish() AuditFinish {
	return AuditFinish{AuditID: testAuditID, EndedAtNS: 99, StatusCode: ptr(200), ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParsePending}
}

func finalStage(name string) HTTPStage {
	stage := testStage(name)
	stage.State = StageStateComplete
	stage.EndedAtNS = ptr(int64(50))
	return stage
}

func finalBody(stage, source string) *BodyStream {
	body := testBody(stage, source)
	body.State = StageStateComplete
	body.ObservedLength, body.StoredLength = 5, 5
	body.SHA256 = make([]byte, 32)
	body.HashComplete, body.EOFSeen = true, true
	body.FirstObservedAtNS, body.LastObservedAtNS = ptr(int64(20)), ptr(int64(30))
	body.ChunkCount = 1
	return &body
}

func validCommitV1() AuditCommit {
	return AuditCommit{
		Finish:         validFinish(),
		CaptureVersion: CaptureVersion1,
		Stages: []StageCommit{
			{Stage: finalStage(StageRequestReceived), StageWritten: true, Body: finalBody(StageRequestReceived, StageRequestReceived), BodyWritten: true},
			{Stage: finalStage(StageRequestSent), StageWritten: true, Body: finalBody(StageRequestSent, StageRequestReceived), BodyWritten: true},
			{Stage: finalStage(StageResponseReceived), Body: finalBody(StageResponseReceived, StageResponseReceived)},
			{Stage: finalStage(StageResponseSent), Body: finalBody(StageResponseSent, StageResponseReceived)},
		},
		Headers: []HTTPHeader{testHeader(StageResponseSent, HeaderKindTrailer, "X-Trailer", 0)},
	}
}

func validCommitV2() AuditCommit {
	commit := validCommitV1()
	commit.CaptureVersion = CaptureVersion2
	commit.Headers = nil
	commit.HeaderBlock = testBlock()
	commit.Stages[2].ContentType = ptr("text/event-stream")
	return commit
}

func TestCheckpointValidationAcceptsBothVersions(t *testing.T) {
	for name, checkpoint := range map[string]AuditCheckpoint{
		"v1":         validCheckpointV1(),
		"v2":         validCheckpointV2(),
		"zero is v1": func() AuditCheckpoint { c := validCheckpointV1(); c.CaptureVersion = 0; return c }(),
		"empty":      {AuditID: testAuditID},
		"v2 trailers only": func() AuditCheckpoint {
			return AuditCheckpoint{AuditID: testAuditID, CaptureVersion: CaptureVersion2, HeaderBlock: testBlock()}
		}(),
	} {
		if err := ValidateAuditCheckpoint(checkpoint); err != nil {
			t.Errorf("%s: unexpected error %v", name, err)
		}
	}
}

func TestCheckpointValidationRejections(t *testing.T) {
	cases := map[string]func(*AuditCheckpoint){
		"no audit id":               func(c *AuditCheckpoint) { c.AuditID = "" },
		"unknown version":           func(c *AuditCheckpoint) { c.CaptureVersion = 3 },
		"stage of other audit":      func(c *AuditCheckpoint) { c.Stages[0].AuditID = "other" },
		"stage not streaming":       func(c *AuditCheckpoint) { c.Stages[0].State = StageStateComplete },
		"stage with end":            func(c *AuditCheckpoint) { c.Stages[0].EndedAtNS = ptr(int64(5)) },
		"unknown stage":             func(c *AuditCheckpoint) { c.Stages[0].Stage = "elsewhere" },
		"repeated stage":            func(c *AuditCheckpoint) { c.Stages[1] = c.Stages[0] },
		"bad status":                func(c *AuditCheckpoint) { c.Stages[0].StatusCode = ptr(42) },
		"v1 block":                  func(c *AuditCheckpoint) { c.HeaderBlock = testBlock() },
		"v1 contents":               func(c *AuditCheckpoint) { c.Contents = []StageContent{{Stage: StageRequestReceived}} },
		"header of other audit":     func(c *AuditCheckpoint) { c.Headers[0].AuditID = "other" },
		"header without name":       func(c *AuditCheckpoint) { c.Headers[0].Name = "" },
		"header bad kind":           func(c *AuditCheckpoint) { c.Headers[0].Kind = "footer" },
		"header without value":      func(c *AuditCheckpoint) { c.Headers[0].ValueEnc = nil },
		"body of other audit":       func(c *AuditCheckpoint) { c.Bodies[0].AuditID = "other" },
		"body finished":             func(c *AuditCheckpoint) { c.Bodies[0].State = StageStateComplete },
		"body foreign source":       func(c *AuditCheckpoint) { c.Bodies[1].SourceStage = StageResponseReceived },
		"body source reversed":      func(c *AuditCheckpoint) { c.Bodies[0].SourceStage = StageRequestSent },
		"body repeated":             func(c *AuditCheckpoint) { c.Bodies[1] = c.Bodies[0] },
		"body stored over observed": func(c *AuditCheckpoint) { c.Bodies[0].StoredLength = 1 },
	}
	for name, mutate := range cases {
		checkpoint := validCheckpointV1()
		mutate(&checkpoint)
		if err := ValidateAuditCheckpoint(checkpoint); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	v2Cases := map[string]func(*AuditCheckpoint){
		"v2 rows": func(c *AuditCheckpoint) {
			c.Headers = []HTTPHeader{testHeader(StageRequestReceived, HeaderKindHeader, "A", 0)}
		},
		"v2 stages without block": func(c *AuditCheckpoint) { c.HeaderBlock = nil },
		"v2 block compression":    func(c *AuditCheckpoint) { c.HeaderBlock.Compression = "zstd" },
		"v2 block too long":       func(c *AuditCheckpoint) { c.HeaderBlock.PlaintextLength = HeaderBlockMaxPlaintextLength + 1 },
		"v2 block negative":       func(c *AuditCheckpoint) { c.HeaderBlock.PlaintextLength = -1 },
		"v2 block empty":          func(c *AuditCheckpoint) { c.HeaderBlock.DataEnc = nil },
		"v2 empty content type":   func(c *AuditCheckpoint) { c.Contents[0].ContentType = ptr("") },
		"v2 content of old stage": func(c *AuditCheckpoint) { c.Contents[0].Stage = StageResponseSent },
		"v2 content repeated":     func(c *AuditCheckpoint) { c.Contents = append(c.Contents, c.Contents[0]) },
	}
	for name, mutate := range v2Cases {
		checkpoint := validCheckpointV2()
		mutate(&checkpoint)
		if err := ValidateAuditCheckpoint(checkpoint); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCommitValidation(t *testing.T) {
	for name, commit := range map[string]AuditCommit{"v1": validCommitV1(), "v2": validCommitV2()} {
		if err := ValidateAuditCommit(commit); err != nil {
			t.Errorf("%s: unexpected error %v", name, err)
		}
	}
	unchanged := validCommitV2()
	for index := range unchanged.Stages {
		unchanged.Stages[index].StageWritten = true
	}
	unchanged.HeaderBlock = nil
	if err := ValidateAuditCommit(unchanged); err != nil {
		t.Errorf("v2 commit without new stages and unchanged block: %v", err)
	}

	cases := map[string]func(*AuditCommit){
		"finish without id":         func(c *AuditCommit) { c.Finish.AuditID = "" },
		"finish in progress":        func(c *AuditCommit) { c.Finish.ForwardStatus = ForwardInProgress },
		"finish rejected unblocked": func(c *AuditCommit) { c.Finish.ForwardStatus = ForwardRejected },
		"finish block fields":       func(c *AuditCommit) { c.Finish.BlockCode = ptr("blocked") },
		"unknown version":           func(c *AuditCommit) { c.CaptureVersion = -1 },
		"negative payload":          func(c *AuditCommit) { c.PayloadBytes = -1 },
		"stages out of order":       func(c *AuditCommit) { c.Stages[0], c.Stages[1] = c.Stages[1], c.Stages[0] },
		"stage repeated":            func(c *AuditCommit) { c.Stages[1] = c.Stages[0] },
		"stage of other audit":      func(c *AuditCommit) { c.Stages[0].Stage.AuditID = "other" },
		"stage streaming":           func(c *AuditCommit) { c.Stages[0].Stage.State = StageStateStreaming },
		"stage without end":         func(c *AuditCommit) { c.Stages[0].Stage.EndedAtNS = nil },
		"v1 content type":           func(c *AuditCommit) { c.Stages[0].ContentType = ptr("text/plain") },
		"body written without body": func(c *AuditCommit) { c.Stages[0].Body = nil },
		"body written, stage not":   func(c *AuditCommit) { c.Stages[0].StageWritten = false },
		"body of other stage":       func(c *AuditCommit) { c.Stages[0].Body.Stage = StageRequestSent },
		"body foreign source":       func(c *AuditCommit) { c.Stages[3].Body.SourceStage = StageRequestReceived },
		"body streaming":            func(c *AuditCommit) { c.Stages[2].Body.State = StageStateStreaming },
		"body hash without eof":     func(c *AuditCommit) { c.Stages[2].Body.EOFSeen = false },
		"timeline without body": func(c *AuditCommit) {
			c.Stages[2].Body = nil
			c.Stages[2].Timeline = &StreamTimeline{EventCount: 1}
		},
		"timeline count mismatch": func(c *AuditCommit) {
			c.Stages[2].Body.StreamEventCount = 2
			c.Stages[2].Timeline = &StreamTimeline{EventCount: 1, Compression: ChunkCompressionNone, PlaintextLength: 1, DataEnc: []byte("x")}
		},
		"v1 block":              func(c *AuditCommit) { c.HeaderBlock = testBlock() },
		"header of other audit": func(c *AuditCommit) { c.Headers[0].AuditID = "other" },
	}
	for name, mutate := range cases {
		commit := validCommitV1()
		mutate(&commit)
		if err := ValidateAuditCommit(commit); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	v2Cases := map[string]func(*AuditCommit){
		"v2 rows": func(c *AuditCommit) {
			c.Headers = []HTTPHeader{testHeader(StageResponseSent, HeaderKindTrailer, "A", 0)}
		},
		"v2 new stage, no block":    func(c *AuditCommit) { c.HeaderBlock = nil },
		"v2 empty content encoding": func(c *AuditCommit) { c.Stages[2].ContentEncoding = ptr("") },
	}
	for name, mutate := range v2Cases {
		commit := validCommitV2()
		mutate(&commit)
		if err := ValidateAuditCommit(commit); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAuditRecordCaptureValidation(t *testing.T) {
	inboundV1 := &InboundStage{
		Stage:   testStage(StageRequestReceived),
		Headers: []HTTPHeader{testHeader(StageRequestReceived, HeaderKindHeader, "User-Agent", 0)},
	}
	inboundV2 := &InboundStage{Stage: testStage(StageRequestReceived), HeaderBlock: testBlock(), ContentType: ptr("application/json")}
	valid := map[string]AuditRecord{
		"legacy":           {AuditID: testAuditID},
		"v1 inbound":       {AuditID: testAuditID, CaptureVersion: CaptureVersion1, Inbound: inboundV1},
		"v2 with ua":       {AuditID: testAuditID, CaptureVersion: CaptureVersion2, UserAgentEnc: []byte("ciphertext"), Inbound: inboundV2},
		"v2 without ua":    {AuditID: testAuditID, CaptureVersion: CaptureVersion2, Inbound: inboundV2},
		"v2 no inbound":    {AuditID: testAuditID, CaptureVersion: CaptureVersion2},
		"zero, no inbound": {AuditID: testAuditID, CaptureVersion: 0},
	}
	for name, record := range valid {
		if err := ValidateAuditRecordCapture(record); err != nil {
			t.Errorf("%s: unexpected error %v", name, err)
		}
	}
	invalid := map[string]AuditRecord{
		"unknown version":  {AuditID: testAuditID, CaptureVersion: 7},
		"v1 user agent":    {AuditID: testAuditID, UserAgentEnc: []byte("ciphertext")},
		"v1 inbound block": {AuditID: testAuditID, Inbound: &InboundStage{Stage: testStage(StageRequestReceived), HeaderBlock: testBlock()}},
		"v1 inbound content": {AuditID: testAuditID, Inbound: &InboundStage{
			Stage: testStage(StageRequestReceived), ContentType: ptr("text/plain")}},
		"v2 inbound rows": {AuditID: testAuditID, CaptureVersion: CaptureVersion2, Inbound: &InboundStage{
			Stage: testStage(StageRequestReceived), HeaderBlock: testBlock(), Headers: inboundV1.Headers}},
		"v2 inbound without block": {AuditID: testAuditID, CaptureVersion: CaptureVersion2, Inbound: &InboundStage{Stage: testStage(StageRequestReceived)}},
		"inbound wrong stage":      {AuditID: testAuditID, Inbound: &InboundStage{Stage: testStage(StageRequestSent)}},
		"inbound other audit":      {AuditID: "other", Inbound: &InboundStage{Stage: testStage(StageRequestReceived)}},
		"inbound trailer": {AuditID: testAuditID, Inbound: &InboundStage{Stage: testStage(StageRequestReceived),
			Headers: []HTTPHeader{testHeader(StageRequestReceived, HeaderKindTrailer, "X-T", 0)}}},
		"inbound header of other stage": {AuditID: testAuditID, Inbound: &InboundStage{Stage: testStage(StageRequestReceived),
			Headers: []HTTPHeader{testHeader(StageRequestSent, HeaderKindHeader, "X-T", 0)}}},
	}
	for name, record := range invalid {
		if err := ValidateAuditRecordCapture(record); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestOwnedChunkValidation(t *testing.T) {
	chunk := BodyChunk{AuditID: testAuditID, Stage: StageResponseReceived, Compression: ChunkCompressionNone, ObservedAtNS: 1, DataEnc: []byte("x")}
	if err := ValidateOwnedChunk(testAuditID, chunk); err != nil {
		t.Fatalf("valid chunk: %v", err)
	}
	for name, mutate := range map[string]func(*BodyChunk){
		"other audit":     func(c *BodyChunk) { c.AuditID = "other" },
		"unknown stage":   func(c *BodyChunk) { c.Stage = "x" },
		"negative seq":    func(c *BodyChunk) { c.Seq = -1 },
		"no time":         func(c *BodyChunk) { c.ObservedAtNS = 0 },
		"no data":         func(c *BodyChunk) { c.DataEnc = nil },
		"bad compression": func(c *BodyChunk) { c.Compression = "br" },
	} {
		copy := chunk
		mutate(&copy)
		if err := ValidateOwnedChunk(testAuditID, copy); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestChunkListEachVisitsInOrderAndStops(t *testing.T) {
	list := ChunkList{{Seq: 0}, {Seq: 1}, {Seq: 2}}
	var seen []int64
	for round := 0; round < 2; round++ {
		seen = seen[:0]
		if err := list.Each(func(chunk BodyChunk) error { seen = append(seen, chunk.Seq); return nil }); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(seen, []int64{0, 1, 2}) {
			t.Fatalf("round %d visited %v", round, seen)
		}
	}
	stop := errors.New("stop")
	count := 0
	if err := list.Each(func(BodyChunk) error { count++; return stop }); !errors.Is(err, stop) || count != 1 {
		t.Fatalf("Each did not stop at the first error: %v after %d", err, count)
	}
}

func TestQueryDetailHeaderSource(t *testing.T) {
	block := &HeaderBlockEvidence{Compression: ChunkCompressionNone, PlaintextLength: 5, DataEnc: []byte("x")}
	detail := AuditQueryDetail{
		Audit:       AuditListRow{CaptureVersion: CaptureVersion2},
		Stages:      []HTTPStage{{Stage: StageRequestReceived}, {Stage: StageResponseReceived}},
		HeaderBlock: block,
	}
	source := detail.HeaderSource()
	want := HeaderSource{CaptureVersion: CaptureVersion2, Block: block, StageSet: []string{StageRequestReceived, StageResponseReceived}}
	if !reflect.DeepEqual(source, want) {
		t.Fatalf("HeaderSource = %+v, want %+v", source, want)
	}
}

func TestEffectiveCaptureVersionAndStageOrder(t *testing.T) {
	if EffectiveCaptureVersion(0) != 1 || EffectiveCaptureVersion(2) != 2 {
		t.Fatal("zero capture version must mean version 1")
	}
	for index, stage := range []string{StageRequestReceived, StageRequestSent, StageResponseReceived, StageResponseSent} {
		if StageOrder(stage) != index {
			t.Fatalf("StageOrder(%s) = %d", stage, StageOrder(stage))
		}
	}
	if StageOrder("unknown") != -1 {
		t.Fatal("unknown stage must have no order")
	}
}
