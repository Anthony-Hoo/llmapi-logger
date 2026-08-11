package parser

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

func TestWorkerStartupScanDecodesGzipAndEncryptsParsedJSON(t *testing.T) {
	t.Parallel()

	cipher := testCipher(t)
	requestPlaintext := []byte(`{"model":"test","secret":"request-canary"}`)
	requestEncoded := gzipBytes(t, requestPlaintext)
	responsePlaintext := []byte(`{"id":"response-test"}`)
	auditID := "audit-worker"
	parserName := "test.parser"
	store := newFakeStore(auditID, parserName)
	requestStage, requestChunks := encryptedStage(t, cipher, auditID, sqlite.StageRequestReceived, "application/json", "gzip", requestEncoded)
	requestKey := stageKey(auditID, sqlite.StageRequestReceived)
	store.stages[requestKey], store.chunks[requestKey] = requestStage, requestChunks
	responseStage, responseChunks := encryptedStage(t, cipher, auditID, sqlite.StageResponseReceived, "application/json", "", responsePlaintext)
	responseKey := stageKey(auditID, sqlite.StageResponseReceived)
	store.stages[responseKey], store.chunks[responseKey] = responseStage, responseChunks
	implementation := &recordingParser{name: parserName, inputs: make(chan Input, 1)}
	worker, err := NewWorker(store, cipher, []Parser{implementation}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(worker.Close)

	select {
	case input := <-implementation.inputs:
		if !bytes.Equal(input.Request.Data, requestPlaintext) || input.Request.ContentEncoding != "gzip" || !input.Request.Complete {
			t.Fatalf("request evidence = %+v data=%q", input.Request, input.Request.Data)
		}
		if !bytes.Equal(input.Response.Data, responsePlaintext) || !input.Response.Complete {
			t.Fatalf("response evidence = %+v data=%q", input.Response, input.Response.Data)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not parse startup pending audit")
	}

	var saved sqlite.ParsedResult
	select {
	case saved = <-store.saved:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not save parsed result")
	}
	if store.resetCount != 1 || saved.Status != StatusOK || saved.RequestModel == nil || *saved.RequestModel != "worker-model" {
		t.Fatalf("unexpected worker result: reset=%d result=%+v", store.resetCount, saved)
	}
	if bytes.Contains(saved.ParsedJSONEnc, []byte("parsed-canary")) || bytes.Contains(saved.ParsedJSONEnc, []byte("conversation-canary")) {
		t.Fatalf("parsed JSON stored in plaintext: %q", saved.ParsedJSONEnc)
	}
	aad, err := security.AAD(auditID, "parsed_json", parserName)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := cipher.Decrypt(aad, saved.ParsedJSONEnc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(decrypted, []byte("parsed-canary")) || !bytes.Contains(decrypted, []byte("conversation-canary")) {
		t.Fatalf("unexpected decrypted parsed JSON: %s", decrypted)
	}
}

func TestWorkerNotifyIsBoundedAndNonBlocking(t *testing.T) {
	t.Parallel()

	worker, err := NewWorker(newFakeStore("audit", "test.parser"), testCipher(t), []Parser{&recordingParser{name: "test.parser"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	for index := 0; index < QueueCapacity; index++ {
		if !worker.Notify(fmt.Sprintf("audit-%d", index)) {
			t.Fatalf("Notify(%d) unexpectedly failed", index)
		}
	}
	if worker.QueueLength() != QueueCapacity {
		t.Fatalf("QueueLength = %d", worker.QueueLength())
	}
	if worker.Notify("overflow") {
		t.Fatal("Notify accepted an item beyond queue capacity")
	}
}

func TestWorkerRecoversParserPanic(t *testing.T) {
	t.Parallel()

	cipher := testCipher(t)
	auditID := "audit-panic"
	store := newFakeStore(auditID, "panic.parser")
	stage, chunks := encryptedStage(t, cipher, auditID, sqlite.StageRequestReceived, "application/json", "", []byte(`{}`))
	key := stageKey(auditID, sqlite.StageRequestReceived)
	store.stages[key], store.chunks[key] = stage, chunks
	worker, err := NewWorker(store, cipher, []Parser{&recordingParser{name: "panic.parser", panic: true}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer worker.Close()

	select {
	case saved := <-store.saved:
		if saved.Status != StatusError || saved.ErrorCode == nil || *saved.ErrorCode != "parser_panic" {
			t.Fatalf("panic result = %+v", saved)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("panic result was not saved")
	}
}

func TestWorkerSaveFailureReleasesAuditForRetry(t *testing.T) {
	t.Parallel()

	cipher := testCipher(t)
	auditID := "audit-retry"
	store := newFakeStore(auditID, "test.parser")
	store.saveFailures = 1
	stage, chunks := encryptedStage(t, cipher, auditID, sqlite.StageRequestReceived, "application/json", "", []byte(`{}`))
	key := stageKey(auditID, sqlite.StageRequestReceived)
	store.stages[key], store.chunks[key] = stage, chunks
	worker, err := NewWorker(store, cipher, []Parser{&recordingParser{name: "test.parser"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer worker.Close()

	deadline := time.Now().Add(3 * time.Second)
	for {
		store.mu.Lock()
		audit := store.audits[auditID]
		released := store.releaseCount
		store.mu.Unlock()
		if released == 1 && audit.ParseStatus == sqlite.ParsePending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("failed parse was not released back to pending")
		}
		time.Sleep(time.Millisecond)
	}
	if !worker.Notify(auditID) {
		t.Fatal("released audit could not be re-enqueued")
	}

	select {
	case saved := <-store.saved:
		if saved.Status != StatusOK {
			t.Fatalf("retried result status = %q", saved.Status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("released audit was not retried")
	}
	store.mu.Lock()
	saveAttempts, releaseCount := store.saveAttempts, store.releaseCount
	store.mu.Unlock()
	if saveAttempts != 2 || releaseCount != 1 {
		t.Fatalf("save attempts = %d, releases = %d", saveAttempts, releaseCount)
	}
}

func TestWorkerEvidenceErrorsOverrideProtocolFallbacks(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		encoding   string
		tamper     bool
		wantStatus string
		wantCode   string
	}{
		{name: "unsupported encoding", encoding: "br", wantStatus: StatusSkipped, wantCode: "unsupported_content_encoding"},
		{name: "ciphertext integrity", tamper: true, wantStatus: StatusError, wantCode: "capture_integrity_error"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			cipher := testCipher(t)
			auditID := "audit-evidence-" + test.name
			store := newFakeStore(auditID, "fallback.parser")
			stage, chunks := encryptedStage(t, cipher, auditID, sqlite.StageRequestReceived, "application/json", test.encoding, []byte(`{"model":"secret"}`))
			if test.tamper {
				chunks[0].DataEnc[len(chunks[0].DataEnc)-1] ^= 0xff
			}
			key := stageKey(auditID, sqlite.StageRequestReceived)
			store.stages[key], store.chunks[key] = stage, chunks
			fallback := Result{Status: StatusError, ErrorCode: "invalid_json"}
			worker, err := NewWorker(store, cipher, []Parser{&recordingParser{name: "fallback.parser", result: &fallback}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := worker.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			defer worker.Close()

			select {
			case saved := <-store.saved:
				if saved.Status != test.wantStatus || saved.ErrorCode == nil || *saved.ErrorCode != test.wantCode {
					t.Fatalf("saved evidence result = %+v, want status=%s code=%s", saved, test.wantStatus, test.wantCode)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("evidence result was not saved")
			}
		})
	}
}

type recordingParser struct {
	name   string
	inputs chan Input
	panic  bool
	result *Result
}

func (implementation *recordingParser) Name() string { return implementation.name }
func (*recordingParser) Version() string             { return "test-1" }
func (implementation *recordingParser) Parse(_ context.Context, input Input) Result {
	if implementation.panic {
		panic("test panic")
	}
	if implementation.inputs != nil {
		implementation.inputs <- input
	}
	if implementation.result != nil {
		return *implementation.result
	}
	view := conversation.New()
	view.Append(conversation.Message{
		Role: conversation.RoleUser, Phase: conversation.PhaseRequest,
		Direction: conversation.DirectionClientToUpstream,
		Content:   []conversation.Part{conversation.Text("conversation-canary")},
	})
	return Result{
		Status: StatusOK, RequestModel: "worker-model", Conversation: view,
		ParsedJSON: []byte(`{"secret":"parsed-canary"}`),
	}
}

type fakeStore struct {
	mu           sync.Mutex
	audits       map[string]sqlite.ParserAudit
	stages       map[string]sqlite.ParserStage
	chunks       map[string][]sqlite.BodyChunk
	saved        chan sqlite.ParsedResult
	resetCount   int
	saveFailures int
	saveAttempts int
	releaseCount int
}

func newFakeStore(auditID, parserName string) *fakeStore {
	return &fakeStore{
		audits: map[string]sqlite.ParserAudit{
			auditID: {
				AuditID: auditID, Protocol: "test", ParserName: parserName, Path: "/test",
				ForwardStatus: sqlite.ForwardCompleted, CaptureStatus: sqlite.CaptureComplete, ParseStatus: sqlite.ParsePending,
			},
		},
		stages: make(map[string]sqlite.ParserStage),
		chunks: make(map[string][]sqlite.BodyChunk),
		saved:  make(chan sqlite.ParsedResult, 4),
	}
}

func (store *fakeStore) ResetProcessingParses(context.Context) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.resetCount++
	for auditID, audit := range store.audits {
		if audit.ParseStatus == sqlite.ParseProcessing {
			audit.ParseStatus = sqlite.ParsePending
			store.audits[auditID] = audit
		}
	}
	return nil
}

func (store *fakeStore) ListPendingParseIDs(context.Context, int) ([]string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	ids := make([]string, 0)
	for auditID, audit := range store.audits {
		if audit.ParseStatus == sqlite.ParsePending {
			ids = append(ids, auditID)
		}
	}
	return ids, nil
}

func (store *fakeStore) LoadParserAudit(_ context.Context, auditID string) (sqlite.ParserAudit, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	audit, ok := store.audits[auditID]
	if !ok {
		return sqlite.ParserAudit{}, fmt.Errorf("missing audit")
	}
	return audit, nil
}

func (store *fakeStore) ClaimPendingParse(_ context.Context, auditID string) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	audit, ok := store.audits[auditID]
	if !ok || audit.ParseStatus != sqlite.ParsePending {
		return false, nil
	}
	audit.ParseStatus = sqlite.ParseProcessing
	store.audits[auditID] = audit
	return true, nil
}

func (store *fakeStore) LoadParserStage(_ context.Context, auditID, stage string) (sqlite.ParserStage, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, ok := store.stages[stageKey(auditID, stage)]
	if !ok {
		return sqlite.ParserStage{}, sql.ErrNoRows
	}
	return value, nil
}

func (store *fakeStore) ReadParserChunks(_ context.Context, auditID, stage string, afterSeq int64, limit int) ([]sqlite.BodyChunk, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	all := store.chunks[stageKey(auditID, stage)]
	result := make([]sqlite.BodyChunk, 0, limit)
	for _, chunk := range all {
		if chunk.Seq <= afterSeq {
			continue
		}
		result = append(result, chunk)
		if len(result) == limit {
			break
		}
	}
	return result, nil
}

func (store *fakeStore) SaveParsedResult(_ context.Context, result sqlite.ParsedResult) error {
	store.mu.Lock()
	store.saveAttempts++
	if store.saveFailures > 0 {
		store.saveFailures--
		store.mu.Unlock()
		return fmt.Errorf("temporary save failure")
	}
	audit := store.audits[result.AuditID]
	audit.ParseStatus = result.Status
	store.audits[result.AuditID] = audit
	store.mu.Unlock()
	store.saved <- result
	return nil
}

func (store *fakeStore) ReleaseProcessingParse(_ context.Context, auditID string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.releaseCount++
	audit, ok := store.audits[auditID]
	if ok && audit.ParseStatus == sqlite.ParseProcessing {
		audit.ParseStatus = sqlite.ParsePending
		store.audits[auditID] = audit
	}
	return nil
}

func encryptedStage(t *testing.T, cipher security.Cipher, auditID, stageName, contentType, contentEncoding string, plaintext []byte) (sqlite.ParserStage, []sqlite.BodyChunk) {
	t.Helper()
	stage := sqlite.ParserStage{
		Stage: sqlite.HTTPStage{AuditID: auditID, Stage: stageName, State: sqlite.StageStateComplete, StartedAtNS: 1},
	}
	digest := sha256.Sum256(plaintext)
	stage.Body = &sqlite.BodyStream{
		AuditID: auditID, Stage: stageName, ObservedLength: int64(len(plaintext)), StoredLength: int64(len(plaintext)),
		SHA256: digest[:], HashComplete: true, EOFSeen: true, State: sqlite.StageStateComplete,
	}
	for _, pair := range [][2]string{{"Content-Type", contentType}, {"Content-Encoding", contentEncoding}} {
		if pair[1] == "" {
			continue
		}
		aad, err := security.AAD(auditID, "header", stageName, sqlite.HeaderKindHeader, pair[0], strconv.Itoa(0))
		if err != nil {
			t.Fatal(err)
		}
		encrypted, err := cipher.Encrypt(aad, []byte(pair[1]))
		if err != nil {
			t.Fatal(err)
		}
		stage.Headers = append(stage.Headers, sqlite.HTTPHeader{
			AuditID: auditID, Stage: stageName, Kind: sqlite.HeaderKindHeader, Name: pair[0],
			ValueIndex: 0, ValueLength: len(pair[1]), ValueEnc: encrypted,
		})
	}
	bodyAAD, err := security.AAD(auditID, "body_chunk", stageName, "0")
	if err != nil {
		t.Fatal(err)
	}
	bodyCiphertext, err := cipher.Encrypt(bodyAAD, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	chunks := []sqlite.BodyChunk{{
		AuditID: auditID, Stage: stageName, Seq: 0, Offset: 0, PlaintextLength: len(plaintext), ObservedAtNS: 1, DataEnc: bodyCiphertext,
	}}
	return stage, chunks
}

func stageKey(auditID, stage string) string { return auditID + "\x00" + stage }

func testCipher(t *testing.T) *security.AESGCM {
	t.Helper()
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{0x42}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}
