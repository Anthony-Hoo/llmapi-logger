package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

func TestWriterPersistsEncryptedEvidenceAndSnapshot(t *testing.T) {
	t.Parallel()

	store, _ := openTestStore(t)
	ctx := context.Background()
	record := testAudit("audit-complete")
	if err := store.BeginAudit(ctx, record); err != nil {
		t.Fatal(err)
	}
	hasAudits, err := store.HasAudits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAudits {
		t.Fatal("HasAudits returned false after committed BeginAudit")
	}

	contentLength := int64(-1)
	stage := HTTPStage{
		AuditID:       record.AuditID,
		Stage:         StageRequestReceived,
		Proto:         "HTTP/1.1",
		Method:        "POST",
		Host:          "newapi.local",
		ContentLength: &contentLength,
		StartedAtNS:   2,
	}
	if err := store.StartStage(ctx, stage); err != nil {
		t.Fatal(err)
	}
	if err := store.StartBody(ctx, BodyStream{AuditID: record.AuditID, Stage: stage.Stage}); err != nil {
		t.Fatal(err)
	}
	headerCiphertext := []byte{0x01, 0x02, 0xff, 0x00}
	if err := store.AddHeaders(ctx, []HTTPHeader{
		{
			AuditID: record.AuditID, Stage: stage.Stage, Kind: HeaderKindHeader,
			Name: "authorization", ValueIndex: 0, ValueLength: 12, ValueEnc: headerCiphertext,
		},
		{
			AuditID: record.AuditID, Stage: stage.Stage, Kind: HeaderKindTrailer,
			Name: "x-checksum", ValueIndex: 0, ValueLength: 6, ValueEnc: []byte{0x03, 0x04},
		},
	}); err != nil {
		t.Fatal(err)
	}
	chunkCiphertext := []byte{0xaa, 0xbb, 0x00, 0xff}
	if err := store.AddChunk(ctx, BodyChunk{
		AuditID: record.AuditID, Stage: stage.Stage, Seq: 0, Offset: 0,
		PlaintextLength: 4, ObservedAtNS: 3, DataEnc: chunkCiphertext,
	}); err != nil {
		t.Fatal(err)
	}
	digest := bytes.Repeat([]byte{0x5a}, 32)
	if err := store.FinishStage(ctx, StageFinish{
		AuditID:       record.AuditID,
		Stage:         stage.Stage,
		State:         StageStateComplete,
		ContentLength: &contentLength,
		EndedAtNS:     4,
		Body: &BodyFinish{
			ObservedLength: 4,
			StoredLength:   4,
			SHA256:         digest,
			HashComplete:   true,
			EOFSeen:        true,
			State:          StageStateComplete,
		},
	}); err != nil {
		t.Fatal(err)
	}
	status := 200
	if err := store.FinishAudit(ctx, AuditFinish{
		AuditID:       record.AuditID,
		EndedAtNS:     5,
		StatusCode:    &status,
		ForwardStatus: ForwardCompleted,
		CaptureStatus: CaptureComplete,
		ParseStatus:   ParsePending,
	}); err != nil {
		t.Fatal(err)
	}

	snapshot, err := store.Snapshot(ctx, record.AuditID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Audit.ForwardStatus != ForwardCompleted || snapshot.Audit.StatusCode == nil || *snapshot.Audit.StatusCode != 200 || snapshot.Audit.EndedAtNS == nil || *snapshot.Audit.EndedAtNS != 5 {
		t.Fatalf("unexpected audit snapshot: %+v", snapshot.Audit)
	}
	if !bytes.Equal(snapshot.Audit.RequestURIEnc, record.RequestURIEnc) {
		t.Fatalf("request URI ciphertext changed: %x != %x", snapshot.Audit.RequestURIEnc, record.RequestURIEnc)
	}
	if len(snapshot.Stages) != 1 || snapshot.Stages[0].State != StageStateComplete {
		t.Fatalf("unexpected stages: %+v", snapshot.Stages)
	}
	if len(snapshot.Headers) != 2 || !bytes.Equal(snapshot.Headers[0].ValueEnc, headerCiphertext) {
		t.Fatalf("unexpected headers: %+v", snapshot.Headers)
	}
	if len(snapshot.Bodies) != 1 || !bytes.Equal(snapshot.Bodies[0].SHA256, digest) || !snapshot.Bodies[0].HashComplete || !snapshot.Bodies[0].EOFSeen {
		t.Fatalf("unexpected bodies: %+v", snapshot.Bodies)
	}
	if len(snapshot.Chunks) != 1 || !bytes.Equal(snapshot.Chunks[0].DataEnc, chunkCiphertext) || snapshot.Chunks[0].Offset != 0 {
		t.Fatalf("unexpected chunks: %+v", snapshot.Chunks)
	}
	if !store.Healthy() {
		t.Fatal("store is unhealthy after successful writes")
	}
}

func TestRejectedAuditHasOnlyObservedStages(t *testing.T) {
	t.Parallel()

	store, _ := openTestStore(t)
	ctx := context.Background()
	record := testAudit("audit-rejected")
	if err := store.BeginAudit(ctx, record); err != nil {
		t.Fatal(err)
	}
	if err := store.StartStage(ctx, HTTPStage{
		AuditID: record.AuditID, Stage: StageRequestReceived, Proto: "HTTP/1.1",
		Method: "POST", Host: "newapi.local", StartedAtNS: 2,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishStage(ctx, StageFinish{
		AuditID: record.AuditID, Stage: StageRequestReceived,
		State: StageStatePartial, EndedAtNS: 3,
	}); err != nil {
		t.Fatal(err)
	}
	blockedBy, blockCode, status := "credential", "credential_required", 401
	if err := store.FinishAudit(ctx, AuditFinish{
		AuditID: record.AuditID, EndedAtNS: 4, StatusCode: &status,
		ForwardStatus: ForwardRejected, CaptureStatus: CapturePartial,
		BlockedBy: &blockedBy, BlockCode: &blockCode,
	}); err != nil {
		t.Fatal(err)
	}

	snapshot, err := store.Snapshot(ctx, record.AuditID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Audit.ForwardStatus != ForwardRejected || snapshot.Audit.ParseStatus != ParseSkipped || snapshot.Audit.BlockedBy == nil || *snapshot.Audit.BlockedBy != blockedBy || snapshot.Audit.BlockCode == nil || *snapshot.Audit.BlockCode != blockCode {
		t.Fatalf("unexpected rejected audit: %+v", snapshot.Audit)
	}
	if len(snapshot.Stages) != 1 || len(snapshot.Bodies) != 0 || len(snapshot.Chunks) != 0 {
		t.Fatalf("rejected audit contains unobserved evidence: %+v", snapshot)
	}
}

func TestWriterConcurrentAudits(t *testing.T) {
	t.Parallel()

	store, _ := openTestStore(t)
	const auditCount = 80
	var wait sync.WaitGroup
	errCh := make(chan error, auditCount)
	for index := 0; index < auditCount; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			ctx := context.Background()
			auditID := fmt.Sprintf("audit-concurrent-%03d", index)
			record := testAudit(auditID)
			record.StartedAtNS += int64(index)
			if err := store.BeginAudit(ctx, record); err != nil {
				errCh <- err
				return
			}
			stage := HTTPStage{
				AuditID: auditID, Stage: StageRequestReceived, Proto: "HTTP/1.1",
				Method: "POST", Host: "newapi.local", StartedAtNS: 1000 + int64(index),
			}
			if err := store.StartStage(ctx, stage); err != nil {
				errCh <- err
				return
			}
			if err := store.StartBody(ctx, BodyStream{AuditID: auditID, Stage: stage.Stage}); err != nil {
				errCh <- err
				return
			}
			if err := store.AddChunk(ctx, BodyChunk{
				AuditID: auditID, Stage: stage.Stage, Seq: 0, Offset: 0,
				PlaintextLength: 1, ObservedAtNS: 2000 + int64(index), DataEnc: []byte{byte(index), 0xff},
			}); err != nil {
				errCh <- err
				return
			}
			if err := store.FinishStage(ctx, StageFinish{
				AuditID: auditID, Stage: stage.Stage, State: StageStatePartial,
				EndedAtNS: 3000 + int64(index),
				Body:      &BodyFinish{ObservedLength: 1, StoredLength: 1, State: StageStatePartial},
			}); err != nil {
				errCh <- err
				return
			}
			if err := store.FinishAudit(ctx, AuditFinish{
				AuditID: auditID, EndedAtNS: 4000 + int64(index),
				ForwardStatus: ForwardCompleted, CaptureStatus: CapturePartial, ParseStatus: ParsePending,
			}); err != nil {
				errCh <- err
			}
		}()
	}
	wait.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}

	var audits, stages, chunks int
	if err := store.readerDB.QueryRow("SELECT COUNT(*) FROM audit_records").Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if err := store.readerDB.QueryRow("SELECT COUNT(*) FROM http_stages").Scan(&stages); err != nil {
		t.Fatal(err)
	}
	if err := store.readerDB.QueryRow("SELECT COUNT(*) FROM body_chunks").Scan(&chunks); err != nil {
		t.Fatal(err)
	}
	if audits != auditCount || stages != auditCount || chunks != auditCount {
		t.Fatalf("counts audits=%d stages=%d chunks=%d, want %d each", audits, stages, chunks, auditCount)
	}
}

func TestWriterRollsBackFailedOperationAndRecoversHealth(t *testing.T) {
	t.Parallel()

	store, _ := openTestStore(t)
	ctx := context.Background()
	record := testAudit("audit-rollback")
	if err := store.BeginAudit(ctx, record); err != nil {
		t.Fatal(err)
	}
	stage := HTTPStage{
		AuditID: record.AuditID, Stage: StageRequestReceived, Proto: "HTTP/1.1",
		Method: "POST", Host: "newapi.local", StartedAtNS: 2,
	}
	stage.defaults()
	if err := store.submitSync(ctx, writeRequest{kind: writeStartStage, data: cloneHTTPStage(stage)}); err != nil {
		t.Fatal(err)
	}

	duplicate := HTTPHeader{
		AuditID: record.AuditID, Stage: stage.Stage, Kind: HeaderKindHeader,
		Name: "x-test", ValueIndex: 0, ValueLength: 1, ValueEnc: []byte{0x01},
	}
	err := store.submitSync(ctx, writeRequest{
		kind: writeAddHeaders,
		data: []HTTPHeader{cloneHTTPHeader(duplicate), cloneHTTPHeader(duplicate)},
	})
	if err == nil {
		t.Fatal("expected duplicate-header transaction failure")
	}
	if store.Healthy() {
		t.Fatal("store remained healthy after failed writer transaction")
	}
	var headerCount int
	if err := store.readerDB.QueryRow("SELECT COUNT(*) FROM http_headers WHERE audit_id = ?", record.AuditID).Scan(&headerCount); err != nil {
		t.Fatal(err)
	}
	if headerCount != 0 {
		t.Fatalf("failed transaction left %d header rows", headerCount)
	}

	if err := store.AddHeaders(ctx, []HTTPHeader{duplicate}); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishStage(ctx, StageFinish{
		AuditID: record.AuditID, Stage: stage.Stage, State: StageStatePartial, EndedAtNS: 3,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishAudit(ctx, AuditFinish{
		AuditID: record.AuditID, EndedAtNS: 4,
		ForwardStatus: ForwardCompleted, CaptureStatus: CapturePartial, ParseStatus: ParsePending,
	}); err != nil {
		t.Fatal(err)
	}
	if !store.Healthy() {
		t.Fatal("store did not recover after successful batch")
	}
	snapshot, err := store.Snapshot(ctx, record.AuditID)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Headers) != 1 {
		t.Fatalf("recovery snapshot has %d headers, want 1", len(snapshot.Headers))
	}
}

func TestCloseDrainsQueueAndRejectsNewWrites(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	record := testAudit("audit-close")
	if err := store.BeginAudit(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	stage := HTTPStage{
		AuditID: record.AuditID, Stage: StageRequestReceived, Proto: "HTTP/1.1",
		Method: "POST", Host: "newapi.local", StartedAtNS: 2,
	}
	if err := store.StartStage(context.Background(), stage); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if store.Healthy() {
		t.Fatal("closed store reports healthy")
	}
	if err := store.StartStage(context.Background(), stage); !errors.Is(err, ErrClosed) {
		t.Fatalf("StartStage after close = %v, want ErrClosed", err)
	}
	if err := store.BeginAudit(context.Background(), testAudit("after-close")); !errors.Is(err, ErrClosed) {
		t.Fatalf("BeginAudit after close = %v, want ErrClosed", err)
	}

	database, err := sql.Open("sqlite", sqliteDSN(path, false))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var stages int
	if err := database.QueryRow("SELECT COUNT(*) FROM http_stages WHERE audit_id = ?", record.AuditID).Scan(&stages); err != nil {
		t.Fatal(err)
	}
	if stages != 1 {
		t.Fatalf("Close did not drain queued stage: count=%d", stages)
	}
}

func TestHotPathQueueFullAndContextCancellation(t *testing.T) {
	t.Parallel()

	store := &Store{queue: make(chan writeRequest, 1)}
	request := writeRequest{kind: writeStartStage, data: HTTPStage{}}
	if err := store.submitAsync(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := store.submitAsync(context.Background(), request); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("second enqueue = %v, want ErrQueueFull", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.submitAsync(ctx, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled enqueue = %v, want context.Canceled", err)
	}
}

func TestWriterInputValidation(t *testing.T) {
	t.Parallel()

	store, _ := openTestStore(t)
	ctx := context.Background()
	if err := store.BeginAudit(ctx, AuditRecord{}); err == nil {
		t.Fatal("expected invalid audit error")
	}
	if err := store.StartStage(ctx, HTTPStage{AuditID: "x", Stage: "unknown", StartedAtNS: 1}); err == nil {
		t.Fatal("expected invalid stage error")
	}
	if err := store.AddHeaders(ctx, []HTTPHeader{{AuditID: "x", Stage: StageRequestReceived}}); err == nil {
		t.Fatal("expected invalid header error")
	}
	if err := store.AddChunk(ctx, BodyChunk{AuditID: "x", Stage: StageRequestReceived, Seq: -1}); err == nil {
		t.Fatal("expected invalid chunk error")
	}
	blockedBy, blockCode := "guard", "blocked"
	if err := store.FinishAudit(ctx, AuditFinish{
		AuditID: "x", EndedAtNS: 1, ForwardStatus: ForwardCompleted,
		CaptureStatus: CaptureComplete, ParseStatus: ParsePending,
		BlockedBy: &blockedBy, BlockCode: &blockCode,
	}); err == nil {
		t.Fatal("expected block fields on non-rejected audit error")
	}
	if err := store.FinishAudit(ctx, AuditFinish{
		AuditID: "x", EndedAtNS: 1, ForwardStatus: ForwardRejected,
		CaptureStatus: CapturePartial,
	}); err == nil {
		t.Fatal("expected missing rejected fields error")
	}
}

func openTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nested", "audit.db")
	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, path
}

func testAudit(auditID string) AuditRecord {
	return AuditRecord{
		AuditID:       auditID,
		StartedAtNS:   1,
		RouteID:       "openai-chat",
		Protocol:      "openai",
		ParserName:    "openai.chat_completions",
		Method:        "POST",
		Path:          "/v1/chat/completions",
		RequestURIEnc: []byte{0x10, 0x20, 0x30},
		Mode:          "available",
	}
}
