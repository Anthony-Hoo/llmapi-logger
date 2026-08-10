package query

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"io"
	"strconv"
	"testing"

	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

func TestStreamRawDecryptsAndVerifiesCompleteBody(t *testing.T) {
	t.Parallel()

	cipher := testCipher(t)
	auditID := "audit-raw"
	stage := sqlite.StageRequestSent
	parts := [][]byte{[]byte("hello "), []byte("world")}
	hash := sha256.Sum256(bytes.Join(parts, nil))
	store := &fakeStore{healthy: true, rawMeta: sqlite.RawBodyMetadata{
		AuditID: auditID, Stage: stage, ObservedLength: 11, StoredLength: 11,
		SHA256: hash[:], HashComplete: true, EOFSeen: true, State: sqlite.StageStateComplete,
	}}
	var offset int64
	for sequence, part := range parts {
		aad, err := security.AAD(auditID, "body_chunk", stage, strconv.Itoa(sequence))
		if err != nil {
			t.Fatal(err)
		}
		encrypted, err := cipher.Encrypt(aad, part)
		if err != nil {
			t.Fatal(err)
		}
		store.chunks = append(store.chunks, sqlite.BodyChunk{
			AuditID: auditID, Stage: stage, Seq: int64(sequence), Offset: offset,
			PlaintextLength: len(part), DataEnc: encrypted,
		})
		offset += int64(len(part))
	}

	service, err := New(store, cipher)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := service.RawMeta(context.Background(), auditID, SideRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !metadata.Complete || metadata.StoredLength != 11 || metadata.SHA256 == "" {
		t.Fatalf("raw metadata = %+v", metadata)
	}
	var output bytes.Buffer
	if err := service.StreamRaw(context.Background(), auditID, SideRequest, &output); err != nil {
		t.Fatal(err)
	}
	if output.String() != "hello world" {
		t.Fatalf("raw output = %q", output.String())
	}
}

func TestStreamRawRejectsTamperedCiphertextWithoutPlaintext(t *testing.T) {
	t.Parallel()

	cipher := testCipher(t)
	auditID := "audit-tampered"
	stage := sqlite.StageResponseReceived
	plaintext := []byte("top secret prompt")
	digest := sha256.Sum256(plaintext)
	aad, err := security.AAD(auditID, "body_chunk", stage, "0")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := cipher.Encrypt(aad, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	encrypted[len(encrypted)-1] ^= 0xff
	store := &fakeStore{
		healthy: true,
		rawMeta: sqlite.RawBodyMetadata{
			AuditID: auditID, Stage: stage, ObservedLength: int64(len(plaintext)), StoredLength: int64(len(plaintext)),
			SHA256: digest[:], HashComplete: true, EOFSeen: true, State: sqlite.StageStateComplete,
		},
		chunks: []sqlite.BodyChunk{{
			AuditID: auditID, Stage: stage, Seq: 0, Offset: 0,
			PlaintextLength: len(plaintext), DataEnc: encrypted,
		}},
	}
	service, err := New(store, cipher)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err = service.StreamRaw(context.Background(), auditID, SideResponse, &output)
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("StreamRaw error = %v, want ErrIntegrity", err)
	}
	if output.Len() != 0 {
		t.Fatalf("tampered stream wrote %d bytes", output.Len())
	}
}

func TestStreamRawRejectsChunkGapEvenForPartialCapture(t *testing.T) {
	t.Parallel()

	cipher := testCipher(t)
	auditID := "audit-partial-gap"
	stage := sqlite.StageRequestSent
	plaintext := []byte("partial")
	aad, err := security.AAD(auditID, "body_chunk", stage, "1")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := cipher.Encrypt(aad, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeStore{
		healthy: true,
		rawMeta: sqlite.RawBodyMetadata{
			AuditID: auditID, Stage: stage, ObservedLength: int64(len(plaintext)), StoredLength: int64(len(plaintext)),
			HashComplete: false, EOFSeen: false, State: sqlite.StageStatePartial,
		},
		chunks: []sqlite.BodyChunk{{
			AuditID: auditID, Stage: stage, Seq: 1, Offset: 0,
			PlaintextLength: len(plaintext), DataEnc: encrypted,
		}},
	}
	service, err := New(store, cipher)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err = service.StreamRaw(context.Background(), auditID, SideRequest, &output)
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("StreamRaw error = %v, want ErrIntegrity", err)
	}
	if output.Len() != 0 {
		t.Fatalf("invalid partial stream wrote %d bytes", output.Len())
	}
}

func TestRawRejectsEvidenceThatIsStillStreaming(t *testing.T) {
	t.Parallel()

	service, err := New(&fakeStore{
		healthy: true,
		rawMeta: sqlite.RawBodyMetadata{
			AuditID: "audit-streaming", Stage: sqlite.StageRequestSent,
			ObservedLength: 7, StoredLength: 7, State: sqlite.StageStateStreaming,
		},
	}, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.RawMeta(context.Background(), "audit-streaming", SideRequest); !errors.Is(err, ErrNotReady) {
		t.Fatalf("RawMeta error = %v, want ErrNotReady", err)
	}
	var output bytes.Buffer
	if err := service.StreamRaw(context.Background(), "audit-streaming", SideRequest, &output); !errors.Is(err, ErrNotReady) {
		t.Fatalf("StreamRaw error = %v, want ErrNotReady", err)
	}
	if output.Len() != 0 {
		t.Fatalf("streaming evidence wrote %d bytes", output.Len())
	}
}

func TestListMapsCursorAndRejectsUnsafeInputs(t *testing.T) {
	t.Parallel()

	cipher := testCipher(t)
	ended := int64(9_007_199_254_740_995)
	store := &fakeStore{
		healthy: true,
		listPage: sqlite.AuditListPage{
			Rows: []sqlite.AuditListRow{{
				AuditID: "audit-page", StartedAtNS: ended - 1, EndedAtNS: &ended,
				RouteID: "route", Protocol: "openai", ParserName: "openai.responses",
				Method: "POST", Path: "/v1/responses", Mode: "available",
				ForwardStatus: sqlite.ForwardCompleted, CaptureStatus: sqlite.CaptureComplete,
				ParseStatus: sqlite.ParseOK,
			}},
			HasMore: true,
		},
	}
	service, err := New(store, cipher)
	if err != nil {
		t.Fatal(err)
	}
	page, err := service.List(context.Background(), Filter{}, Cursor{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if page.NextCursor == nil || page.NextCursor.BeforeID != "audit-page" || page.NextCursor.BeforeStartedAtNS != ended-1 {
		t.Fatalf("page cursor = %+v", page.NextCursor)
	}
	if _, err := service.List(context.Background(), Filter{}, Cursor{BeforeID: "audit-page"}, 1); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("incomplete cursor error = %v", err)
	}
	if _, err := service.List(context.Background(), Filter{Path: "not-absolute"}, Cursor{}, 1); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("invalid path error = %v", err)
	}
}

func TestRawNotFoundIsNormalized(t *testing.T) {
	t.Parallel()

	service, err := New(&fakeStore{healthy: true, rawErr: sql.ErrNoRows}, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.RawMeta(context.Background(), "missing", SideRequest); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RawMeta error = %v, want ErrNotFound", err)
	}
	if err := service.StreamRaw(context.Background(), "missing", SideRequest, io.Discard); !errors.Is(err, ErrNotFound) {
		t.Fatalf("StreamRaw error = %v, want ErrNotFound", err)
	}
}

type fakeStore struct {
	healthy   bool
	listPage  sqlite.AuditListPage
	listErr   error
	detail    sqlite.AuditQueryDetail
	detailErr error
	rawMeta   sqlite.RawBodyMetadata
	rawErr    error
	chunks    []sqlite.BodyChunk
	chunkErr  error
}

func (store *fakeStore) Healthy() bool { return store.healthy }

func (store *fakeStore) ListAudits(context.Context, sqlite.AuditQueryFilter, sqlite.AuditQueryCursor, int) (sqlite.AuditListPage, error) {
	return store.listPage, store.listErr
}

func (store *fakeStore) QueryAuditDetail(context.Context, string) (sqlite.AuditQueryDetail, error) {
	return store.detail, store.detailErr
}

func (store *fakeStore) RawBodyMeta(context.Context, string, string) (sqlite.RawBodyMetadata, error) {
	return store.rawMeta, store.rawErr
}

func (store *fakeStore) StreamBodyChunks(_ context.Context, _, _ string, visit func(sqlite.BodyChunk) error) error {
	for _, chunk := range store.chunks {
		if err := visit(chunk); err != nil {
			return err
		}
	}
	return store.chunkErr
}

func testCipher(t *testing.T) *security.AESGCM {
	t.Helper()
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{0x42}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}
