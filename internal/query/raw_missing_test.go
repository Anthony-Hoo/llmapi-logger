package query

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"testing"

	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

func TestKnownMissingChunksDoNotDisableEvidenceValidation(t *testing.T) {
	t.Parallel()
	for _, scenario := range []string{"saved fragments", "unmarked gap", "bad GCM", "overlap", "out of bounds", "wrong stored length", "wrong sequence"} {
		t.Run(scenario, func(t *testing.T) {
			cipher := testCipher(t)
			code := sqlite.CaptureChunkMissing
			store := &fakeStore{rawMeta: sqlite.RawBodyMetadata{
				AuditID: "missing-chunks", Stage: sqlite.StageRequestSent,
				State: sqlite.StageStatePartial, RetentionState: sqlite.RetentionFull,
				ObservedLength: 9, StoredLength: 6, ErrorCode: &code,
			}}
			for i, part := range []string{"abc", "ghi"} {
				seq := int64(i * 2)
				aad, err := security.AAD("missing-chunks", "body_chunk", sqlite.StageRequestSent, strconv.FormatInt(seq, 10))
				if err != nil {
					t.Fatal(err)
				}
				data, err := cipher.Encrypt(aad, []byte(part))
				if err != nil {
					t.Fatal(err)
				}
				store.chunks = append(store.chunks, sqlite.BodyChunk{AuditID: "missing-chunks", Stage: sqlite.StageRequestSent, Seq: seq, Offset: int64(i * 6), PlaintextLength: 3, DataEnc: data})
			}
			switch scenario {
			case "unmarked gap":
				store.rawMeta.ErrorCode = nil
			case "bad GCM":
				store.chunks[0].DataEnc[0] ^= 1
			case "overlap":
				store.chunks[1].Offset = 2
			case "out of bounds":
				store.chunks[1].Offset = 9
			case "wrong stored length":
				store.rawMeta.StoredLength = 7
			case "wrong sequence":
				store.chunks[1].Seq = 3 // AAD no longer authenticates.
			}
			service, err := New(store, cipher)
			if err != nil {
				t.Fatal(err)
			}
			var result bytes.Buffer
			err = service.StreamRaw(context.Background(), "missing-chunks", SideRequest, &result)
			if scenario == "saved fragments" {
				if err != nil || result.String() != "abcghi" {
					t.Fatalf("fragment export failed: %v", err)
				}
			} else if !errors.Is(err, ErrIntegrity) {
				t.Fatalf("invalid evidence accepted: %v", err)
			}
		})
	}
}
