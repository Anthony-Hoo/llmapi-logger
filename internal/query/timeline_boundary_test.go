package query

import (
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"

	"llmapi-logger/internal/bodycodec"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
	"llmapi-logger/internal/streamtimeline"
)

func TestTimelineUsesRawFallbackAndOwningSource(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name                             string
		side                             Side
		fallback, preferred              string
		addPreferred, differentPreferred bool
	}{
		{"request fallback", SideRequest, sqlite.StageRequestReceived, sqlite.StageRequestSent, false, false},
		{"response fallback", SideResponse, sqlite.StageResponseSent, sqlite.StageResponseReceived, false, false},
		{"deduplicated request source", SideRequest, sqlite.StageRequestReceived, sqlite.StageRequestSent, true, false},
		{"preferred body without timeline", SideRequest, sqlite.StageRequestReceived, sqlite.StageRequestSent, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			store, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "audit.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			cipher := testCipher(t)
			const id = "timeline-boundary"
			if err := store.BeginAudit(ctx, sqlite.AuditRecord{AuditID: id, StartedAtNS: 1, RouteID: "route", Protocol: "openai", ParserName: "parser", Method: "POST", Path: "/v1/responses", RequestURIEnc: []byte{1}, Mode: "available"}); err != nil {
				t.Fatal(err)
			}
			writeStage := func(stage, value string, withTimeline bool) {
				t.Helper()
				if err := store.StartStage(ctx, sqlite.HTTPStage{AuditID: id, Stage: stage, StartedAtNS: 2}); err != nil {
					t.Fatal(err)
				}
				if err := store.StartBody(ctx, sqlite.BodyStream{AuditID: id, Stage: stage}); err != nil {
					t.Fatal(err)
				}
				aad, err := security.AAD(id, "body_chunk", stage, "0")
				if err != nil {
					t.Fatal(err)
				}
				data, err := cipher.Encrypt(aad, []byte(value))
				if err != nil {
					t.Fatal(err)
				}
				if err := store.AddChunk(ctx, sqlite.BodyChunk{AuditID: id, Stage: stage, PlaintextLength: len(value), ObservedAtNS: 3, DataEnc: data}); err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256([]byte(value))
				body := &sqlite.BodyFinish{ObservedLength: int64(len(value)), StoredLength: int64(len(value)), ChunkCount: 1, State: sqlite.StageStateComplete, HashComplete: true, EOFSeen: true, SHA256: digest[:]}
				if withTimeline {
					points, err := streamtimeline.Encode([]streamtimeline.Point{{Offset: int64(len(value)), AtNS: 3}})
					if err != nil {
						t.Fatal(err)
					}
					compression, encoded, err := bodycodec.Encode(points, "application/x-llmapi-stream-timeline")
					if err != nil {
						t.Fatal(err)
					}
					aad, err := security.AAD(id, "stream_timeline_v1", stage, compression)
					if err != nil {
						t.Fatal(err)
					}
					data, err := cipher.Encrypt(aad, encoded)
					if err != nil {
						t.Fatal(err)
					}
					at := int64(3)
					body.StreamEventCount, body.StreamTimelineComplete = 1, true
					body.Timeline = &sqlite.StreamTimeline{EventCount: 1, FirstEventAtNS: &at, LastEventAtNS: &at, Complete: true, Compression: compression, PlaintextLength: int64(len(points)), DataEnc: data}
				}
				if err := store.FinishStage(ctx, sqlite.StageFinish{AuditID: id, Stage: stage, State: sqlite.StageStateComplete, EndedAtNS: 4, Body: body}); err != nil {
					t.Fatal(err)
				}
			}
			writeStage(test.fallback, "ABC", true)
			if test.addPreferred {
				value := "ABC"
				if test.differentPreferred {
					value = "XYZ"
				}
				writeStage(test.preferred, value, false)
			}
			status := 200
			if err := store.FinishAudit(ctx, sqlite.AuditFinish{AuditID: id, EndedAtNS: 5, StatusCode: &status, ForwardStatus: sqlite.ForwardCompleted, CaptureStatus: sqlite.CaptureComplete, ParseStatus: sqlite.ParsePending}); err != nil {
				t.Fatal(err)
			}
			service, err := New(store, cipher)
			if err != nil {
				t.Fatal(err)
			}
			got, err := service.Timeline(ctx, id, test.side)
			if test.differentPreferred {
				if !errors.Is(err, ErrNotFound) {
					t.Fatalf("unexpected cross-boundary fallback: %v", err)
				}
				return
			}
			if err != nil || got.Stage != test.fallback || !got.Complete || len(got.Points) != 1 || got.Points[0].Offset != 3 {
				t.Fatalf("wrong timeline source or evidence: %+v, %v", got, err)
			}
		})
	}
}
