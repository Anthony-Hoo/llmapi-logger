package sqlite

import (
	"context"
	"fmt"
	"testing"
)

func TestFailedHeaderGroupMarksOnlyAffectedStagesAcrossAudits(t *testing.T) {
	t.Parallel()
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprintf("startup recovery=%v", recovery), func(t *testing.T) {
			store, path := openTestStore(t)
			ctx := context.Background()
			for _, id := range []string{"headers-one", "headers-two"} {
				if err := store.BeginAudit(ctx, testAudit(id)); err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{StageRequestReceived, StageResponseReceived} {
					stage := HTTPStage{AuditID: id, Stage: name, StartedAtNS: 2}
					stage.defaults()
					if err := store.submitSync(ctx, writeRequest{kind: writeStartStage, data: stage}); err != nil {
						t.Fatal(err)
					}
				}
			}
			headers := []HTTPHeader{
				{AuditID: "headers-one", Stage: StageRequestReceived, Kind: HeaderKindHeader, Name: "x-test", ValueLength: 1, ValueEnc: []byte{1}},
				{AuditID: "headers-one", Stage: StageResponseReceived, Kind: HeaderKindHeader, Name: "x-test", ValueLength: 1, ValueEnc: []byte{2}},
				{AuditID: "headers-two", Stage: StageRequestReceived, Kind: HeaderKindHeader, Name: "x-test", ValueLength: 1, ValueEnc: []byte{3}},
			}
			headers = append(headers, headers[0]) // Roll back the entire mixed group.
			if err := store.AddHeaders(ctx, headers); err != nil {
				t.Fatal(err)
			}
			if recovery {
				// A failed header write can survive a restart before FinishStage.
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
				var err error
				store, err = Open(ctx, path)
				if err != nil {
					t.Fatal(err)
				}
				defer store.Close()
				if count, err := store.RecoverInterruptedAudits(ctx, 5); err != nil || count != 2 {
					t.Fatalf("recovery = %d, %v", count, err)
				}
			} else {
				for _, id := range []string{"headers-one", "headers-two"} {
					for _, name := range []string{StageRequestReceived, StageResponseReceived} {
						if err := store.FinishStage(ctx, StageFinish{AuditID: id, Stage: name, State: StageStateComplete, EndedAtNS: 4}); err != nil {
							t.Fatal(err)
						}
					}
					if err := store.FinishAudit(ctx, AuditFinish{AuditID: id, EndedAtNS: 5, ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParsePending}); err != nil {
						t.Fatal(err)
					}
				}
			}
			assertTableCount(t, store.readerDB, "http_headers", 0)
			for _, id := range []string{"headers-one", "headers-two"} {
				snapshot, err := store.Snapshot(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				if snapshot.Audit.CaptureStatus != CaptureFailed {
					t.Fatal("lost parent capture failure")
				}
				for _, stage := range snapshot.Stages {
					affected := id == "headers-one" || stage.Stage == StageRequestReceived
					if affected && (stage.State != StageStatePartial || stage.EndedAtNS == nil || stage.ErrorCode == nil || *stage.ErrorCode != "capture_headers_failed") {
						t.Fatal("lost affected stage identity or terminal status")
					}
					if !affected && !recovery && stage.State != StageStateComplete {
						t.Fatal("unaffected stage was downgraded")
					}
				}
			}
		})
	}
}
