package audit

import (
	"crypto/sha256"
	"testing"
	"time"

	"llmapi-logger/internal/storage/sqlite"
)

func TestFinishStageDetectsBodyBoundaryMismatch(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		source    string
		forwarded string
		wantState string
		wantCode  string
	}{
		{name: "equal", source: "same body", forwarded: "same body", wantState: sqlite.StageStateComplete},
		{name: "mismatch", source: "received body", forwarded: "different body", wantState: sqlite.StageStatePartial, wantCode: "body_stage_mismatch"},
	} {
		t.Run(test.name, func(t *testing.T) {
			session := &Session{
				now:           func() time.Time { return time.Unix(0, 100) },
				stages:        make(map[string]*stageCapture),
				forwardStatus: sqlite.ForwardCompleted,
			}
			source := completedBodyStage(sqlite.StageRequestReceived, test.source)
			forwarded := completedBodyStage(sqlite.StageRequestSent, test.forwarded)
			session.stages[source.name] = source
			session.stages[forwarded.name] = forwarded

			finish := session.finishStageLocked(forwarded)
			if finish.State != test.wantState || finish.Body == nil || finish.Body.State != test.wantState {
				t.Fatalf("stage/body state = %q/%v, want %q", finish.State, finish.Body, test.wantState)
			}
			gotCode := ""
			if finish.Body.ErrorCode != nil {
				gotCode = *finish.Body.ErrorCode
			}
			if gotCode != test.wantCode {
				t.Fatalf("body error code = %q, want %q", gotCode, test.wantCode)
			}
			if session.captureFault != (test.wantState == sqlite.StageStatePartial) {
				t.Fatalf("capture fault = %v", session.captureFault)
			}
		})
	}
}

func completedBodyStage(name, value string) *stageCapture {
	digest := sha256.New()
	_, _ = digest.Write([]byte(value))
	return &stageCapture{
		name:        name,
		expectsBody: true,
		body: &bodyCapture{
			digest:         digest,
			persistChunks:  true,
			sourceStage:    name,
			observedLength: int64(len(value)),
			storedLength:   int64(len(value)),
			chunkCount:     1,
			eofSeen:        true,
			hashComplete:   true,
			closed:         true,
			streamComplete: true,
		},
	}
}
