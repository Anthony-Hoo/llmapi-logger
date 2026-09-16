package audit

import (
	"testing"
	"time"

	"llmapi-logger/internal/storage/sqlite"
	"llmapi-logger/internal/streamtimeline"
)

func TestFinishStageReportsUnsealedTimelineIncomplete(t *testing.T) {
	t.Parallel()
	session := &Session{
		now:           func() time.Time { return time.Unix(0, 400) },
		stages:        make(map[string]*stageCapture),
		forwardStatus: sqlite.ForwardCompleted,
	}
	stage := completedBodyStage(sqlite.StageResponseReceived, "data: a\n\ndata: b\n\ndata: c\n\n")
	stage.body.stream = true
	stage.body.streamEvents = 3
	// A wall-clock step backwards makes the observed points unencodable.
	stage.body.streamPoints = []streamtimeline.Point{{Offset: 10, AtNS: 300}, {Offset: 20, AtNS: 200}, {Offset: 30, AtNS: 250}}
	session.stages[stage.name] = stage

	finish := session.finishStageLocked(stage)
	if finish.Body == nil || finish.Body.Timeline != nil || finish.Body.StreamEventCount != 3 {
		t.Fatalf("unexpected body finish: %+v", finish.Body)
	}
	if finish.Body.StreamTimelineComplete {
		t.Fatal("events without a sealed timeline were reported as a complete timeline")
	}
}
