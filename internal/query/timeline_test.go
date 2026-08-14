package query

import (
	"context"
	"testing"

	"llmapi-logger/internal/bodycodec"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
	"llmapi-logger/internal/streamtimeline"
)

func TestTimelineDecryptsAndVerifiesLogicalEventPoints(t *testing.T) {
	t.Parallel()
	cipher := testCipher(t)
	auditID := "audit-timeline"
	stage := sqlite.StageResponseReceived
	points := []streamtimeline.Point{{Offset: 20, AtNS: 100}, {Offset: 50, AtNS: 110}, {Offset: 90, AtNS: 125}}
	plaintext, err := streamtimeline.Encode(points)
	if err != nil {
		t.Fatal(err)
	}
	compression, encoded, err := bodycodec.Encode(plaintext, "application/x-llmapi-stream-timeline")
	if err != nil {
		t.Fatal(err)
	}
	aad, err := security.AAD(auditID, "stream_timeline_v1", stage, compression)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := cipher.Encrypt(aad, encoded)
	if err != nil {
		t.Fatal(err)
	}
	first, last := points[0].AtNS, points[len(points)-1].AtNS
	store := &fakeStore{healthy: true, timeline: sqlite.StoredStreamTimeline{
		AuditID: auditID, Stage: stage, ObservedLength: 100,
		EventCount: int64(len(points)), FirstEventAtNS: &first, LastEventAtNS: &last,
		Complete: true, Compression: compression, PlaintextLength: int64(len(plaintext)), DataEnc: encrypted,
	}}
	service, err := New(store, cipher)
	if err != nil {
		t.Fatal(err)
	}
	got, err := service.Timeline(context.Background(), auditID, SideResponse)
	if err != nil {
		t.Fatal(err)
	}
	if got.EventCount != 3 || len(got.Points) != 3 || got.Points[2].Offset != 90 || got.Points[2].AtNS != 125 {
		t.Fatalf("timeline = %+v", got)
	}
}

func TestTimelineAllowsBoundedPrefixWhenEventCountExceedsCaptureLimit(t *testing.T) {
	t.Parallel()
	cipher := testCipher(t)
	auditID := "audit-timeline-truncated"
	stage := sqlite.StageResponseReceived
	points := make([]streamtimeline.Point, maxTimelinePoints)
	for index := range points {
		points[index] = streamtimeline.Point{Offset: int64(index + 1), AtNS: int64(1000 + index)}
	}
	plaintext, err := streamtimeline.Encode(points)
	if err != nil {
		t.Fatal(err)
	}
	compression, encoded, err := bodycodec.Encode(plaintext, "application/x-llmapi-stream-timeline")
	if err != nil {
		t.Fatal(err)
	}
	aad, err := security.AAD(auditID, "stream_timeline_v1", stage, compression)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := cipher.Encrypt(aad, encoded)
	if err != nil {
		t.Fatal(err)
	}
	first := points[0].AtNS
	last := points[len(points)-1].AtNS + 7
	store := &fakeStore{healthy: true, timeline: sqlite.StoredStreamTimeline{
		AuditID: auditID, Stage: stage, ObservedLength: int64(maxTimelinePoints + 20),
		EventCount: int64(maxTimelinePoints + 7), FirstEventAtNS: &first, LastEventAtNS: &last,
		Complete: false, Compression: compression, PlaintextLength: int64(len(plaintext)), DataEnc: encrypted,
	}}
	service, err := New(store, cipher)
	if err != nil {
		t.Fatal(err)
	}
	got, err := service.Timeline(context.Background(), auditID, SideResponse)
	if err != nil {
		t.Fatal(err)
	}
	if got.Complete || got.EventCount != int64(maxTimelinePoints+7) || len(got.Points) != maxTimelinePoints ||
		got.Points[len(got.Points)-1].AtNS >= *got.LastEventAtNS {
		t.Fatalf("timeline = events:%d points:%d complete:%v last:%d stored-last:%d",
			got.EventCount, len(got.Points), got.Complete, *got.LastEventAtNS, got.Points[len(got.Points)-1].AtNS)
	}
}
