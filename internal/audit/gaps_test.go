package audit

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"llmapi-logger/internal/storage/sqlite"
)

func TestGapBufferAggregatesStableReasons(t *testing.T) {
	t.Parallel()

	writer := &fakeGapWriter{}
	times := []time.Time{time.Unix(0, 10), time.Unix(0, 20), time.Unix(0, 30), time.Unix(0, 40)}
	index := 0
	buffer := newGapBuffer(writer, discardGapLogger(), func() time.Time {
		value := times[index]
		index++
		return value
	})
	buffer.record(sqlite.GapReasonWrite)
	buffer.record(sqlite.GapReasonWrite)
	buffer.record(sqlite.GapReasonEncryption)
	if err := buffer.flush(context.Background()); err != nil {
		t.Fatal(err)
	}

	gaps := writer.all()
	if len(gaps) != 2 {
		t.Fatalf("gap count = %d, want 2: %+v", len(gaps), gaps)
	}
	byReason := make(map[string]sqlite.AuditGap, len(gaps))
	for _, gap := range gaps {
		byReason[gap.Reason] = gap
	}
	writeGap := byReason[sqlite.GapReasonWrite]
	if writeGap.RequestCount != 2 || writeGap.StartedAtNS != 10 || writeGap.EndedAtNS != 20 || writeGap.Detail != sqlite.GapDetailWrite {
		t.Fatalf("write gap = %+v", writeGap)
	}
	encryptionGap := byReason[sqlite.GapReasonEncryption]
	if encryptionGap.RequestCount != 1 || encryptionGap.StartedAtNS != 30 || encryptionGap.EndedAtNS != 30 || encryptionGap.Detail != sqlite.GapDetailEncryption {
		t.Fatalf("encryption gap = %+v", encryptionGap)
	}
}

func TestGapBufferMergesFailedFlushBackForRetry(t *testing.T) {
	t.Parallel()

	writer := &fakeGapWriter{failures: 1}
	nowNS := int64(100)
	buffer := newGapBuffer(writer, discardGapLogger(), func() time.Time {
		nowNS++
		return time.Unix(0, nowNS)
	})
	buffer.record(sqlite.GapReasonQueueFull)
	if err := buffer.flush(context.Background()); err == nil {
		t.Fatal("expected first flush failure")
	}
	buffer.record(sqlite.GapReasonQueueFull)
	if err := buffer.flush(context.Background()); err != nil {
		t.Fatal(err)
	}

	gaps := writer.all()
	if len(gaps) != 1 || gaps[0].Reason != sqlite.GapReasonQueueFull || gaps[0].RequestCount != 2 {
		t.Fatalf("retried gaps = %+v", gaps)
	}
}

func TestSessionRecordsAtMostOneGap(t *testing.T) {
	t.Parallel()

	writer := &fakeGapWriter{}
	buffer := newGapBuffer(writer, discardGapLogger(), func() time.Time { return time.Unix(0, 100) })
	session := &Session{gaps: buffer}
	session.recordGapReason(sqlite.GapReasonWrite)
	session.recordGapReason(sqlite.GapReasonEncryption)
	if err := buffer.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	gaps := writer.all()
	if len(gaps) != 1 || gaps[0].Reason != sqlite.GapReasonWrite || gaps[0].RequestCount != 1 {
		t.Fatalf("session gaps = %+v", gaps)
	}
}

type fakeGapWriter struct {
	mu       sync.Mutex
	failures int
	gaps     []sqlite.AuditGap
}

func (writer *fakeGapWriter) InsertAuditGaps(_ context.Context, gaps []sqlite.AuditGap) error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.failures > 0 {
		writer.failures--
		return errors.New("temporary failure")
	}
	writer.gaps = append(writer.gaps, gaps...)
	return nil
}

func (writer *fakeGapWriter) all() []sqlite.AuditGap {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return append([]sqlite.AuditGap(nil), writer.gaps...)
}

func discardGapLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
