package retention

import (
	"context"
	"testing"
	"time"

	"llmapi-logger/internal/storage"
)

// The exported Batcher follows the rules retention's own tests pin: start at
// one, double after a full fast batch, shrink in proportion after a slow one,
// drop to one after a slow failure of several and grow the ceiling back one
// completed run at a time; the pause is as long as the batch, at most 5 s.
func TestBatcherSizesBatchesAsRetentionDoes(t *testing.T) {
	t.Parallel()
	batcher := NewBatcher()
	if batcher.Size() != 1 {
		t.Fatalf("initial size %d", batcher.Size())
	}
	batcher.BeginRun()
	for _, want := range []int{2, 4, 8, 16, 32, 64, 128, storage.RetentionBatchLimit, storage.RetentionBatchLimit} {
		size := batcher.Size()
		batcher.Done(size, size, size, 10*time.Millisecond)
		if batcher.Size() != want {
			t.Fatalf("after a fast full batch of %d: %d, want %d", size, batcher.Size(), want)
		}
	}
	// A batch cut short does not grow the size.
	batcher.SetSize(8)
	batcher.Done(8, 3, 3, time.Millisecond)
	if batcher.Size() != 8 {
		t.Fatalf("short batch grew the size to %d", batcher.Size())
	}
	// 200 at 4 s is four times the target: a quarter.
	batcher.SetSize(200)
	batcher.Done(200, 200, 200, 4*time.Second)
	if batcher.Size() != 50 {
		t.Fatalf("slow batch size %d", batcher.Size())
	}
	batcher.EndRun()

	// A run that fails slowly at size.
	batcher.BeginRun()
	ctx := context.Background()
	if batcher.Failed(ctx, 1, time.Minute) || batcher.Failed(ctx, 50, 10*time.Millisecond) || batcher.Size() != 50 {
		t.Fatalf("a failure not caused by the size changed it to %d", batcher.Size())
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if batcher.Failed(canceled, 50, time.Minute) {
		t.Fatal("a canceled batch reduced the size")
	}
	if !batcher.Failed(ctx, 50, 2*time.Second) || batcher.Size() != 1 {
		t.Fatalf("slow failure left size %d", batcher.Size())
	}
	batcher.SetSize(100)
	if batcher.Size() != 1 {
		t.Fatalf("size %d above the ceiling of one", batcher.Size())
	}
	for _, ceiling := range []int{1, 2, 4} {
		// The run that failed did not complete: the next BeginRun keeps the
		// ceiling; each completed run doubles it.
		batcher.BeginRun()
		batcher.SetSize(1000)
		if batcher.Size() != ceiling {
			t.Fatalf("ceiling %d, want %d", batcher.Size(), ceiling)
		}
		batcher.EndRun()
	}

	for elapsed, want := range map[time.Duration]time.Duration{
		0: 0, 300 * time.Millisecond: 300 * time.Millisecond, 5 * time.Second: 5 * time.Second, time.Minute: MaxBatchPause,
	} {
		if got := PauseAfter(elapsed); got != want {
			t.Fatalf("PauseAfter(%s) = %s, want %s", elapsed, got, want)
		}
	}
}
