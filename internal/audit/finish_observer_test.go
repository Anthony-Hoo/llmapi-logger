package audit

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

// TestFinishObserverSeesEachSessionOnce: the observer cmd/audit-bench sets
// gets one duration per session, from the call that did the work, and
// Finish's result is unchanged.
func TestFinishObserverSeesEachSessionOnce(t *testing.T) {
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{5}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	store, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "observer.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	manager, err := NewManagerWithOptions(store, cipher, nil, ModeAvailable, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var seen []time.Duration
	SetFinishObserver(func(duration time.Duration) {
		mu.Lock()
		seen = append(seen, duration)
		mu.Unlock()
	})
	t.Cleanup(func() { SetFinishObserver(nil) })
	session := driveStream(t, manager, []byte(`{"model":"model-example","stream":true}`), sseBody(64<<10, 1))
	if err := session.Finish(); err != nil {
		t.Fatal(err)
	}
	if err := session.Finish(); err != nil {
		t.Fatal(err)
	}
	SetFinishObserver(nil)
	other := driveStream(t, manager, []byte(`{"model":"model-example","stream":true}`), sseBody(1<<10, 2))
	if err := other.Finish(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0] <= 0 {
		t.Fatalf("observed %v, want one positive duration", seen)
	}
}
