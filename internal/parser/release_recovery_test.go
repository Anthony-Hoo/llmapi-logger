package parser

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"llmapi-logger/internal/storage/sqlite"
)

type failingReleaseStore struct {
	*fakeStore
	failures         int32
	applyBeforeError bool
	attempts         atomic.Int32
}

func (store *failingReleaseStore) ReleaseProcessingParse(ctx context.Context, auditID string) error {
	if store.attempts.Add(1) <= store.failures {
		if store.applyBeforeError {
			if err := store.fakeStore.ReleaseProcessingParse(ctx, auditID); err != nil {
				return err
			}
		}
		return errors.New("temporary release failure")
	}
	return store.fakeStore.ReleaseProcessingParse(ctx, auditID)
}

func TestWorkerRecoversFailedReleaseWithoutRestart(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name             string
		failures         int32
		applyBeforeError bool
	}{
		{name: "storage recovers after three failed releases", failures: 3},
		{name: "release committed before acknowledgement failed", failures: 1, applyBeforeError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			const id = "release-recovery"
			cipher := testCipher(t)
			store := &failingReleaseStore{
				fakeStore: newFakeStore(id, "test.parser"),
				failures:  test.failures, applyBeforeError: test.applyBeforeError,
			}
			store.saveFailures = 1
			stage, chunks := encryptedStage(t, cipher, id, sqlite.StageRequestReceived, "application/json", "", []byte(`{}`))
			key := stageKey(id, sqlite.StageRequestReceived)
			store.stages[key], store.chunks[key] = stage, chunks
			worker, err := NewWorker(store, cipher, []Parser{&recordingParser{name: "test.parser"}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			worker.scanInterval = 5 * time.Millisecond
			if err := worker.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			defer worker.Close()
			select {
			case result := <-store.saved:
				if result.Status != StatusOK {
					t.Fatalf("recovered result = %s", result.Status)
				}
			case <-time.After(time.Second):
				t.Fatal("audit stayed processing after storage recovered; pending scans did not retry release")
			}
			worker.Close()
			if got := store.attempts.Load(); got != test.failures+1 {
				t.Fatalf("release attempts = %d, want %d before parsing again", got, test.failures+1)
			}
			store.mu.Lock()
			defer store.mu.Unlock()
			if store.resetCount != 1 || store.saveAttempts != 2 {
				t.Fatalf("recovery reset or reparsed unexpectedly: resets=%d saves=%d", store.resetCount, store.saveAttempts)
			}
		})
	}
}

func TestWorkerBoundsClaimsDuringReleaseOutage(t *testing.T) {
	t.Parallel()
	store := &failingReleaseStore{fakeStore: newFakeStore("queued", "test.parser"), failures: QueueCapacity + 1}
	store.saveFailures = QueueCapacity + 1
	worker, err := NewWorker(store, testCipher(t), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	for i := 0; i < QueueCapacity; i++ {
		id := fmt.Sprintf("release-outage-%d", i)
		audit := store.audits["queued"]
		audit.AuditID = id
		store.audits[id] = audit
		worker.process(context.Background(), id)
	}
	worker.process(context.Background(), "queued")
	if store.audits["queued"].ParseStatus != sqlite.ParsePending || store.saveAttempts != QueueCapacity {
		t.Fatal("worker claimed more audits than its release recovery capacity")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	worker.retryProcessingReleases(ctx)
	if store.attempts.Load() != QueueCapacity {
		t.Fatal("shutdown retried releases instead of leaving recovery to startup")
	}
	store.failures = 0
	worker.retryProcessingReleases(context.Background())
	if len(worker.pendingReleases) != 0 {
		t.Fatal("release backlog remained after storage recovered")
	}
	worker.process(context.Background(), "queued")
	if store.saveAttempts != QueueCapacity+1 {
		t.Fatal("worker did not resume deferred claims after storage recovered")
	}
}
