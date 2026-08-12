package newapi

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

func TestCallerWorkerRetriesDelayedLogAndResolves(t *testing.T) {
	store := &fakeCallerStore{pending: []sqlite.CallerLookup{{AuditID: "audit-1", RequestID: "req-1"}}}
	lookup := &fakeIdentityLookup{results: []lookupResult{
		{},
		{found: true, identity: RequestIdentity{RequestID: "req-1", UserID: 7, Username: "alice", TokenID: 42, TokenName: "codex"}},
	}}
	worker, err := NewWorker(store, lookup, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(10, 0)
	worker.now = func() time.Time { return base }
	worker.process(context.Background(), store.pending[0])
	if len(store.retries) != 1 || store.retries[0].Attempts != 1 || store.retries[0].NextAttemptAtNS == nil {
		t.Fatalf("retries = %+v", store.retries)
	}
	item := store.pending[0]
	item.Attempts = 1
	worker.process(context.Background(), item)
	if len(store.links) != 1 || store.links[0].NewAPIUserID != 7 || store.links[0].NewAPITokenID != 42 || store.links[0].Attempts != 2 {
		t.Fatalf("links = %+v", store.links)
	}
}

func TestCallerWorkerStopsAfterBoundedAttempts(t *testing.T) {
	store := &fakeCallerStore{}
	worker, _ := NewWorker(store, &fakeIdentityLookup{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	worker.now = func() time.Time { return time.Unix(20, 0) }
	worker.process(context.Background(), sqlite.CallerLookup{AuditID: "audit", RequestID: "req", Attempts: len(retryDelays)})
	if len(store.retries) != 1 || store.retries[0].Attempts != len(retryDelays)+1 || store.retries[0].NextAttemptAtNS != nil {
		t.Fatalf("terminal retry = %+v", store.retries)
	}
}

func TestCallerWorkerUsesFinalThirtySecondRetry(t *testing.T) {
	store := &fakeCallerStore{}
	worker, _ := NewWorker(store, &fakeIdentityLookup{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	base := time.Unix(25, 0)
	worker.now = func() time.Time { return base }
	worker.process(context.Background(), sqlite.CallerLookup{
		AuditID: "audit", RequestID: "req", Attempts: len(retryDelays) - 1,
	})
	if len(store.retries) != 1 || store.retries[0].Attempts != len(retryDelays) || store.retries[0].NextAttemptAtNS == nil {
		t.Fatalf("final scheduled retry = %+v", store.retries)
	}
	want := base.Add(30 * time.Second).UnixNano()
	if *store.retries[0].NextAttemptAtNS != want {
		t.Fatalf("next attempt = %d, want %d", *store.retries[0].NextAttemptAtNS, want)
	}
}

func TestCallerWorkerPersistsRetryForLookupError(t *testing.T) {
	store := &fakeCallerStore{}
	lookup := &fakeIdentityLookup{results: []lookupResult{{err: errors.New("temporary")}}}
	worker, _ := NewWorker(store, lookup, slog.New(slog.NewTextHandler(io.Discard, nil)))
	worker.now = func() time.Time { return time.Unix(30, 0) }
	worker.process(context.Background(), sqlite.CallerLookup{AuditID: "audit", RequestID: "req"})
	if len(store.retries) != 1 || store.retries[0].NextAttemptAtNS == nil {
		t.Fatalf("retry = %+v", store.retries)
	}
}

type lookupResult struct {
	identity RequestIdentity
	found    bool
	err      error
}

type fakeIdentityLookup struct {
	mu      sync.Mutex
	results []lookupResult
}

func (lookup *fakeIdentityLookup) LookupRequest(context.Context, string) (RequestIdentity, bool, error) {
	lookup.mu.Lock()
	defer lookup.mu.Unlock()
	if len(lookup.results) == 0 {
		return RequestIdentity{}, false, nil
	}
	result := lookup.results[0]
	lookup.results = lookup.results[1:]
	return result.identity, result.found, result.err
}

type fakeCallerStore struct {
	mu      sync.Mutex
	pending []sqlite.CallerLookup
	links   []sqlite.TokenLink
	retries []sqlite.CallerRetry
}

func (store *fakeCallerStore) ListDueCallerLookups(context.Context, int64, int) ([]sqlite.CallerLookup, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return append([]sqlite.CallerLookup(nil), store.pending...), nil
}

func (store *fakeCallerStore) UpsertTokenLink(_ context.Context, link sqlite.TokenLink) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.links = append(store.links, link)
	return nil
}

func (store *fakeCallerStore) RetryCallerLookup(_ context.Context, retry sqlite.CallerRetry) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.retries = append(store.retries, retry)
	return nil
}
