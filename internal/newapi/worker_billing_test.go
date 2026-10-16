package newapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"llmapi-logger/internal/storage/sqlite"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func statusPointer(value int) *int { return &value }

func billedLog(quota int64) RequestLog {
	return RequestLog{
		RequestID: "req", UserID: 7, Username: "alice", TokenID: 42, TokenName: "codex",
		ConsumeRows: 1, Quota: quota, PromptTokens: 100, CompletionTokens: 20, Complete: true,
	}
}

func errorOnlyLog() RequestLog {
	return RequestLog{RequestID: "req", UserID: 7, Username: "alice", TokenID: 42, TokenName: "codex", Complete: true}
}

func TestCallerWorkerWritesActualBillingWithIdentity(t *testing.T) {
	store := &fakeCallerStore{}
	lookup := &fakeIdentityLookup{quotaPerUnit: 500000, results: []lookupResult{{found: true, record: billedLog(250000)}}}
	worker, _ := NewWorker(store, lookup, quietLogger())
	worker.now = func() time.Time { return time.Unix(40, 0) }
	worker.process(context.Background(), sqlite.CallerLookup{AuditID: "audit", RequestID: "req", StatusCode: statusPointer(200)})
	if len(store.links) != 1 || len(store.retries) != 0 {
		t.Fatalf("links=%+v retries=%+v", store.links, store.retries)
	}
	link := store.links[0]
	if link.BillingState != sqlite.BillingBilled || *link.Quota != 250000 || *link.QuotaPerUnit != 500000 ||
		*link.BilledPromptTokens != 100 || *link.BilledCompletionTokens != 20 || link.NewAPIUserID != 7 {
		t.Fatalf("link = %+v", link)
	}
}

func TestCallerWorkerRetriesErrorOnlyLogAfterSuccessfulResponse(t *testing.T) {
	store := &fakeCallerStore{}
	lookup := &fakeIdentityLookup{quotaPerUnit: 500000, results: []lookupResult{
		{found: true, record: errorOnlyLog()},
		{found: true, record: billedLog(1000)},
	}}
	worker, _ := NewWorker(store, lookup, quietLogger())
	worker.now = func() time.Time { return time.Unix(50, 0) }
	item := sqlite.CallerLookup{AuditID: "audit", RequestID: "req", StatusCode: statusPointer(200)}
	worker.process(context.Background(), item)
	if len(store.links) != 0 || len(store.retries) != 1 || store.retries[0].NextAttemptAtNS == nil {
		t.Fatalf("error-only 2xx must retry: links=%+v retries=%+v", store.links, store.retries)
	}
	item.Attempts = 1
	worker.process(context.Background(), item)
	if len(store.links) != 1 || store.links[0].BillingState != sqlite.BillingBilled || *store.links[0].Quota != 1000 {
		t.Fatalf("links = %+v", store.links)
	}
}

func TestCallerWorkerErrorOnlyLogIsUnbilledForFailedResponseOrLastAttempt(t *testing.T) {
	for name, item := range map[string]sqlite.CallerLookup{
		"non-2xx":      {AuditID: "audit", RequestID: "req", StatusCode: statusPointer(502)},
		"no status":    {AuditID: "audit", RequestID: "req"},
		"last attempt": {AuditID: "audit", RequestID: "req", StatusCode: statusPointer(200), Attempts: len(retryDelays)},
	} {
		t.Run(name, func(t *testing.T) {
			store := &fakeCallerStore{}
			lookup := &fakeIdentityLookup{quotaPerUnit: 500000, results: []lookupResult{{found: true, record: errorOnlyLog()}}}
			worker, _ := NewWorker(store, lookup, quietLogger())
			worker.now = func() time.Time { return time.Unix(60, 0) }
			worker.process(context.Background(), item)
			if len(store.retries) != 0 || len(store.links) != 1 {
				t.Fatalf("links=%+v retries=%+v", store.links, store.retries)
			}
			link := store.links[0]
			if link.BillingState != sqlite.BillingUnbilled || link.Quota != nil || link.Username != "alice" {
				t.Fatalf("link = %+v", link)
			}
		})
	}
}

func TestCallerWorkerRetriesWhenQuotaPerUnitIsMissing(t *testing.T) {
	store := &fakeCallerStore{}
	lookup := &fakeIdentityLookup{results: []lookupResult{{found: true, record: billedLog(1000)}, {found: true, record: billedLog(1000)}}}
	worker, _ := NewWorker(store, lookup, quietLogger())
	worker.now = func() time.Time { return time.Unix(70, 0) }
	item := sqlite.CallerLookup{AuditID: "audit", RequestID: "req", StatusCode: statusPointer(200)}
	worker.process(context.Background(), item)
	if len(store.links) != 0 || len(store.retries) != 1 || store.retries[0].NextAttemptAtNS == nil {
		t.Fatalf("missing rate must retry without a link: links=%+v retries=%+v", store.links, store.retries)
	}
	// The final attempt keeps the identity rather than dropping it, without
	// inventing a conversion factor.
	item.Attempts = len(retryDelays)
	worker.process(context.Background(), item)
	if len(store.links) != 1 || store.links[0].BillingState != sqlite.BillingUnbilled || store.links[0].QuotaPerUnit != nil {
		t.Fatalf("final link = %+v", store.links)
	}
}

func TestBillingBackfillRecordsResultsWithoutTouchingCallers(t *testing.T) {
	store := &fakeCallerStore{unchecked: []sqlite.BillingBackfillItem{
		{AuditID: "new", RequestID: "req-new"},
		{AuditID: "mid", RequestID: "req-mid"},
		{AuditID: "old", RequestID: "req-old"},
	}}
	lookup := &fakeIdentityLookup{quotaPerUnit: 400000, results: []lookupResult{
		{found: true, record: billedLog(800000)},
		{found: true, record: errorOnlyLog()},
		{found: false},
	}}
	worker, _ := NewWorker(store, lookup, quietLogger())
	for index := 0; index < 3; index++ {
		delay, more := worker.backfillStep(context.Background())
		if !more || delay != backfillInterval {
			t.Fatalf("step %d = %v %v", index, delay, more)
		}
	}
	if _, more := worker.backfillStep(context.Background()); more {
		t.Fatal("backfill must stop when no unchecked link is left")
	}
	if len(store.updates) != 3 || len(store.links) != 0 || len(store.retries) != 0 {
		t.Fatalf("updates=%+v links=%+v retries=%+v", store.updates, store.links, store.retries)
	}
	billed := store.updates[0]
	if billed.AuditID != "new" || billed.State != sqlite.BillingBilled || *billed.Quota != 800000 || *billed.QuotaPerUnit != 400000 || billed.Attempts != 1 {
		t.Fatalf("billed = %+v", billed)
	}
	if store.updates[1].State != sqlite.BillingUnbilled || store.updates[2].State != sqlite.BillingUnbilled {
		t.Fatalf("error-only and missing logs must be unbilled: %+v", store.updates)
	}
	if got := lookup.calls; len(got) != 3 || got[0] != "req-new" || got[2] != "req-old" {
		t.Fatalf("lookup order = %v", got)
	}
}

func TestBillingBackfillStopsAfterThreeFailuresAndPauses(t *testing.T) {
	store := &fakeCallerStore{unchecked: []sqlite.BillingBackfillItem{{AuditID: "audit", RequestID: "req"}}}
	failure := errors.New("temporary")
	lookup := &fakeIdentityLookup{quotaPerUnit: 500000, results: []lookupResult{
		{err: failure},
		{found: true, record: billedLog(5)}, // counts as a failure: rate cleared below
		{err: failure},
	}}
	worker, _ := NewWorker(store, lookup, quietLogger())

	delay, more := worker.backfillStep(context.Background())
	if !more || delay != backfillInterval || store.updates[0].State != sqlite.BillingUnchecked || store.updates[0].Attempts != 1 {
		t.Fatalf("first failure = %v %v %+v", delay, more, store.updates)
	}
	lookup.mu.Lock()
	lookup.quotaPerUnit = 0
	lookup.mu.Unlock()
	delay, more = worker.backfillStep(context.Background())
	if !more || delay != backfillPause || store.updates[1].State != sqlite.BillingUnchecked || store.updates[1].Attempts != 2 {
		t.Fatalf("consecutive failure must pause: %v %v %+v", delay, more, store.updates)
	}
	delay, more = worker.backfillStep(context.Background())
	if !more || delay != backfillPause || store.updates[2].State != sqlite.BillingUnbilled || store.updates[2].Attempts != sqlite.MaxBillingAttempts {
		t.Fatalf("third failure must give up as unbilled: %v %v %+v", delay, more, store.updates)
	}
	if len(store.unchecked) != 0 || len(store.links) != 0 || len(store.retries) != 0 {
		t.Fatalf("backfill touched callers: %+v %+v %+v", store.unchecked, store.links, store.retries)
	}
}

func TestBillingBackfillRunsAfterDueCallersAndStopsOnClose(t *testing.T) {
	store := &fakeCallerStore{unchecked: []sqlite.BillingBackfillItem{{AuditID: "a", RequestID: "req-a"}, {AuditID: "b", RequestID: "req-b"}}}
	lookup := &fakeIdentityLookup{quotaPerUnit: 500000, results: []lookupResult{{found: true, record: billedLog(1)}, {found: true, record: billedLog(2)}}}
	worker, _ := NewWorker(store, lookup, quietLogger())
	worker.scanInterval = time.Hour
	timers := make(chan chan time.Time, 8)
	var delays []time.Duration
	delayCh := make(chan time.Duration, 8)
	worker.after = func(delay time.Duration) <-chan time.Time {
		fire := make(chan time.Time, 1)
		delayCh <- delay
		timers <- fire
		return fire
	}
	if err := worker.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	fire := func() {
		t.Helper()
		select {
		case timer := <-timers:
			delays = append(delays, <-delayCh)
			timer <- time.Unix(0, 0)
		case <-time.After(5 * time.Second):
			t.Fatal("backfill timer was not armed")
		}
	}
	fire() // first backfill step
	fire() // second backfill step
	fire() // finds nothing left and stops arming the timer
	deadline := time.Now().Add(5 * time.Second)
	for {
		store.mu.Lock()
		done := len(store.events) > 0 && store.events[len(store.events)-1] == "backfill" && len(store.unchecked) == 0 && countEvents(store.events, "backfill") == 3
		store.mu.Unlock()
		if done || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	worker.Close()

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.updates) != 2 || store.updates[0].AuditID != "a" || store.updates[1].AuditID != "b" {
		t.Fatalf("updates = %+v", store.updates)
	}
	// Every backfill step is preceded by a scan for due caller lookups.
	for index, event := range store.events {
		if event == "backfill" && (index == 0 || store.events[index-1] != "scan") {
			t.Fatalf("backfill ran before due callers: %v", store.events)
		}
	}
	if len(delays) != 3 || delays[0] != backfillInterval || delays[1] != backfillInterval {
		t.Fatalf("delays = %v", delays)
	}
	select {
	case <-timers:
		t.Fatal("timer armed after the backfill finished")
	default:
	}
}

func countEvents(events []string, name string) int {
	count := 0
	for _, event := range events {
		if event == name {
			count++
		}
	}
	return count
}

func TestBillingBackfillStopsWhenClosedWhilePaused(t *testing.T) {
	store := &fakeCallerStore{unchecked: []sqlite.BillingBackfillItem{{AuditID: "a", RequestID: "req-a"}}}
	worker, _ := NewWorker(store, &fakeIdentityLookup{}, quietLogger())
	worker.scanInterval = time.Hour
	armed := make(chan struct{}, 1)
	worker.after = func(time.Duration) <-chan time.Time {
		armed <- struct{}{}
		return make(chan time.Time) // never fires
	}
	if err := worker.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-armed
	closed := make(chan struct{})
	go func() {
		worker.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not stop a waiting backfill")
	}
	if len(store.updates) != 0 {
		t.Fatalf("updates = %+v", store.updates)
	}
}
