package postgres

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"
	"time"

	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/uaguard"
)

// heldWriter returns a Store that shares the real connections of store but
// whose queue nobody drains yet, so a test can cancel the caller while its
// write is admitted and still pending. No timing assumption about batching.
func heldWriter(store *Store) *Store {
	return &Store{writerDB: store.writerDB, writerConn: store.writerConn, readerDB: store.readerDB, queue: make(chan writeRequest, 1), done: make(chan struct{})}
}

// releaseHeld cancels nothing itself: the caller has already cancelled. It
// asserts the admitted write has not returned yet, then lets the real writer
// run it and returns what the caller finally received.
func releaseHeld(t *testing.T, writer *Store, done <-chan error) error {
	t.Helper()
	var request writeRequest
	select {
	case request = <-writer.queue:
	case <-time.After(storeWait):
		t.Fatal("write was not queued")
	}
	select {
	case err := <-done:
		t.Fatalf("admitted write returned before a definitive result: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	writer.queue <- request
	close(writer.queue)
	go writer.runWriter()
	select {
	case err := <-done:
		<-writer.done
		return err
	case <-time.After(storeWait):
		t.Fatal("admitted write hung")
		return nil
	}
}

// A user-agent rule change takes effect on live traffic the moment the service
// publishes it. Before, a request cancelled after admission got an error while
// the row was written anyway, leaving the database and the enforced rules
// apart until restart and inviting a retry that created a duplicate rule.
func TestAdmittedUserAgentRuleWritesPublishDespiteCallerCancellation(t *testing.T) {
	for _, operation := range []string{"create", "update", "delete"} {
		t.Run(operation, func(t *testing.T) {
			ctx := context.Background()
			store, _ := openTestStore(t)
			writer := heldWriter(store)
			service, err := uaguard.New(ctx, writer)
			if err != nil {
				t.Fatal(err)
			}
			before := service.List()
			if len(before) != 1 {
				t.Fatalf("a fresh store must hold the default rule, got %+v", before)
			}

			requestCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				input := uaguard.RuleInput{Name: "new", Enabled: true, ModelPattern: "^model", UserAgentPattern: "^client"}
				var err error
				switch operation {
				case "create":
					_, err = service.Create(requestCtx, input)
				case "update":
					_, err = service.Update(requestCtx, before[0].ID, input)
				case "delete":
					err = service.Delete(requestCtx, before[0].ID)
				}
				done <- err
			}()
			// Cancel only once the write is known to be admitted.
			deadline := time.After(storeWait)
			for len(writer.queue) == 0 {
				select {
				case <-deadline:
					t.Fatal("write was not queued")
				default:
					time.Sleep(time.Millisecond)
				}
			}
			cancel()
			if err := releaseHeld(t, writer, done); err != nil {
				t.Fatalf("admitted %s returned %v, want the definitive nil", operation, err)
			}

			persisted, err := store.ListUserAgentRules(ctx)
			if err != nil {
				t.Fatal(err)
			}
			// A nil and an empty list are the same outcome after a delete.
			if enforced := service.List(); len(enforced) != len(persisted) || (len(persisted) != 0 && !reflect.DeepEqual(enforced, persisted)) {
				t.Fatalf("enforced rules %+v differ from the database %+v", enforced, persisted)
			}
			want := map[string]int{"create": 2, "update": 1, "delete": 0}[operation]
			if len(persisted) != want {
				t.Fatalf("%s left %d rules, want %d: %+v", operation, len(persisted), want, persisted)
			}
		})
	}
}

// The administrator actions below cannot be undone: a dismissed suggestion
// stays dismissed, the latest calibration decides which fields reports hide,
// and a regenerated week replaces its snapshot. Their caller must receive what
// really happened, not an early context error.
func TestAdmittedAdministratorWritesReturnTheDefinitiveResult(t *testing.T) {
	cases := []struct {
		name  string
		write func(context.Context, *Store) error
		check func(*testing.T, *Store, error)
	}{
		{
			name: "facet calibration",
			write: func(ctx context.Context, writer *Store) error {
				return writer.SaveFacetCalibration(ctx, storage.FacetCalibration{CreatedAtNS: 1, PromptVersion: "facet-v1", Model: "m", Samples: 1, Agreement: "{}"})
			},
			check: func(t *testing.T, store *Store, err error) {
				if err != nil {
					t.Fatalf("calibration returned %v, want nil", err)
				}
				assertTableCount(t, store.readerDB, "facet_calibrations", 1)
			},
		},
		{
			name: "dismiss a missing suggestion",
			write: func(ctx context.Context, writer *Store) error {
				return writer.DismissSuggestion(ctx, 404, storage.ScopeAll, 1)
			},
			check: func(t *testing.T, _ *Store, err error) {
				// The definitive answer is "no such suggestion", not "cancelled".
				if !errors.Is(err, sql.ErrNoRows) {
					t.Fatalf("dismiss returned %v, want sql.ErrNoRows", err)
				}
			},
		},
		{
			name: "weekly snapshot",
			write: func(ctx context.Context, writer *Store) error {
				return writer.SaveWeeklySnapshot(ctx, orgreport.WeeklySnapshot{Week: "2026-08-10", FrozenAtNS: 1, GeneratedAtNS: 1})
			},
			check: func(t *testing.T, store *Store, err error) {
				if err != nil {
					t.Fatalf("snapshot returned %v, want nil", err)
				}
				assertTableCount(t, store.readerDB, "org_weekly_snapshots", 1)
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			store, _ := openTestStore(t)
			writer := heldWriter(store)
			requestCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- test.write(requestCtx, writer) }()
			deadline := time.After(storeWait)
			for len(writer.queue) == 0 {
				select {
				case <-deadline:
					t.Fatal("write was not queued")
				default:
					time.Sleep(time.Millisecond)
				}
			}
			cancel()
			test.check(t, store, releaseHeld(t, writer, done))
		})
	}
}
