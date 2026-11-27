package parser_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/builtin"
	"llmapi-logger/internal/parser/handover"
	"llmapi-logger/internal/protofixture"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/storage"
)

// Design I.6 and G.4: two turns of one conversation end back to back, and
// the later turn is linked under the earlier one, because the worker parses
// in hand-over order: when both are handed over with plaintext; when the
// earlier one is handed over as an id-only job; and when the earlier one is
// left to the pending scan because the queue was full (the later one, ending
// right after it, finds the queue as full and is left to the scan too, which
// lists audits in start order).
func TestLaterTurnLinksUnderTheEarlierOne(t *testing.T) {
	turns, err := protofixture.Build(protofixture.Case{Protocol: protofixture.OpenAIChat, Scenario: protofixture.ScenarioMultiTurn},
		protofixture.Options{Seed: 5})
	if err != nil {
		t.Fatal(err)
	}
	for _, situation := range []string{"both with plaintext", "earlier id-only", "earlier left to the scan", "control: later parsed first"} {
		t.Run(situation, func(t *testing.T) {
			harness := newFinalizeHarness(t, finalizeStores(t)["sqlite"](t), audit.Options{}, builtin.All())
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			if situation != "earlier left to the scan" {
				if err := harness.worker.Start(ctx); err != nil {
					t.Fatal(err)
				}
			}
			harness.send(harness.handler, turns[0])
			earlier := harness.next()
			harness.send(harness.handler, turns[1])
			later := harness.next()
			if earlier.Evidence == nil || later.Evidence == nil {
				t.Fatal("a turn was handed over without its plaintext")
			}
			switch situation {
			case "both with plaintext":
				submitAll(t, harness.worker, earlier, later)
			case "earlier id-only":
				earlier.Release()
				submitAll(t, harness.worker, handover.Job{Audit: earlier.Audit}, later)
			case "earlier left to the scan":
				for index := range parser.FinalizeQueueCapacity {
					if !harness.worker.Submit(handover.Job{Audit: storage.ParserAudit{AuditID: fmt.Sprintf("filler-%d", index)}}) {
						t.Fatalf("filler %d refused", index)
					}
				}
				if harness.worker.Submit(earlier) || harness.worker.Submit(later) {
					t.Fatal("a full queue took a job")
				}
				if err := harness.worker.Start(ctx); err != nil {
					t.Fatal(err)
				}
				waitFor(t, func() bool { return harness.worker.QueueLength() == 0 })
				harness.worker.ScanForTest(ctx)
			case "control: later parsed first":
				// What G.4 allows when an earlier audit left to the scan is
				// overtaken: the test above would see it.
				submitAll(t, harness.worker, later)
				waitParsed(t, harness.store, later.Audit.AuditID)
				submitAll(t, harness.worker, earlier)
				waitParsed(t, harness.store, earlier.Audit.AuditID)
				if linked(t, harness, earlier.Audit.AuditID, later.Audit.AuditID) {
					t.Fatal("a turn parsed first was linked under one parsed after it")
				}
				return
			}
			waitParsed(t, harness.store, earlier.Audit.AuditID, later.Audit.AuditID)
			if !linked(t, harness, earlier.Audit.AuditID, later.Audit.AuditID) {
				t.Fatal("the later turn is not linked under the earlier one")
			}
		})
	}
}

func submitAll(t *testing.T, worker *parser.Worker, jobs ...handover.Job) {
	t.Helper()
	for _, job := range jobs {
		if !worker.Submit(job) {
			t.Fatalf("audit %s: job refused", job.Audit.AuditID)
		}
	}
}

func waitFor(t *testing.T, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// waitParsed waits until every audit has a terminal parse status.
func waitParsed(t *testing.T, store parser.Store, ids ...string) {
	t.Helper()
	for _, id := range ids {
		waitFor(t, func() bool {
			loaded, err := store.LoadParserAudit(context.Background(), id)
			return err == nil && loaded.ParseStatus != storage.ParsePending && loaded.ParseStatus != storage.ParseProcessing
		})
	}
}

// linked reports whether childID's turn is linked under parentID's.
func linked(t *testing.T, harness *finalizeHarness, parentID, childID string) bool {
	t.Helper()
	queryStore, ok := harness.store.(query.Store)
	if !ok {
		t.Fatal("the store has no query surface")
	}
	service, err := query.New(queryStore, harness.cipher)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := service.Get(context.Background(), parentID, nil)
	if err != nil {
		t.Fatal(err)
	}
	child, err := service.Get(context.Background(), childID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if parent.Turn == nil || child.Turn == nil {
		t.Fatalf("turns %+v and %+v", parent.Turn, child.Turn)
	}
	return child.Turn.ParentTurnID != nil && *child.Turn.ParentTurnID == parent.Turn.TurnID && child.Turn.ConversationID == parent.Turn.ConversationID
}
