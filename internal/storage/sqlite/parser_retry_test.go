package sqlite

import (
	"context"
	"testing"
	"time"
)

func TestParseSaveRetriesBackOffPersistAndEndWithRawEvidence(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, path := openTestStore(t)
	ended := int64(2)
	const id = "parse-save-retry"
	insertRetentionAudit(t, store, id, 1, &ended, ParseProcessing, true)
	for attempt := 1; attempt <= maxParseSaveFailures; attempt++ {
		before := time.Now()
		if err := store.ReleaseProcessingParse(ctx, id); err != nil {
			t.Fatal(err)
		}
		var failures int
		var next *int64
		var status string
		if err := store.readerDB.QueryRow("SELECT parse_save_failures, parse_next_at_ns, parse_status FROM audit_records WHERE audit_id = ?", id).Scan(&failures, &next, &status); err != nil {
			t.Fatal(err)
		}
		if failures != attempt {
			t.Fatalf("failures = %d, want %d", failures, attempt)
		}
		if attempt == maxParseSaveFailures {
			if status != ParseError || next != nil {
				t.Fatalf("terminal retry status = %s, next = %v", status, next)
			}
			break
		}
		delay := 30 * time.Second * time.Duration(1<<(attempt-1))
		if status != ParsePending || next == nil || *next < before.Add(delay).UnixNano() || *next > time.Now().Add(delay).UnixNano() {
			t.Fatalf("retry %d did not schedule %s backoff: %s, %v", attempt, delay, status, next)
		}
		// Recovery must preserve the persisted budget and due time.
		if attempt == 1 {
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			var err error
			store, err = Open(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			if err := store.ResetProcessingParses(ctx); err != nil {
				t.Fatal(err)
			}
		}
		if claimed, err := store.ClaimPendingParse(ctx, id); err != nil || claimed {
			t.Fatalf("notification bypassed backoff: %v, %v", claimed, err)
		}
		if ids, err := store.ListPendingParseIDs(ctx, 10); err != nil || len(ids) != 0 {
			t.Fatalf("scan bypassed backoff: %v, %v", ids, err)
		}
		// Advance only this fixture's scheduling metadata, without wall-clock sleeps.
		if _, err := store.writerDB.Exec("UPDATE audit_records SET parse_next_at_ns = 0 WHERE audit_id = ?", id); err != nil {
			t.Fatal(err)
		}
		if ids, err := store.ListPendingParseIDs(ctx, 10); err != nil || len(ids) != 1 || ids[0] != id {
			t.Fatalf("due retry missing from scan: %v, %v", ids, err)
		}
		if claimed, err := store.ClaimPendingParse(ctx, id); err != nil || !claimed {
			t.Fatalf("due retry could not claim: %v, %v", claimed, err)
		}
	}
	if err := store.ReleaseProcessingParse(ctx, id); err != nil {
		t.Fatal(err)
	}
	if ids, err := store.ListPendingParseIDs(ctx, 10); err != nil || len(ids) != 0 {
		t.Fatalf("terminal failure is still pending: %v, %v", ids, err)
	}
	var code string
	if err := store.readerDB.QueryRow("SELECT error_code FROM parsed_results WHERE audit_id = ?", id).Scan(&code); err != nil || code != "parsed_result_save_failed" {
		t.Fatalf("terminal error code = %q, %v", code, err)
	}
	snapshot, err := store.Snapshot(ctx, id)
	if err != nil || len(snapshot.Chunks) == 0 || len(snapshot.Bodies) == 0 {
		t.Fatalf("terminal failure lost raw evidence: %+v, %v", snapshot, err)
	}
	for _, body := range snapshot.Bodies {
		if body.RetentionState != RetentionFull {
			t.Fatalf("retention = %q, want full", body.RetentionState)
		}
	}
	if snapshot.Audit.ForwardStatus != ForwardCompleted {
		t.Fatal("parser retry changed the forwarding outcome")
	}
}

func TestLateParseReleaseDoesNotUndoSuccessfulSave(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	ended := int64(2)
	insertRetentionAudit(t, store, "late-release", 1, &ended, ParseProcessing, true)
	ctx := context.Background()
	audit, err := store.LoadParserAudit(ctx, "late-release")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveParsedResult(ctx, ParsedResult{AuditID: audit.AuditID, ParserName: audit.ParserName, ParserVersion: "1", Status: ParseOK, ParsedAtNS: 3}); err != nil {
		t.Fatal(err)
	}
	if err := store.ReleaseProcessingParse(ctx, audit.AuditID); err != nil {
		t.Fatal(err)
	}
	var failures int
	var status string
	if err := store.readerDB.QueryRow("SELECT parse_save_failures, parse_status FROM audit_records WHERE audit_id = ?", audit.AuditID).Scan(&failures, &status); err != nil || failures != 0 || status != ParseOK {
		t.Fatalf("late release changed successful save: failures=%d status=%s err=%v", failures, status, err)
	}
}
