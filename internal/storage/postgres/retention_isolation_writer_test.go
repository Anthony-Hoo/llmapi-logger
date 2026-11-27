package postgres

import (
	"context"
	"testing"
	"time"
)

// failAuditDeletes makes deleting an audit fail with a storage-class error,
// which the writer does not isolate with a savepoint.
func failAuditDeletes(t *testing.T, store *Store) {
	t.Helper()
	for _, statement := range []string{
		`CREATE FUNCTION failing_audit_delete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'simulated storage failure' USING ERRCODE = '58030';
END $$`,
		`CREATE TRIGGER failing_audit_delete BEFORE DELETE ON audit_records FOR EACH ROW EXECUTE FUNCTION failing_audit_delete()`,
	} {
		if _, err := store.writerConn.ExecContext(context.Background(), statement); err != nil {
			t.Fatal(err)
		}
	}
}

// queueBehindBusyWriter holds the writer in one operation, queues the given
// submissions in order behind it and then lets the writer go, so they reach
// the writer together, as they do when it comes back from slow work. It
// returns one result channel per submission.
func queueBehindBusyWriter(t *testing.T, store *Store, submissions ...func() error) []chan error {
	t.Helper()
	entered, release, gateDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		gateDone <- store.submitSync(context.Background(), writeRequest{kind: writeDerived, data: derivedWrite(func(dbTransaction) error {
			close(entered)
			<-release
			return nil
		})})
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("writer did not start the gate operation")
	}
	results := make([]chan error, len(submissions))
	for index, submit := range submissions {
		results[index] = make(chan error, 1)
		go func() { results[index] <- submit() }()
		deadline := time.Now().Add(10 * time.Second)
		for len(store.queue) != index+1 {
			if time.Now().After(deadline) {
				t.Fatalf("submission %d did not reach the writer queue", index)
			}
			time.Sleep(time.Millisecond)
		}
	}
	close(release)
	if err := <-gateDone; err != nil {
		t.Fatal(err)
	}
	return results
}

func auditCount(t *testing.T, store *Store, where string) int {
	t.Helper()
	var count int
	if err := store.readerDB.QueryRow("SELECT COUNT(*) FROM audit_records WHERE " + where).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// A retention batch that fails for a storage reason fails alone: an audit
// write that reached the writer with it, before or after it, must not be
// rolled back with it.
func TestRetentionStorageFailureDoesNotFailQueuedWrites(t *testing.T) {
	t.Parallel()
	for _, retentionFirst := range []bool{false, true} {
		name := "audit write first"
		if retentionFirst {
			name = "retention first"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store, _ := openTestStore(t)
			insertRetentionAudit(t, store, "expired-audit", 1, int64Pointer(2), ParseOK, true)
			failAuditDeletes(t, store)

			submissions := []func() error{
				func() error { return store.BeginAudit(context.Background(), testAudit("live-audit")) },
				func() error {
					_, err := store.DeleteExpired(context.Background(), 10, 1, 0)
					return err
				},
			}
			auditIndex := 0
			if retentionFirst {
				submissions[0], submissions[1] = submissions[1], submissions[0]
				auditIndex = 1
			}
			results := queueBehindBusyWriter(t, store, submissions...)
			if err := <-results[auditIndex]; err != nil {
				t.Fatalf("audit write queued with retention failed: %v", err)
			}
			if err := <-results[1-auditIndex]; err == nil {
				t.Fatal("retention reported no error")
			}
			if auditCount(t, store, "audit_id = 'live-audit'") != 1 || auditCount(t, store, "audit_id = 'expired-audit'") != 1 {
				t.Fatal("the audit write was rolled back with the failed retention batch")
			}
		})
	}
}
