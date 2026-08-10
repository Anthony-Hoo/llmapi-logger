package sqlite

import (
	"context"
	"testing"
)

func TestInsertAuditGapsAcceptsOnlyStableReasonDetailPairs(t *testing.T) {
	t.Parallel()

	store, _ := openTestStore(t)
	ctx := context.Background()
	gaps := []AuditGap{
		{StartedAtNS: 1, EndedAtNS: 2, Reason: GapReasonQueueFull, RequestCount: 3, Detail: GapDetailQueueFull, CreatedAtNS: 3},
		{StartedAtNS: 4, EndedAtNS: 5, Reason: GapReasonWrite, RequestCount: 1, Detail: GapDetailWrite, CreatedAtNS: 6},
	}
	if err := store.InsertAuditGaps(ctx, gaps); err != nil {
		t.Fatal(err)
	}

	var count, total int
	if err := store.readerDB.QueryRow("SELECT COUNT(*), SUM(request_count) FROM audit_gaps").Scan(&count, &total); err != nil {
		t.Fatal(err)
	}
	if count != 2 || total != 4 {
		t.Fatalf("gap count=%d total=%d, want 2 and 4", count, total)
	}

	invalid := []AuditGap{
		{StartedAtNS: 1, EndedAtNS: 2, Reason: "dial tcp secret.internal", RequestCount: 1, Detail: GapDetailWrite, CreatedAtNS: 3},
		{StartedAtNS: 1, EndedAtNS: 2, Reason: GapReasonWrite, RequestCount: 1, Detail: "disk error: secret", CreatedAtNS: 3},
		{StartedAtNS: 2, EndedAtNS: 1, Reason: GapReasonWrite, RequestCount: 1, Detail: GapDetailWrite, CreatedAtNS: 3},
	}
	for index, gap := range invalid {
		if err := store.InsertAuditGaps(ctx, []AuditGap{gap}); err == nil {
			t.Fatalf("invalid gap %d was accepted", index)
		}
	}
	if err := store.readerDB.QueryRow("SELECT COUNT(*) FROM audit_gaps").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("invalid gaps changed row count to %d", count)
	}
}
