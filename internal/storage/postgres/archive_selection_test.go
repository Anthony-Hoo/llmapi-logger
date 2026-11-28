package postgres

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/storage"
)

// These tests need a real PostgreSQL (TEST_DATABASE_URL) and skip otherwise.

type candidateView struct {
	id           string
	deferral     string
	current      bool
	nextRevision int64
	turn         bool
}

func viewCandidates(candidates []ArchiveCandidate) []candidateView {
	views := make([]candidateView, 0, len(candidates))
	for _, candidate := range candidates {
		views = append(views, candidateView{candidate.AuditID, candidate.Deferral, candidate.Current, candidate.NextRevision, candidate.ConversationID != nil})
	}
	return views
}

func registerTestIntent(t *testing.T, store *Store, run ArchiveRun, segmentID string, formatVersion int64, members ...ArchiveMember) {
	t.Helper()
	segment := testArchiveSegment(segmentID, run.RunID, "sessions/"+segmentID+".manifest.json", len(members))
	segment.FormatVersion = formatVersion
	if _, err := store.RegisterArchiveIntent(context.Background(), ArchiveIntent{Segment: segment, Members: members}); err != nil {
		t.Fatal(err)
	}
}

// The selection of B.1 in one snapshot: the deferral reasons and their
// precedence, the current member rule, the next revision, paging along the
// watermark (with two audits started at the same time), conversation
// completion behind the watermark, stale re-inclusion and the re-check of
// given audits.
func TestArchiveSelectionQueries(t *testing.T) {
	ctx := context.Background()
	store, _ := openSignedStore(t)
	cipher := graphTestCipher(t)
	ended := func(at int64) *int64 { value := at + 1; return &value }
	for _, audit := range []struct {
		id      string
		started int64
		open    bool
		parse   string
	}{
		{"a1", 100, false, ParseOK}, {"a2", 100, false, ParsePending}, {"a3", 200, false, ParseProcessing},
		{"a4", 300, false, ParseOK}, {"a5", 400, true, ParsePending}, {"a6", 500, false, ParsePending},
		{"a7", 600, false, ParseOK}, {"a8", 700, false, ParseOK}, {"a10", 900, false, ParseOK}, {"a9", 2000, false, ParseOK},
	} {
		var end *int64
		if !audit.open {
			end = ended(audit.started)
		}
		insertRetentionAudit(t, store, audit.id, audit.started, end, audit.parse, false)
	}
	for _, id := range []string{"a4", "a6"} {
		mustExecWriter(t, store, `UPDATE audit_records SET newapi_request_id = 'request-'||audit_id, caller_status = 'pending',
		    caller_next_at_ns = 1, caller_updated_at_ns = 1 WHERE audit_id = $1`, id)
	}
	saveGraphTestTurn(t, store, cipher, "c1", "", "selection-c1", 50, []graphTestItem{userItem("one")}, []graphTestItem{assistantItem("two")})
	saveGraphTestTurn(t, store, cipher, "c2", "selection-c1", "selection-c2", 800,
		[]graphTestItem{userItem("one"), assistantItem("two"), userItem("three")}, []graphTestItem{assistantItem("four")})

	run := testArchiveRun("51000000000000000000000000000001", 10)
	if _, err := store.BeginArchiveRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	wrong := bytes.Repeat([]byte{0x77}, 32)
	// a7: a stale revision 1, then a current revision 2 in a publishing segment.
	registerTestIntent(t, store, run, "52000000000000000000000000000001", 0, testArchiveMember("a7", 1, wrong))
	registerTestIntent(t, store, run, "52000000000000000000000000000002", 0, testArchiveMember("a7", 2, archiveStampOf(t, store, "a7")))
	// a8: sealed, but in a segment of another format version.
	registerTestIntent(t, store, run, "52000000000000000000000000000003", 1, testArchiveMember("a8", 1, archiveStampOf(t, store, "a8")))
	// a10: only a stale member; gone-audit: a stale member of an audit that
	// is no longer in the hot store.
	registerTestIntent(t, store, run, "52000000000000000000000000000004", 0, testArchiveMember("a10", 1, wrong), testArchiveMember("gone-audit", 1, wrong))

	snapshot := openArchiveSnapshot(t, store, cipher)
	page, err := snapshot.Due(nil, 1000, 0, archiveListLimit)
	if err != nil {
		t.Fatal(err)
	}
	want := []candidateView{
		{"c1", "", false, 1, true},
		{"a1", "", false, 1, false},
		{"a2", storage.ArchiveDeferredParsePending, false, 1, false},
		{"a3", storage.ArchiveDeferredParsePending, false, 1, false},
		{"a4", storage.ArchiveDeferredCallerPending, false, 1, false},
		// Open wins over a pending parse.
		{"a5", storage.ArchiveDeferredOpen, false, 1, false},
		// A pending parse wins over a pending caller.
		{"a6", storage.ArchiveDeferredParsePending, false, 1, false},
		{"a7", "", true, 3, false},
		{"a8", "", false, 2, false},
		{"c2", "", false, 1, true},
		{"a10", "", false, 2, false},
	}
	if got := viewCandidates(page.Candidates); !reflect.DeepEqual(got, want) || page.More || page.Last == nil || *page.Last != (ArchivePosition{StartedAtNS: 900, AuditID: "a10"}) {
		t.Fatalf("due page = %+v (more %v, last %+v), want %+v", got, page.More, page.Last, want)
	}
	due := map[string]bool{}
	for _, candidate := range page.Candidates {
		due[candidate.AuditID] = candidate.Due()
		if candidate.AuditID == "c2" && (candidate.TurnCreatedAtNS == nil || *candidate.TurnCreatedAtNS != 800) {
			t.Fatalf("c2 turn time = %v", candidate.TurnCreatedAtNS)
		}
	}
	if !due["a1"] || due["a2"] || due["a7"] || !due["a8"] || !due["a10"] {
		t.Fatalf("due = %v", due)
	}

	// Paging three at a time gives the same sequence; resuming from Last of
	// a page whose last audit shares its start time with the next (a1, a2)
	// loses nothing.
	var paged []candidateView
	var after *ArchivePosition
	for pages := 0; ; pages++ {
		limit := 3
		if pages == 0 {
			limit = 2 // ends on a1, at the same start time as a2
		}
		page, err := snapshot.Due(after, 1000, 0, limit)
		if err != nil {
			t.Fatal(err)
		}
		paged = append(paged, viewCandidates(page.Candidates)...)
		if !page.More {
			break
		}
		after = page.Last
	}
	if !reflect.DeepEqual(paged, want) {
		t.Fatalf("paged = %+v", paged)
	}
	// A watermark at the very end gives an empty page without a position.
	if page, err := snapshot.Due(&ArchivePosition{StartedAtNS: 900, AuditID: "a10"}, 1000, 0, 5); err != nil || len(page.Candidates) != 0 || page.Last != nil || page.More {
		t.Fatalf("page after the end = %+v, %v", page, err)
	}

	// Conversation completion is not limited by a watermark: c1 is behind any
	// watermark that has reached c2.
	conversation := ""
	if err := store.readerDB.QueryRow(`SELECT conversation_id FROM turns WHERE audit_id = 'c2'`).Scan(&conversation); err != nil {
		t.Fatal(err)
	}
	members, err := snapshot.ConversationCandidates([]string{conversation, "conv_unknown"}, 1000, 0)
	if err != nil || !reflect.DeepEqual(viewCandidates(members), []candidateView{{"c1", "", false, 1, true}, {"c2", "", false, 1, true}}) {
		t.Fatalf("conversation candidates = %+v, %v", members, err)
	}
	if members, err := snapshot.ConversationCandidates([]string{conversation}, 500, 0); err != nil || len(members) != 1 || members[0].AuditID != "c1" {
		t.Fatalf("conversation candidates before the cutoff = %+v, %v", members, err)
	}
	// The re-check of given audits leaves out those that are gone.
	again, err := snapshot.Candidates([]string{"a5", "gone-audit", "a1"}, 0)
	if err != nil || !reflect.DeepEqual(viewCandidates(again), []candidateView{{"a1", "", false, 1, false}, {"a5", storage.ArchiveDeferredOpen, false, 1, false}}) {
		t.Fatalf("candidates = %+v, %v", again, err)
	}
	// Stale re-inclusion: a10 only. a7 has a current member, gone-audit is
	// not in the hot store, a8's member is not stale.
	stale, err := snapshot.StaleCandidates(1000, 0, "", 10)
	if err != nil || !reflect.DeepEqual(viewCandidates(stale), []candidateView{{"a10", "", false, 2, false}}) {
		t.Fatalf("stale candidates = %+v, %v", stale, err)
	}
	if stale, err := snapshot.StaleCandidates(1000, 0, "a10", 10); err != nil || len(stale) != 0 {
		t.Fatalf("stale candidates after a10 = %+v, %v", stale, err)
	}
	// Under format version 1, a8 is current and a7 is not.
	page, err = snapshot.Due(&ArchivePosition{StartedAtNS: 599, AuditID: ""}, 750, 1, 10)
	if err != nil || !reflect.DeepEqual(viewCandidates(page.Candidates), []candidateView{{"a7", "", false, 3, false}, {"a8", "", true, 2, false}}) {
		t.Fatalf("due under format 1 = %+v, %v", page.Candidates, err)
	}
}

// The page after a watermark reads only the rows it returns from
// audit_records, through audit_records_started_idx, however many audits lie
// behind the watermark.
func TestArchiveDueQueryStaysOnTheStartedIndex(t *testing.T) {
	store, _ := openTestStore(t)
	seedProcessedAudits(t, store, seededAudits)
	watermark := seededAudits - 10
	scans := explainScans(t, store, archiveDueQuery, int64(0), int64(watermark*1000), fmt.Sprintf("seed-%06d", watermark), int64(seededAudits*1000+5000), 6)
	scan := scans["audit_records"]
	if scan == nil {
		t.Fatalf("plan has no audit_records scan: %v", scans)
	}
	for _, nodeType := range scan.nodeTypes {
		if !strings.Contains(nodeType, "audit_records_started_idx") {
			t.Fatalf("audit_records read by %v", scan.nodeTypes)
		}
	}
	if scan.examined > 6 {
		t.Fatalf("audit_records rows examined = %v, want at most the page", scan.examined)
	}
}

// RegisterArchiveIntent runs on the single writer. Its cost per member is
// measured here for the runner: the stamp is recomputed for every member in
// the writer transaction.
func TestArchiveIntentRegistrationCost(t *testing.T) {
	ctx := context.Background()
	store, _ := openTestStore(t)
	const members = 2000
	seedProcessedAudits(t, store, members)
	run := testArchiveRun("53000000000000000000000000000001", 10)
	if _, err := store.BeginArchiveRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	transaction, err := store.readerDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	intent := ArchiveIntent{Segment: testArchiveSegment("54000000000000000000000000000001", run.RunID, "sessions/cost.manifest.json", members)}
	for index := 1; index <= members; index++ {
		id := fmt.Sprintf("seed-%06d", index)
		stamp, _, err := archiveChangeStamp(ctx, transaction, id)
		if err != nil {
			t.Fatal(err)
		}
		intent.Members = append(intent.Members, testArchiveMember(id, 1, stamp[:]))
	}
	_ = transaction.Rollback()
	started := time.Now()
	result, err := store.RegisterArchiveIntent(ctx, intent)
	elapsed := time.Since(started)
	if err != nil || len(result.Stale) != 0 {
		t.Fatalf("intent: %d stale, %v", len(result.Stale), err)
	}
	t.Logf("RegisterArchiveIntent with %d members: %v (%v per member)", members, elapsed.Round(time.Millisecond), (elapsed / members).Round(time.Microsecond))
}
