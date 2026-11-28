package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"llmapi-logger/internal/storage"
)

// These tests need a real PostgreSQL (TEST_DATABASE_URL) and skip otherwise.

// sealRemovableSegment registers and seals a segment of format version
// version whose members are the audits with their current change stamps, and
// returns the removal requests for them.
func sealRemovableSegment(t *testing.T, store *Store, run ArchiveRun, segmentID string, version int64, revision int64, auditIDs ...string) []ArchiveRemoval {
	t.Helper()
	var members []ArchiveMember
	var removals []ArchiveRemoval
	for _, id := range auditIDs {
		stamp := archiveStampOf(t, store, id)
		members = append(members, ArchiveMember{AuditID: id, Revision: revision, RecordDigest: bytes.Repeat([]byte{0x55}, 32),
			ChangeStamp: stamp, StartedAtNS: 1, StateChangedAtNS: 3000})
		removals = append(removals, ArchiveRemoval{SegmentID: segmentID, AuditID: id, Revision: revision, ChangeStamp: stamp})
	}
	registerTestIntent(t, store, run, segmentID, version, members...)
	if err := store.SealArchiveSegment(context.Background(), ArchiveSeal{SegmentID: segmentID, ManifestSHA256: bytes.Repeat([]byte{0x66}, 32),
		DiskBytes: 1, SealedAtNS: 4000}); err != nil {
		t.Fatal(err)
	}
	return removals
}

func auditExists(t *testing.T, store *Store, auditID string) bool {
	t.Helper()
	var exists bool
	if err := store.readerDB.QueryRow(`SELECT EXISTS (SELECT 1 FROM audit_records WHERE audit_id = $1)`, auditID).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	return exists
}

func memberState(t *testing.T, store *Store, auditID string, revision int64) (string, int64) {
	t.Helper()
	var state string
	var changed int64
	if err := store.readerDB.QueryRow(`SELECT state, state_changed_at_ns FROM archive_members WHERE audit_id = $1 AND revision = $2`,
		auditID, revision).Scan(&state, &changed); err != nil {
		t.Fatalf("member %s/%d: %v", auditID, revision, err)
	}
	return state, changed
}

func segmentState(t *testing.T, store *Store, segmentID string) (string, sql.NullInt64) {
	t.Helper()
	var state string
	var removed sql.NullInt64
	if err := store.readerDB.QueryRow(`SELECT state, removed_at_ns FROM archive_segments WHERE segment_id = $1`, segmentID).Scan(&state, &removed); err != nil {
		t.Fatal(err)
	}
	return state, removed
}

// auditRowCounts counts the audit's rows in every per-audit table of the
// change stamp.
func auditRowCounts(t *testing.T, store *Store, auditID string) map[string]int {
	t.Helper()
	counts := map[string]int{}
	for _, table := range archiveStampTables {
		query := `SELECT COUNT(*) FROM ` + table.name + ` WHERE audit_id = $1`
		if table.byTurn {
			query = `SELECT COUNT(*) FROM ` + table.name + ` AS r JOIN turns AS t ON t.turn_id = r.turn_id WHERE t.audit_id = $1`
		}
		var count int
		if err := store.readerDB.QueryRow(query, auditID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		counts[table.name] = count
	}
	return counts
}

func outcomesOf(result ArchiveRemovalResult) map[string]string {
	out := map[string]string{}
	for _, outcome := range result.Outcomes {
		out[outcome.AuditID] = outcome.Outcome
	}
	return out
}

// M.2 step 1, the format gate and the idempotence point: only sealed members
// of sealed segments of format version 1 or later whose row matches the
// request are considered. A trial (version 0) segment, a publishing segment,
// a request whose stamp, revision or segment differs and a repeated batch
// change nothing. A member whose audit is gone is marked hot_removed; the
// others are deleted with deleteAuditBatch, marked hot_removed with the time
// given, and their segment once nothing in it is sealed.
func TestRemoveArchivedDeletesOnlyVerifiedMembers(t *testing.T) {
	ctx := context.Background()
	store, _ := openSignedStore(t)
	for index, id := range []string{"rm-trial", "rm-publishing", "rm-a", "rm-b", "rm-gone", "rm-wrong"} {
		ended := int64(101 + index*10)
		insertRetentionAudit(t, store, id, int64(100+index*10), &ended, ParseOK, true)
	}
	run := testArchiveRun("52000000000000000000000000000001", 10)
	if _, err := store.BeginArchiveRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	trial := sealRemovableSegment(t, store, run, "52000000000000000000000000000010", 0, 1, "rm-trial")
	publishingStamp := archiveStampOf(t, store, "rm-publishing")
	registerTestIntent(t, store, run, "52000000000000000000000000000011", 1, ArchiveMember{AuditID: "rm-publishing", Revision: 1,
		RecordDigest: bytes.Repeat([]byte{0x55}, 32), ChangeStamp: publishingStamp, StartedAtNS: 1, StateChangedAtNS: 3000})
	current := sealRemovableSegment(t, store, run, "52000000000000000000000000000012", 1, 1, "rm-a", "rm-b", "rm-gone", "rm-wrong")

	listed, err := store.ListRemovableArchiveMembers(ctx, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	var listedIDs []string
	for _, member := range listed {
		listedIDs = append(listedIDs, member.AuditID)
		if member.SegmentID != "52000000000000000000000000000012" || member.Revision != 1 || len(member.ChangeStamp) != 32 {
			t.Fatalf("listed %+v", member)
		}
	}
	if want := []string{"rm-a", "rm-b", "rm-gone", "rm-wrong"}; !reflect.DeepEqual(listedIDs, want) {
		t.Fatalf("removable %v, want %v", listedIDs, want)
	}
	if page, err := store.ListRemovableArchiveMembers(ctx, &ArchiveMemberKey{AuditID: "rm-b", Revision: 1}, 1); err != nil || len(page) != 1 || page[0].AuditID != "rm-gone" {
		t.Fatalf("second page %+v, %v", page, err)
	}

	mustExecWriter(t, store, `DELETE FROM audit_records WHERE audit_id = 'rm-gone'`)
	trialRows := auditRowCounts(t, store, "rm-trial")
	batch := append(append([]ArchiveRemoval{}, trial...), ArchiveRemoval{SegmentID: "52000000000000000000000000000011", AuditID: "rm-publishing", Revision: 1, ChangeStamp: publishingStamp})
	wrong := current[3]
	wrong.ChangeStamp = bytes.Repeat([]byte{0x01}, 32)
	batch = append(batch, current[0], current[1], current[2], wrong)
	result, err := store.RemoveArchived(ctx, batch, 5000)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"rm-trial": storage.ArchiveRemovalSkipped, "rm-publishing": storage.ArchiveRemovalSkipped,
		"rm-a": storage.ArchiveRemovalRemoved, "rm-b": storage.ArchiveRemovalRemoved,
		"rm-gone": storage.ArchiveRemovalAlreadyGone, "rm-wrong": storage.ArchiveRemovalSkipped,
	}
	if got := outcomesOf(result); !reflect.DeepEqual(got, want) || len(result.Outcomes) != len(batch) || result.RemovedSegments != 0 {
		t.Fatalf("outcomes %v (%+v), want %v", got, result, want)
	}
	for index, outcome := range result.Outcomes {
		if outcome.AuditID != batch[index].AuditID {
			t.Fatalf("outcome %d is %s, request order %s", index, outcome.AuditID, batch[index].AuditID)
		}
	}
	for id, exists := range map[string]bool{"rm-trial": true, "rm-publishing": true, "rm-wrong": true, "rm-a": false, "rm-b": false} {
		if auditExists(t, store, id) != exists {
			t.Fatalf("%s exists = %v, want %v", id, !exists, exists)
		}
	}
	if got := auditRowCounts(t, store, "rm-trial"); !reflect.DeepEqual(got, trialRows) {
		t.Fatalf("trial member's rows changed: %v, was %v", got, trialRows)
	}
	for id, wantState := range map[string]string{"rm-trial": "sealed", "rm-publishing": "sealed", "rm-a": "hot_removed", "rm-b": "hot_removed", "rm-gone": "hot_removed", "rm-wrong": "sealed"} {
		state, changed := memberState(t, store, id, 1)
		if state != wantState || (wantState == "hot_removed") != (changed == 5000) {
			t.Fatalf("%s: %s at %d, want %s", id, state, changed, wantState)
		}
	}
	if state, _ := segmentState(t, store, "52000000000000000000000000000012"); state != storage.ArchiveSegmentSealed {
		t.Fatalf("segment with a sealed member left is %s", state)
	}

	// The wrong request again with the stored stamp: the last member goes,
	// and with it the segment.
	result, err = store.RemoveArchived(ctx, []ArchiveRemoval{current[3]}, 6000)
	if err != nil || outcomesOf(result)["rm-wrong"] != storage.ArchiveRemovalRemoved || result.RemovedSegments != 1 {
		t.Fatalf("result %+v, %v", result, err)
	}
	if state, removed := segmentState(t, store, "52000000000000000000000000000012"); state != storage.ArchiveSegmentHotRemoved || removed.Int64 != 6000 {
		t.Fatalf("segment %s removed at %v", state, removed)
	}
	if state, _ := segmentState(t, store, "52000000000000000000000000000010"); state != storage.ArchiveSegmentSealed {
		t.Fatalf("trial segment %s", state)
	}
	// A repeated batch is all skipped and deletes nothing.
	again, err := store.RemoveArchived(ctx, current, 7000)
	if err != nil {
		t.Fatal(err)
	}
	for _, outcome := range again.Outcomes {
		if outcome.Outcome != storage.ArchiveRemovalSkipped {
			t.Fatalf("repeated batch: %+v", again)
		}
	}
	if listed, err := store.ListRemovableArchiveMembers(ctx, nil, 100); err != nil || len(listed) != 0 {
		t.Fatalf("still removable %+v, %v", listed, err)
	}
	if _, err := store.RemoveArchived(ctx, []ArchiveRemoval{current[0], current[0]}, 1); err == nil {
		t.Fatal("an audit listed twice was accepted")
	}
	if _, err := store.RemoveArchived(ctx, nil, 1); err == nil {
		t.Fatal("an empty batch was accepted")
	}
}

// The stamp gate of M.2 step 2: after the export, each write of M.1 rows 1 to
// 3 and an inserted or deleted row in every per-audit table makes the member
// stale and deletes nothing of it, while an unchanged member of the same
// batch is removed. A stale member is never removed later on the old stamp.
func TestRemoveArchivedStampGate(t *testing.T) {
	ctx := context.Background()
	store, dsn := openSignedStore(t)
	cipher := graphTestCipher(t)
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	exec := func(statement string, arguments ...any) {
		t.Helper()
		if _, err := admin.ExecContext(ctx, statement, arguments...); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	response := "response_received_from_newapi"

	// A plain audit with a row in every per-audit table but the turn tables.
	plain := func(id string, started int64) {
		ended := started + 1
		insertRetentionAudit(t, store, id, started, &ended, ParseOK, true)
		exec(`INSERT INTO http_stages (audit_id, stage, state, proto, method, host, started_at_ns) VALUES ($1, $2, 'complete', 'HTTP/1.1', 'POST', 'newapi.local', 1)`, id, response)
		exec(`INSERT INTO http_header_blocks (audit_id, compression, plaintext_length, block_enc) VALUES ($1, 'none', 1, '\x01')`, id)
		exec(`INSERT INTO stream_timelines (audit_id, stage, event_count, timeline_complete, compression, plaintext_length) VALUES ($1, $2, 0, 1, 'none', 0)`, id, StageRequestReceived)
	}
	type mutation struct {
		name   string
		graph  bool
		setup  func(id string)
		mutate func(id string)
	}
	turnOf := `(SELECT turn_id FROM turns WHERE audit_id = $1)`
	mutations := []mutation{
		{name: "M.1 row 1: billing backfill", mutate: func(id string) {
			quota, prompt, completion, perUnit := int64(10), int64(3), int64(4), 500000.0
			if err := store.UpdateTokenLinkBilling(ctx, BillingUpdate{AuditID: id, State: BillingBilled, Attempts: 1,
				Quota: &quota, QuotaPerUnit: &perUnit, BilledPromptTokens: &prompt, BilledCompletionTokens: &completion}); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "M.1 row 2: project identity insert", mutate: func(id string) {
			if err := store.SaveProjectIdentity(ctx, identityTestRow(id)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "M.1 row 2: project identity upgrade", setup: func(id string) {
			if err := store.SaveProjectIdentity(ctx, identityTestRow(id)); err != nil {
				t.Fatal(err)
			}
		}, mutate: func(id string) {
			identity := identityTestRow(id)
			identity.Version = 2
			if err := store.SaveProjectIdentity(ctx, identity); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "audit_records update", mutate: func(id string) {
			exec(`UPDATE audit_records SET parse_save_failures = parse_save_failures WHERE audit_id = $1`, id)
		}},
		{name: "http_stages insert", mutate: func(id string) {
			exec(`INSERT INTO http_stages (audit_id, stage, state, proto, method, host, started_at_ns) VALUES ($1, 'request_sent_to_newapi', 'complete', 'HTTP/1.1', 'POST', 'newapi.local', 1)`, id)
		}},
		{name: "http_stages delete", mutate: func(id string) { exec(`DELETE FROM http_stages WHERE audit_id = $1 AND stage = $2`, id, response) }},
		{name: "http_headers insert", mutate: func(id string) {
			exec(`INSERT INTO http_headers (audit_id, stage, kind, name, value_index, value_length, value_enc) VALUES ($1, $2, 'header', 'x-probe', 0, 1, '\x01')`, id, StageRequestReceived)
		}},
		{name: "http_headers delete", mutate: func(id string) { exec(`DELETE FROM http_headers WHERE audit_id = $1`, id) }},
		{name: "http_header_blocks delete", mutate: func(id string) { exec(`DELETE FROM http_header_blocks WHERE audit_id = $1`, id) }},
		{name: "body_streams insert", mutate: func(id string) {
			exec(`INSERT INTO body_streams (audit_id, stage, source_stage, observed_length, stored_length, hash_complete, eof_seen, state, retention_state)
			      VALUES ($1, $2, $2, 1, 1, 0, 0, 'partial', 'full')`, id, response)
		}},
		{name: "body_streams and its chunks delete", mutate: func(id string) { exec(`DELETE FROM body_streams WHERE audit_id = $1`, id) }},
		{name: "body_chunks insert", mutate: func(id string) {
			exec(`INSERT INTO body_chunks (audit_id, stage, seq, "offset", plaintext_length, encoded_length, observed_at_ns, compression, data_enc)
			      VALUES ($1, $2, 1, 1, 1, 1, 1, 'none', '\x01')`, id, StageRequestReceived)
		}},
		{name: "body_chunks delete", mutate: func(id string) { exec(`DELETE FROM body_chunks WHERE audit_id = $1`, id) }},
		{name: "stream_timelines insert", mutate: func(id string) {
			exec(`INSERT INTO stream_timelines (audit_id, stage, event_count, timeline_complete, compression, plaintext_length) VALUES ($1, $2, 0, 1, 'none', 0)`, id, response)
		}},
		{name: "stream_timelines delete", mutate: func(id string) { exec(`DELETE FROM stream_timelines WHERE audit_id = $1`, id) }},
		{name: "parsed_results delete", mutate: func(id string) { exec(`DELETE FROM parsed_results WHERE audit_id = $1`, id) }},
		{name: "token_links delete", mutate: func(id string) { exec(`DELETE FROM token_links WHERE audit_id = $1`, id) }},
		{name: "audit_project_identity delete", setup: func(id string) {
			if err := store.SaveProjectIdentity(ctx, identityTestRow(id)); err != nil {
				t.Fatal(err)
			}
		}, mutate: func(id string) { exec(`DELETE FROM audit_project_identity WHERE audit_id = $1`, id) }},
		{name: "integrity_events insert", mutate: func(id string) {
			exec(`INSERT INTO integrity_events (audit_id, event_type, payload_digest, event_mac, created_at_ns)
			      VALUES ($1, 'reconstruction_failed', decode(repeat('01', 32), 'hex'), decode(repeat('02', 32), 'hex'), 1)`, id)
		}},
		{name: "integrity_events delete", graph: true, mutate: func(id string) { exec(`DELETE FROM integrity_events WHERE audit_id = $1`, id) }},
		{name: "turns update", graph: true, mutate: func(id string) { exec(`UPDATE turns SET link_confidence = link_confidence WHERE audit_id = $1`, id) }},
		{name: "turns delete", graph: true, mutate: func(id string) { exec(`DELETE FROM turns WHERE audit_id = $1`, id) }},
		{name: "turn_context_ops insert", graph: true, mutate: func(id string) {
			exec(`INSERT INTO turn_context_ops (turn_id, op_index, operation, item_count) SELECT turn_id, 1000, 'retain', 1 FROM turns WHERE audit_id = $1`, id)
		}},
		{name: "turn_context_ops delete", graph: true, mutate: func(id string) { exec(`DELETE FROM turn_context_ops WHERE turn_id = `+turnOf, id) }},
		{name: "turn_response_items insert", graph: true, mutate: func(id string) {
			exec(`INSERT INTO turn_response_items (turn_id, ordinal, slot, object_hash, semantic_hash)
			      SELECT turn_id, 1000, 'probe', decode(repeat('ab', 32), 'hex'), decode(repeat('ab', 32), 'hex') FROM turns WHERE audit_id = $1`, id)
		}},
		{name: "turn_response_items delete", graph: true, mutate: func(id string) { exec(`DELETE FROM turn_response_items WHERE turn_id = `+turnOf, id) }},
	}
	// The probe object must exist before the insert that references it.
	exec(`INSERT INTO content_objects (object_hash, semantic_hash, kind, compression, plaintext_length, encoded_length, data_enc, created_at_ns)
	      VALUES (decode(repeat('ab', 32), 'hex'), decode(repeat('ab', 32), 'hex'), 'user_message', 'none', 1, 1, '\x01', 1) ON CONFLICT DO NOTHING`)

	// M.1 row 3: the parent of the member is deleted by other means and the
	// member, its retained child, is checkpointed. The parent is the oldest
	// audit, so retention's DeleteExpired takes exactly it.
	saveGraphTestTurn(t, store, cipher, "gate-parent", "", "gate-response-parent", 10,
		[]graphTestItem{userItem("gate parent question")}, []graphTestItem{assistantItem("gate parent answer")})
	saveGraphTestTurn(t, store, cipher, "gate-child", "gate-response-parent", "gate-response-child", 20,
		[]graphTestItem{userItem("gate parent question"), assistantItem("gate parent answer"), userItem("gate child question")},
		[]graphTestItem{assistantItem("gate child answer")})

	ids := map[string]string{}
	for index, mutation := range mutations {
		id := fmt.Sprintf("gate-%02d", index)
		ids[mutation.name] = id
		started := int64(1000 + index*10)
		if mutation.graph {
			saveGraphTestTurn(t, store, cipher, id, "", "gate-response-"+id, started,
				[]graphTestItem{userItem("question of " + id)}, []graphTestItem{assistantItem("answer of " + id)})
		} else {
			plain(id, started)
		}
		if mutation.setup != nil {
			mutation.setup(id)
		}
	}
	plain("gate-control", 5000)

	run := testArchiveRun("53000000000000000000000000000001", 10)
	if _, err := store.BeginArchiveRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	all := []string{"gate-parent", "gate-child", "gate-control"}
	for _, mutation := range mutations {
		all = append(all, ids[mutation.name])
	}
	batch := sealRemovableSegment(t, store, run, "53000000000000000000000000000010", 1, 1, all...)

	for _, mutation := range mutations {
		mutation.mutate(ids[mutation.name])
	}
	if result, err := store.DeleteExpired(ctx, 15, 1, 0); err != nil || result.DeletedAudits != 1 || auditExists(t, store, "gate-parent") {
		t.Fatalf("delete parent %+v, %v", result, err)
	}
	var reason string
	if err := store.readerDB.QueryRow(`SELECT link_reason FROM turns WHERE audit_id = 'gate-child'`).Scan(&reason); err != nil || reason != "retention_checkpoint" {
		t.Fatalf("child link reason %q, %v", reason, err)
	}
	before := map[string]map[string]int{}
	for _, id := range all {
		before[id] = auditRowCounts(t, store, id)
	}

	result, err := store.RemoveArchived(ctx, batch, 9000)
	if err != nil {
		t.Fatal(err)
	}
	outcomes := outcomesOf(result)
	if outcomes["gate-control"] != storage.ArchiveRemovalRemoved || auditExists(t, store, "gate-control") {
		t.Fatalf("control: %s", outcomes["gate-control"])
	}
	if outcomes["gate-parent"] != storage.ArchiveRemovalAlreadyGone {
		t.Fatalf("parent: %s", outcomes["gate-parent"])
	}
	stale := map[string]string{"M.1 row 3: checkpoint of the retained child": "gate-child"}
	for name, id := range ids {
		stale[name] = id
	}
	for name, id := range stale {
		if outcomes[id] != storage.ArchiveRemovalStale {
			t.Errorf("%s: outcome %s, want stale", name, outcomes[id])
			continue
		}
		if state, _ := memberState(t, store, id, 1); state != storage.ArchiveMemberStale {
			t.Errorf("%s: member %s", name, state)
		}
		if got := auditRowCounts(t, store, id); !reflect.DeepEqual(got, before[id]) {
			t.Errorf("%s: rows %v, were %v", name, got, before[id])
		}
		if !auditExists(t, store, id) {
			t.Errorf("%s: the audit was deleted", name)
		}
	}
	// The segment has no sealed member left.
	if state, _ := segmentState(t, store, "53000000000000000000000000000010"); state != storage.ArchiveSegmentHotRemoved {
		t.Fatalf("segment %s", state)
	}
	// A stale member is never removed on its old stamp.
	if again, err := store.RemoveArchived(ctx, batch, 9100); err != nil || outcomesOf(again)["gate-child"] != storage.ArchiveRemovalSkipped {
		t.Fatalf("again %+v, %v", again, err)
	}
}

// M.3, the crash before the removal transaction commits: a constraint
// trigger deferred to the commit fails it after deleteAuditBatch and the
// catalog updates ran. The whole batch rolls back: the audits and every row
// of theirs are there and the members sealed. Without the fault the same
// batch removes them once.
func TestRemoveArchivedRollsBackAsOneTransaction(t *testing.T) {
	ctx := context.Background()
	store, dsn := openSignedStore(t)
	cipher := graphTestCipher(t)
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	saveGraphTestTurn(t, store, cipher, "crash-parent", "", "crash-response-parent", 100,
		[]graphTestItem{userItem("crash question")}, []graphTestItem{assistantItem("crash answer")})
	saveGraphTestTurn(t, store, cipher, "crash-child", "crash-response-parent", "crash-response-child", 200,
		[]graphTestItem{userItem("crash question"), assistantItem("crash answer"), userItem("crash follow-up")},
		[]graphTestItem{assistantItem("crash second answer")})
	ended := int64(301)
	insertRetentionAudit(t, store, "crash-plain", 300, &ended, ParseOK, true)
	run := testArchiveRun("54000000000000000000000000000001", 10)
	if _, err := store.BeginArchiveRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	// Only the parent and the plain audit: the child stays hot and is
	// checkpointed inside the transaction that then fails.
	batch := sealRemovableSegment(t, store, run, "54000000000000000000000000000010", 1, 1, "crash-parent", "crash-plain")
	counts := func() string {
		var out []string
		for _, id := range []string{"crash-parent", "crash-child", "crash-plain"} {
			out = append(out, fmt.Sprint(auditRowCounts(t, store, id)))
		}
		var objects, conversations int
		_ = store.readerDB.QueryRow(`SELECT (SELECT COUNT(*) FROM content_objects), (SELECT COUNT(*) FROM conversations)`).Scan(&objects, &conversations)
		return strings.Join(out, "\n") + fmt.Sprintf("\nobjects %d conversations %d", objects, conversations)
	}
	childStamp := archiveStampOf(t, store, "crash-child")
	before := counts()
	for _, statement := range []string{
		`CREATE FUNCTION fail_archive_removal() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'injected commit failure'; END $$`,
		`CREATE CONSTRAINT TRIGGER fail_archive_removal AFTER UPDATE ON archive_members
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.state = 'hot_removed') EXECUTE FUNCTION fail_archive_removal()`,
	} {
		if _, err := admin.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.RemoveArchived(ctx, batch, 5000); err == nil {
		t.Fatal("the failed commit was reported as a success")
	}
	if after := counts(); after != before {
		t.Fatalf("a failed removal changed the hot store:\n%s\nwas\n%s", after, before)
	}
	if !bytes.Equal(archiveStampOf(t, store, "crash-child"), childStamp) {
		t.Fatal("the rolled back checkpoint changed the child")
	}
	for _, id := range []string{"crash-parent", "crash-plain"} {
		if state, _ := memberState(t, store, id, 1); state != storage.ArchiveMemberSealed {
			t.Fatalf("%s is %s after the rollback", id, state)
		}
	}
	for _, statement := range []string{`DROP TRIGGER fail_archive_removal ON archive_members`, `DROP FUNCTION fail_archive_removal()`} {
		if _, err := admin.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	result, err := store.RemoveArchived(ctx, batch, 6000)
	if err != nil {
		t.Fatal(err)
	}
	for _, outcome := range result.Outcomes {
		if outcome.Outcome != storage.ArchiveRemovalRemoved {
			t.Fatalf("retry %+v", result)
		}
	}
	var reason string
	if err := store.readerDB.QueryRow(`SELECT link_reason FROM turns WHERE audit_id = 'crash-child'`).Scan(&reason); err != nil || reason != "retention_checkpoint" {
		t.Fatalf("retained child %q, %v", reason, err)
	}
	if auditExists(t, store, "crash-parent") || auditExists(t, store, "crash-plain") || !auditExists(t, store, "crash-child") {
		t.Fatal("wrong audits removed")
	}
}

// Gap removal (M.2): the audit_gaps rows of sealed gap members of sealed
// gaps segment of version 1 or later are deleted and the members and, once
// empty, the segment marked hot_removed; a trial segment's gaps stay; a gap
// row already gone is still marked; a repeat removes nothing.
func TestRemoveArchivedGaps(t *testing.T) {
	ctx := context.Background()
	store, _ := openTestStore(t)
	var gapIDs []int64
	for index := 0; index < 5; index++ {
		var id int64
		if err := store.writerConn.QueryRowContext(ctx, `INSERT INTO audit_gaps (started_at_ns, ended_at_ns, reason, request_count, detail, created_at_ns)
VALUES ($1, $2, 'queue_full', 1, '', $2) RETURNING id`, 1000+index, 1001+index).Scan(&id); err != nil {
			t.Fatal(err)
		}
		gapIDs = append(gapIDs, id)
	}
	run := testArchiveRun("55000000000000000000000000000001", 10)
	if _, err := store.BeginArchiveRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	register := func(segmentID string, version int64, gaps []int64) {
		segment := testArchiveSegment(segmentID, run.RunID, "gaps/"+segmentID+".manifest.json", len(gaps))
		segment.BundleKind, segment.FormatVersion = storage.ArchiveBundleGaps, version
		if _, err := store.RegisterArchiveIntent(ctx, ArchiveIntent{Segment: segment, GapIDs: gaps}); err != nil {
			t.Fatal(err)
		}
		if err := store.SealArchiveSegment(ctx, ArchiveSeal{SegmentID: segmentID, ManifestSHA256: bytes.Repeat([]byte{0x66}, 32), DiskBytes: 1, SealedAtNS: 4000}); err != nil {
			t.Fatal(err)
		}
	}
	register("55000000000000000000000000000010", 0, gapIDs[:1])
	register("55000000000000000000000000000011", 1, gapIDs[1:])
	mustExecWriter(t, store, `DELETE FROM audit_gaps WHERE id = $1`, gapIDs[4])

	// The trial segment is never removed, asked for by name or not.
	if trial, err := store.RemoveArchivedGaps(ctx, "55000000000000000000000000000010", 2, 5000); err != nil || trial != (ArchiveGapRemovalResult{}) {
		t.Fatalf("trial %+v, %v", trial, err)
	}
	current := "55000000000000000000000000000011"
	first, err := store.RemoveArchivedGaps(ctx, current, 2, 5000)
	if err != nil || first.RemovedGaps != 2 || first.DeletedRows != 2 || first.RemovedSegments != 0 {
		t.Fatalf("first %+v, %v", first, err)
	}
	second, err := store.RemoveArchivedGaps(ctx, current, 2, 5000)
	if err != nil || second.RemovedGaps != 2 || second.DeletedRows != 1 || second.RemovedSegments != 1 {
		t.Fatalf("second %+v, %v", second, err)
	}
	if third, err := store.RemoveArchivedGaps(ctx, current, 2, 5000); err != nil || third != (ArchiveGapRemovalResult{}) {
		t.Fatalf("third %+v, %v", third, err)
	}
	var left []int64
	rows, err := store.readerDB.Query(`SELECT id FROM audit_gaps ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id int64
		_ = rows.Scan(&id)
		left = append(left, id)
	}
	rows.Close()
	if !reflect.DeepEqual(left, gapIDs[:1]) {
		t.Fatalf("gaps left %v, want the trial segment's %v", left, gapIDs[:1])
	}
	if state, removed := segmentState(t, store, "55000000000000000000000000000011"); state != storage.ArchiveSegmentHotRemoved || removed.Int64 != 5000 {
		t.Fatalf("gap segment %s at %v", state, removed)
	}
	if state, _ := segmentState(t, store, "55000000000000000000000000000010"); state != storage.ArchiveSegmentSealed {
		t.Fatalf("trial gap segment %s", state)
	}
	if _, err := store.RemoveArchivedGaps(ctx, current, RetentionBatchLimit+1, 1); err == nil {
		t.Fatal("an oversized gap batch was accepted")
	}
}
