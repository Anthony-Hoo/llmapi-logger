package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/archive/runner"
	"llmapi-logger/internal/archivecli"
	"llmapi-logger/internal/config"
	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/protofixture"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/postgres"
)

// The cold archive's verified removal end to end on PostgreSQL (design M,
// N.3): real traffic through the proxy, archive runs in archive_then_delete.
// The format is not frozen yet, so the runner is told to work at format
// version 1 through the test seam; the bundles still carry version 0.

// archivedTables are the tables an archived audit has rows in, and the
// shared ones removal may garbage collect.
var archivedTables = []string{
	"audit_records", "http_stages", "http_headers", "http_header_blocks", "body_streams", "body_chunks", "stream_timelines",
	"parsed_results", "token_links", "audit_project_identity", "integrity_events", "turns", "turn_context_ops",
	"turn_response_items", "conversations", "content_objects", "binary_objects", "content_binary_refs",
	"content_external_refs", "audit_gaps",
}

func newRemovalEnv(t *testing.T) *archiveEnv {
	t.Helper()
	return newArchiveEnvWith(t, config.ArchiveModeArchiveThenDelete, func(env *archiveEnv) { env.formatVersion = 1 })
}

func (env *archiveEnv) store() *postgres.Store {
	env.t.Helper()
	store, ok := env.app.auditStore.(*postgres.Store)
	if !ok {
		env.t.Fatal("the audit store is not PostgreSQL")
	}
	return store
}

func (env *archiveEnv) count(query string, arguments ...any) int {
	env.t.Helper()
	var count int
	if err := env.db.QueryRow(query, arguments...).Scan(&count); err != nil {
		env.t.Fatalf("%s: %v", query, err)
	}
	return count
}

// tableHashes is an MD5 of the rows of every archived table.
func (env *archiveEnv) tableHashes() map[string]string {
	env.t.Helper()
	out := map[string]string{}
	for _, table := range archivedTables {
		var digest string
		if err := env.db.QueryRow(`SELECT COALESCE(md5(string_agg(t::text, E'\n' ORDER BY t::text)), '') FROM "` + table + `" AS t`).Scan(&digest); err != nil {
			env.t.Fatal(err)
		}
		out[table] = digest
	}
	return out
}

// archiveExports renders, from the archive, the exports of each audit that
// audit-archive offers (or the error code of one that has none).
func (env *archiveEnv) archiveExports(ids []string) map[string]string {
	env.t.Helper()
	reader, _ := env.readArchive()
	out := map[string]string{}
	for _, id := range ids {
		audit, err := reader.Audit(env.ctx, id)
		if err != nil {
			env.t.Fatalf("%s from the archive: %v", id, err)
		}
		for _, kind := range []string{"detail", "conversation", "headers", "request", "response", "raw-request", "raw-response", "timeline-response"} {
			var buffer bytes.Buffer
			err := archivecli.ExportAudit(env.ctx, audit, kind, &buffer)
			out[id+"/"+kind] = fmt.Sprintf("%d:%s:%x", audit.Record.Revision, archivecli.ErrorCode(err), buffer.Bytes())
		}
	}
	return out
}

func (env *archiveEnv) requireNoUnrecordedRemoval() {
	env.t.Helper()
	if lost := env.count(`SELECT COUNT(*) FROM archive_members AS m WHERE m.state = 'sealed'
AND NOT EXISTS (SELECT 1 FROM audit_records AS a WHERE a.audit_id = m.audit_id)`); lost != 0 {
		env.t.Fatalf("%d sealed members whose audit is gone", lost)
	}
	if missing := env.count(`SELECT COUNT(*) FROM archive_members AS m WHERE m.state = 'hot_removed'
AND EXISTS (SELECT 1 FROM audit_records AS a WHERE a.audit_id = m.audit_id)`); missing != 0 {
		env.t.Fatalf("%d hot_removed members whose audit is still hot", missing)
	}
}

// The happy path: traffic of the four protocols, a blocked request without a
// turn and two gaps; one run exports and removes everything. Every archived
// table is empty afterwards (integrity_events excepted, invariant 8), content
// and binary objects included; members and segments are hot_removed; the
// bundles verify with audit-archive's Go API and every removed audit reads
// back from them exactly as before the removal; a second run does nothing;
// the next start verifies the integrity chain and the background payload
// verification passes; HasAudits stays true, and a start without the key
// file does not create a new key.
func TestPostgresArchiveRemovesVerifiedAudits(t *testing.T) {
	env := newRemovalEnv(t)
	logs := env.logs.String()
	if !strings.Contains(logs, `"error_category":"archive_removal_active"`) || strings.Contains(logs, "archive_removal_trial_format") ||
		strings.Contains(logs, `"error_category":"archive_export_only"`) || env.app.retention != nil {
		t.Fatalf("start-up logs %s", logs)
	}
	env.traffic(protofixture.Protocols(), 3)
	env.blockedRequest()
	if _, err := env.db.Exec(`INSERT INTO audit_gaps (started_at_ns, ended_at_ns, reason, request_count, detail, created_at_ns)
VALUES (1000, 2000, 'queue_full', 3, '', 2001), (3000, 4000, 'db_unavailable', 1, '', 4001)`); err != nil {
		t.Fatal(err)
	}
	ids := env.auditIDs()
	events := env.count(`SELECT COUNT(*) FROM integrity_events`)
	if env.count(`SELECT COUNT(*) FROM content_objects`) == 0 || env.count(`SELECT COUNT(*) FROM binary_objects`) == 0 {
		t.Fatal("the traffic has no content or binary objects to collect")
	}
	env.due()
	// Between the export and the removal: the archive reads every member as
	// the hot store does (the run samples them all), and its exports are
	// kept to compare with what it reads after the removal.
	var before map[string]string
	capture := func(step string) error {
		if step == runner.StepBeforeRecordPass && before == nil {
			before = env.archiveExports(ids)
		}
		return nil
	}
	env.step.Store(&capture)
	result := env.mustRun()
	env.step.Store(nil)
	removal := result.Removal
	if result.Counts.ExportedAudits != int64(len(ids)) || result.SampleMismatched != 0 || result.Excluded != 0 ||
		removal.Removed != int64(len(ids)) || removal.Stale != 0 || removal.AlreadyGone != 0 || removal.Skipped != 0 ||
		removal.RemovedGaps != 2 || result.Counts.RemovedAudits != int64(len(ids)) || result.Counts.RemovedGaps != 2 {
		t.Fatalf("run %+v", result)
	}
	for _, table := range archivedTables {
		rows := env.count(`SELECT COUNT(*) FROM "` + table + `"`)
		if table == "integrity_events" {
			if rows != events {
				t.Fatalf("integrity events %d, were %d", rows, events)
			}
		} else if rows != 0 {
			t.Fatalf("%s has %d rows after the removal", table, rows)
		}
	}
	if left := env.count(`SELECT COUNT(*) FROM archive_members WHERE state <> 'hot_removed'`) +
		env.count(`SELECT COUNT(*) FROM archive_gap_members WHERE state <> 'hot_removed'`) +
		env.count(`SELECT COUNT(*) FROM archive_segments WHERE state <> 'hot_removed' OR removed_at_ns IS NULL`); left != 0 {
		t.Fatalf("%d catalog rows not hot_removed", left)
	}
	var recorded storage.ArchiveRunCounts
	if err := env.db.QueryRow(`SELECT removed_audits, removed_gaps FROM archive_runs WHERE run_id = $1`, result.RunID).
		Scan(&recorded.RemovedAudits, &recorded.RemovedGaps); err != nil || recorded.RemovedAudits != int64(len(ids)) || recorded.RemovedGaps != 2 {
		t.Fatalf("run record %+v (%v)", recorded, err)
	}
	if after := env.archiveExports(ids); !reflect.DeepEqual(after, before) {
		t.Fatal("the archive reads the removed audits differently after the removal")
	}
	var line string
	for _, each := range strings.Split(env.logs.String(), "\n") {
		if strings.Contains(each, `"msg":"archive removal completed"`) {
			line = each
		}
	}
	if !strings.Contains(line, fmt.Sprintf(`"removed_audits":%d`, len(ids))) || strings.Contains(line, "apx_") || strings.Contains(line, env.cfg.Archive.Dir) {
		t.Fatalf("removal log line %q", line)
	}
	if has, err := env.store().HasAudits(env.ctx); err != nil || !has {
		t.Fatalf("HasAudits %v, %v", has, err)
	}
	if again := env.mustRun(); again.Removal.Removed != 0 || again.Counts.ExportedAudits != 0 || again.Removal.RemovedGaps != 0 {
		t.Fatalf("second run %+v", again)
	}

	// The next start verifies the whole event chain (EnableIntegrity), and
	// the background payload verification passes.
	if err := env.app.Close(); err != nil {
		t.Fatal(err)
	}
	env.logs = &lockedBuffer{}
	env.start()
	if err := env.store().VerifyIntegrityPayloads(env.ctx); err != nil || env.store().IntegrityPayloadState() == "failed" {
		t.Fatalf("payload verification %v, state %s", err, env.store().IntegrityPayloadState())
	}
	if err := env.app.Close(); err != nil {
		t.Fatal(err)
	}

	// Without the key file the start refuses to create a new key.
	if err := os.Rename(env.cfg.KeyPath, env.cfg.KeyPath+".moved"); err != nil {
		t.Fatal(err)
	}
	var startLogs lockedBuffer
	application, err := NewContext(env.ctx, env.cfg, slog.New(slog.NewJSONHandler(&startLogs, nil)))
	if err == nil {
		defer application.Close()
		if application.auditStore != nil && application.auditStore.Healthy() {
			t.Fatal("the audit store started without its key")
		}
	}
	if _, statErr := os.Stat(env.cfg.KeyPath); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("a new key was created (%v)", statErr)
	}
	if !strings.Contains(startLogs.String(), `"error_category":"key_unavailable"`) {
		t.Fatalf("start-up logs %s (%v)", startLogs.String(), err)
	}
}

// At the built-in format version 0 (no seam), archive_then_delete exports
// and removes nothing: every archived table hashes the same before and after
// the run, and the start says why.
func TestPostgresArchiveRemovalAtFormatVersionZero(t *testing.T) {
	env := newArchiveEnv(t, config.ArchiveModeArchiveThenDelete)
	if !strings.Contains(env.logs.String(), `"error_category":"archive_removal_trial_format"`) || env.app.archive.FormatVersion() != 0 {
		t.Fatalf("start-up logs %s", env.logs.String())
	}
	env.traffic([]protofixture.Protocol{protofixture.OpenAIChat, protofixture.Gemini}, 2)
	if _, err := env.db.Exec(`INSERT INTO audit_gaps (started_at_ns, ended_at_ns, reason, request_count, detail, created_at_ns)
VALUES (1000, 2000, 'queue_full', 3, '', 2001)`); err != nil {
		t.Fatal(err)
	}
	before := env.tableHashes()
	env.due()
	result := env.mustRun()
	if result.Counts.ExportedAudits != int64(env.sent) || result.ExportedGaps != 1 || result.Removal.Removed != 0 || result.Removal.RemovedGaps != 0 {
		t.Fatalf("run %+v", result)
	}
	if after := env.tableHashes(); !reflect.DeepEqual(after, before) {
		for table := range before {
			if after[table] != before[table] {
				t.Errorf("%s changed", table)
			}
		}
		t.Fatal("archive_then_delete changed the hot store at format version 0")
	}
	if sealed := env.count(`SELECT COUNT(*) FROM archive_members WHERE state = 'sealed'`); sealed != env.sent {
		t.Fatalf("%d sealed members for %d audits", sealed, env.sent)
	}
	env.mustRun()
	if after := env.tableHashes(); !reflect.DeepEqual(after, before) {
		t.Fatal("a second run changed the hot store at format version 0")
	}
}

// The stamp gate (M.2 step 2, M.4) with real records: between the export and
// the removal of one run, one audit's project identity is upgraded and
// another's is saved for the first time (M.1 row 2), and
// retention-style deletion by other means takes the oldest audit, which
// checkpoints its child (row 3). Those three members turn stale and keep
// every row, the deleted one is recorded hot_removed, the rest are removed.
// The next run exports the three again at revision 2 and removes them; the
// archive reads revision 2.
func TestPostgresArchiveRemovalStampGate(t *testing.T) {
	env := newRemovalEnv(t)
	env.traffic([]protofixture.Protocol{protofixture.OpenAIChat, protofixture.AnthropicMessages}, 3)
	ids := env.auditIDs()
	var parent, child string
	var parentStarted int64
	if err := env.db.QueryRow(`
SELECT p.audit_id, c.audit_id, a.started_at_ns FROM turns AS p JOIN turns AS c ON c.parent_turn_id = p.turn_id
JOIN audit_records AS a ON a.audit_id = p.audit_id ORDER BY a.started_at_ns, c.created_at_ns LIMIT 1`).Scan(&parent, &child, &parentStarted); err != nil {
		t.Fatal(err)
	}
	if !env.isFirstStarted(parent) {
		t.Fatal("the oldest parent is not the oldest audit")
	}
	// upgraded is the audit whose project identity is upgraded (M.1 row 2);
	// M.1 row 1 needs a resolved caller, which this traffic does not have,
	// and is covered by the store test TestRemoveArchivedStampGate.
	var upgraded, identity string
	for _, id := range ids {
		if id == parent || id == child {
			continue
		}
		if upgraded == "" {
			upgraded = id
		} else if identity == "" {
			identity = id
		}
	}
	// The upgraded audit has an identity of version 1 when it is exported.
	saveIdentity := func(id string, version int) {
		t.Helper()
		aad, err := orgreport.IdentityAAD(id, version)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := env.app.cipher.Encrypt(aad, []byte(`{"cwd":"/work/example"}`))
		if err != nil {
			t.Fatal(err)
		}
		if err := env.store().SaveProjectIdentity(env.ctx, storage.ProjectIdentityRow{AuditID: id, Version: version, ExtractedAtNS: 10,
			Source: "codex_turn_metadata", BodyScanned: true, IdentityFPR: bytes.Repeat([]byte{1}, 32), CwdFPR: bytes.Repeat([]byte{4}, 32),
			IdentityEnc: sealed}); err != nil {
			t.Fatal(err)
		}
	}
	saveIdentity(upgraded, 1)
	env.due()
	changed := false
	change := func(step string) error {
		if step != runner.StepBeforeRecordPass || changed {
			return nil
		}
		changed = true
		store := env.store()
		saveIdentity(upgraded, 2)
		saveIdentity(identity, 1)
		if deleted, err := store.DeleteExpired(env.ctx, parentStarted+1, 1, 0); err != nil || deleted.DeletedAudits != 1 {
			t.Fatalf("delete parent %+v, %v", deleted, err)
		}
		return nil
	}
	env.step.Store(&change)
	changedRows := map[string]map[string]int{}
	result := env.mustRun()
	env.step.Store(nil)
	if !changed || result.Removal.Stale != 3 || result.Removal.AlreadyGone != 1 || result.Removal.Removed != int64(len(ids)-4) ||
		result.Counts.StaleAudits != 3 {
		for name, id := range map[string]string{"upgraded": upgraded, "identity": identity, "child": child, "parent": parent} {
			var state string
			_ = env.db.QueryRow(`SELECT state FROM archive_members WHERE audit_id = $1 ORDER BY revision DESC LIMIT 1`, id).Scan(&state)
			t.Logf("%s: %s", name, state)
		}
		t.Fatalf("first run %+v", result.Removal)
	}
	for _, id := range []string{upgraded, identity, child} {
		var state string
		if err := env.db.QueryRow(`SELECT state FROM archive_members WHERE audit_id = $1 AND revision = 1`, id).Scan(&state); err != nil || state != storage.ArchiveMemberStale {
			t.Fatalf("%s member %q (%v)", id, state, err)
		}
		if env.count(`SELECT COUNT(*) FROM audit_records WHERE audit_id = $1`, id) != 1 {
			t.Fatalf("%s was removed", id)
		}
		changedRows[id] = map[string]int{}
		for _, table := range []string{"http_stages", "body_streams", "parsed_results", "turns"} {
			changedRows[id][table] = env.count(`SELECT COUNT(*) FROM `+table+` WHERE audit_id = $1`, id)
		}
	}
	if changedRows[child]["turns"] != 1 || env.count(`SELECT COUNT(*) FROM turns WHERE audit_id = $1 AND link_reason = 'retention_checkpoint'`, child) != 1 {
		t.Fatal("the child was not checkpointed")
	}
	var parentState string
	if err := env.db.QueryRow(`SELECT state FROM archive_members WHERE audit_id = $1`, parent).Scan(&parentState); err != nil || parentState != storage.ArchiveMemberHotRemoved {
		t.Fatalf("parent member %q (%v)", parentState, err)
	}
	env.requireNoUnrecordedRemoval()

	second := env.mustRun()
	if second.Counts.ExportedAudits != 3 || second.Removal.Removed != 3 || second.Removal.Stale != 0 || second.Counts.IntegrityFailedAudits != 0 {
		t.Fatalf("second run %+v / %+v", second.Counts, second.Removal)
	}
	if left := env.count(`SELECT COUNT(*) FROM audit_records`); left != 0 {
		t.Fatalf("%d audits left", left)
	}
	reader, _ := env.readArchive()
	for _, id := range []string{upgraded, identity, child} {
		audit, err := reader.Audit(env.ctx, id)
		if err != nil || audit.Record.Revision != 2 {
			t.Fatalf("%s reads revision %v (%v)", id, audit, err)
		}
		var state string
		if err := env.db.QueryRow(`SELECT state FROM archive_members WHERE audit_id = $1 AND revision = 2`, id).Scan(&state); err != nil || state != storage.ArchiveMemberHotRemoved {
			t.Fatalf("%s revision 2 %q (%v)", id, state, err)
		}
	}
	env.requireNoUnrecordedRemoval()
}

// isFirstStarted reports whether id is the audit that started first.
func (env *archiveEnv) isFirstStarted(id string) bool {
	var first string
	if err := env.db.QueryRow(`SELECT audit_id FROM audit_records ORDER BY started_at_ns, audit_id LIMIT 1`).Scan(&first); err != nil {
		env.t.Fatal(err)
	}
	return first == id
}

// contextOps hashes the context operations and lineage of every turn still
// in the hot store.
func (env *archiveEnv) contextOps() map[string]string {
	env.t.Helper()
	rows, err := env.db.Query(`
SELECT t.turn_id, md5(COALESCE(t.parent_turn_id, '') || '/' || t.parent_base || '/' || t.link_reason || '/' ||
       COALESCE((SELECT string_agg(o::text, E'\n' ORDER BY o.op_index) FROM turn_context_ops AS o WHERE o.turn_id = t.turn_id), ''))
FROM turns AS t`)
	if err != nil {
		env.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var turn, digest string
		if err := rows.Scan(&turn, &digest); err != nil {
			env.t.Fatal(err)
		}
		out[turn] = digest
	}
	return out
}

// Ordering (M.2, decision 5.2 item 2) with real conversations: a chain of
// four turns and a two-turn pair, removed one audit per batch in one run. A trigger holds each batch above half a second so the
// batch size stays at one. Before every batch the lineage and context
// operations of every turn still hot are what they were: no checkpoint
// rewrites a member before its own removal, no member turns stale, and no
// turn is left a retention checkpoint.
func TestPostgresArchiveRemovalTakesChildrenBeforeParents(t *testing.T) {
	env := newRemovalEnv(t)
	options := protofixture.Options{Seed: 7, ItemBytes: 120, SystemBytes: 200}
	chain := protofixture.NewConversation(protofixture.OpenAIResponses, true, options, 40)
	for turn := 0; turn < 3; turn++ {
		env.send(chain.Next(protofixture.ScenarioBasic, protofixture.Features{}))
	}
	env.send(chain.Next(protofixture.ScenarioBasic, protofixture.Features{}))
	pair := protofixture.NewConversation(protofixture.OpenAIChat, true, options, 41)
	env.send(pair.Next(protofixture.ScenarioBasic, protofixture.Features{}))
	env.send(pair.Next(protofixture.ScenarioBasic, protofixture.Features{}))
	env.waitTerminal()
	// The proxy links a turn to the latest turn of its conversation key, so
	// this traffic cannot form a branch (a fork links to the newest turn);
	// the branch is covered by the runner's host test.
	if links := env.count(`SELECT COUNT(*) FROM turns AS c JOIN turns AS p ON p.turn_id = c.parent_turn_id`); links != 4 {
		t.Fatalf("%d parent links, want a chain of four and a pair", links)
	}
	for _, statement := range []string{
		`CREATE FUNCTION slow_archive_removal() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.6); RETURN NULL; END $$`,
		`CREATE TRIGGER slow_archive_removal AFTER UPDATE ON archive_members FOR EACH STATEMENT EXECUTE FUNCTION slow_archive_removal()`,
	} {
		if _, err := env.db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	env.due()
	previous := map[string]string{}
	batches := 0
	check := func(step string) error {
		switch step {
		case runner.StepBeforeRecordPass:
			previous = env.contextOps()
		case runner.StepBetweenRemovalBatches, runner.StepAfterRemoval:
			batches++
			for turn, digest := range env.contextOps() {
				if previous[turn] != digest {
					t.Errorf("turn %s was rewritten before its removal", turn)
				}
			}
		}
		return nil
	}
	env.step.Store(&check)
	result := env.mustRun()
	env.step.Store(nil)
	if result.Removal.Removed != int64(env.sent) || result.Removal.Stale != 0 || result.Removal.Batches != int64(env.sent) {
		t.Fatalf("removal %+v for %d audits", result.Removal, env.sent)
	}
	if batches < env.sent || env.count(`SELECT COUNT(*) FROM audit_records`) != 0 || env.count(`SELECT COUNT(*) FROM archive_members WHERE state = 'stale'`) != 0 {
		t.Fatalf("%d batches checked", batches)
	}
}

// The counter-example of M.2 on PostgreSQL: the members of one conversation
// are given the start times of the A/B case (the later a turn was created,
// the earlier its request started; only the catalog's copy of started_at_ns,
// which RemovalOrder does not read) and removed one at a time in start order
// descending. Each removal of a parent checkpoints the child that is still
// to be removed, which then turns stale. The same members in RemovalOrder
// turn none stale.
func TestPostgresArchiveStartOrderMakesFalseStaleMembers(t *testing.T) {
	for _, test := range []struct {
		name  string
		order func([]storage.ArchiveRemovable) []storage.ArchiveRemovable
		stale bool
	}{
		{"start order descending", func(members []storage.ArchiveRemovable) []storage.ArchiveRemovable {
			ordered := append([]storage.ArchiveRemovable(nil), members...)
			sortByStartDescending(ordered)
			return ordered
		}, true},
		{"removal order", runner.RemovalOrder, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			env := newArchiveEnvWith(t, config.ArchiveModeExportOnly, func(env *archiveEnv) { env.formatVersion = 1 })
			conversation := protofixture.NewConversation(protofixture.OpenAIResponses, true, protofixture.Options{Seed: 3, ItemBytes: 100}, 50)
			for turn := 0; turn < 4; turn++ {
				env.send(conversation.Next(protofixture.ScenarioBasic, protofixture.Features{}))
			}
			env.waitTerminal()
			env.due()
			env.mustRun()
			if _, err := env.db.Exec(`UPDATE archive_members SET started_at_ns = -turn_created_at_ns WHERE turn_created_at_ns IS NOT NULL`); err != nil {
				t.Fatal(err)
			}
			store := env.store()
			members, err := store.ListRemovableArchiveMembers(env.ctx, nil, 100)
			if err != nil || len(members) != 4 {
				t.Fatalf("members %d, %v", len(members), err)
			}
			stale := 0
			for _, member := range test.order(members) {
				result, err := store.RemoveArchived(env.ctx, []storage.ArchiveRemoval{member.ArchiveRemoval}, time.Now().UnixNano())
				if err != nil {
					t.Fatal(err)
				}
				if result.Outcomes[0].Outcome == storage.ArchiveRemovalStale {
					stale++
				}
			}
			checkpoints := env.count(`SELECT COUNT(*) FROM turns WHERE link_reason = 'retention_checkpoint'`)
			if test.stale != (stale > 0) || test.stale != (checkpoints > 0) {
				t.Fatalf("%d stale, %d checkpointed turns", stale, checkpoints)
			}
			t.Logf("%s: %d stale, %d checkpointed turns", test.name, stale, checkpoints)
		})
	}
}

func sortByStartDescending(members []storage.ArchiveRemovable) {
	for left := 1; left < len(members); left++ {
		for right := left; right > 0 && members[right].StartedAtNS > members[right-1].StartedAtNS; right-- {
			members[right], members[right-1] = members[right-1], members[right]
		}
	}
}

// A conversation stays active while its older turns are archived (N.3 row
// 3): a new turn arrives after the export, before the removal, and builds on
// the last archived turn. Removing the archived turns checkpoints it (it
// becomes a retention_checkpoint root); its detail, reconstruction and
// session conversation read from the hot store exactly as before the
// removal; the objects it references are kept and no object is left that
// nothing references; the removed turns read from the archive.
func TestPostgresArchiveRemovalKeepsTheActiveConversation(t *testing.T) {
	env := newRemovalEnv(t)
	options := protofixture.Options{Seed: 11, ItemBytes: 150, SystemBytes: 300, ToolDefinitions: 1}
	conversation := protofixture.NewConversation(protofixture.AnthropicMessages, true, options, 60)
	for turn := 0; turn < 3; turn++ {
		env.send(conversation.Next(protofixture.ScenarioBasic, protofixture.Features{}))
	}
	env.waitTerminal()
	archived := env.auditIDs()
	env.due()
	hot, err := query.New(env.app.auditStore, env.app.cipher)
	if err != nil {
		t.Fatal(err)
	}
	var active string
	views := func(id string) string {
		var out []string
		detail, err := hot.Get(env.ctx, id, nil)
		if err == nil {
			// A.3: a count over the whole conversation at query time.
			detail.Audit.ConversationTurns = nil
		}
		out = append(out, jsonOf(t, detail, err))
		turn, err := hot.ReconstructTurn(env.ctx, id)
		out = append(out, jsonOf(t, turn, err))
		session, err := hot.SessionConversation(env.ctx, id)
		out = append(out, jsonOf(t, session, err))
		return strings.Join(out, "\n")
	}
	var before string
	arrive := func(step string) error {
		if step == runner.StepBeforeRecordPass && active == "" {
			env.send(conversation.Next(protofixture.ScenarioBasic, protofixture.Features{}))
			env.waitTerminal()
			for _, id := range env.auditIDs() {
				if !contains(archived, id) {
					active = id
				}
			}
			before = views(active)
		}
		return nil
	}
	env.step.Store(&arrive)
	result := env.mustRun()
	env.step.Store(nil)
	if active == "" || result.Removal.Removed != int64(len(archived)) || result.Removal.Stale != 0 {
		t.Fatalf("removal %+v", result.Removal)
	}
	if ids := env.auditIDs(); len(ids) != 1 || ids[0] != active {
		t.Fatalf("hot audits %v, want only the active turn", ids)
	}
	var reason string
	var parent *string
	if err := env.db.QueryRow(`SELECT link_reason, parent_turn_id FROM turns WHERE audit_id = $1`, active).Scan(&reason, &parent); err != nil ||
		reason != "retention_checkpoint" || parent != nil {
		t.Fatalf("active turn %q parent %v (%v)", reason, parent, err)
	}
	after := views(active)
	if after != before {
		t.Fatalf("the active turn reads differently after the removal:\nbefore %s\nafter  %s", before, after)
	}
	if orphans := env.count(`SELECT COUNT(*) FROM content_objects AS c WHERE
NOT EXISTS (SELECT 1 FROM turns AS t WHERE t.request_envelope_hash = c.object_hash OR t.response_envelope_hash = c.object_hash)
AND NOT EXISTS (SELECT 1 FROM turn_context_ops AS o WHERE o.object_hash = c.object_hash)
AND NOT EXISTS (SELECT 1 FROM turn_response_items AS i WHERE i.object_hash = c.object_hash)`); orphans != 0 {
		t.Fatalf("%d content objects nothing references", orphans)
	}
	if env.count(`SELECT COUNT(*) FROM content_objects`) == 0 {
		t.Fatal("the active turn's objects were collected")
	}
	reader, _ := env.readArchive()
	for _, id := range archived {
		audit, err := reader.Audit(env.ctx, id)
		if err != nil {
			t.Fatalf("%s from the archive: %v", id, err)
		}
		var buffer bytes.Buffer
		if err := archivecli.ExportAudit(env.ctx, audit, "conversation", &buffer); err != nil || buffer.Len() == 0 {
			t.Fatalf("%s conversation from the archive (%v)", id, err)
		}
	}
	// The next run archives the active turn, now due, and removes it.
	if next := env.mustRun(); next.Counts.ExportedAudits != 1 || next.Removal.Removed != 1 {
		t.Fatalf("next run %+v", next.Removal)
	}
}

func jsonOf(t *testing.T, value any, err error) string {
	t.Helper()
	if err != nil {
		return "error: " + err.Error()
	}
	data, marshalErr := json.Marshal(value)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	var generic any
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatal(err)
	}
	stripLineage(generic)
	if data, marshalErr = json.Marshal(generic); marshalErr != nil {
		t.Fatal(marshalErr)
	}
	return string(data)
}

// stripLineage drops the four lineage fields, which the checkpoint of a
// retained child rewrites by design (A.1, Q6); the test checks them apart.
func stripLineage(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for _, key := range []string{"parent_turn_id", "parent_base", "link_reason", "link_confidence"} {
			delete(typed, key)
		}
		for _, each := range typed {
			stripLineage(each)
		}
	case []any:
		for _, each := range typed {
			stripLineage(each)
		}
	}
}

func contains(values []string, value string) bool {
	for _, each := range values {
		if each == value {
			return true
		}
	}
	return false
}

// The crash points of M.3, each followed by a run that completes: the
// removal transaction fails at its commit (a deferred constraint trigger):
// the whole batch rolls back, every member is still sealed and the run
// fails; the run stops between two batches; the run stops after the last
// batch, before its record is finished. Afterwards every audit is removed
// exactly once (nothing already gone, nothing removed twice), and at no
// point is a sealed member's audit gone or a hot_removed member's audit
// still hot.
func TestPostgresArchiveRemovalCrashPoints(t *testing.T) {
	for _, point := range []string{"before_commit", runner.StepBetweenRemovalBatches, runner.StepAfterRemoval} {
		t.Run(point, func(t *testing.T) {
			env := newRemovalEnv(t)
			env.traffic([]protofixture.Protocol{protofixture.OpenAIChat}, 2)
			ids := env.auditIDs()
			env.due()
			if point == "before_commit" {
				for _, statement := range []string{
					`CREATE FUNCTION fail_archive_removal() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected commit failure'; END $$`,
					`CREATE CONSTRAINT TRIGGER fail_archive_removal AFTER UPDATE ON archive_members DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW WHEN (NEW.state = 'hot_removed') EXECUTE FUNCTION fail_archive_removal()`,
				} {
					if _, err := env.db.Exec(statement); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				crash := func(step string) error {
					if step == point {
						return errors.New("crash")
					}
					return nil
				}
				env.step.Store(&crash)
			}
			first, err := env.run()
			env.step.Store(nil)
			if err == nil && first.Status == storage.ArchiveRunCompleted {
				t.Fatalf("the run did not stop: %+v", first)
			}
			env.requireNoUnrecordedRemoval()
			hot := len(env.auditIDs())
			switch point {
			case "before_commit":
				if first.Reason != "removal_failed" || hot != len(ids) || env.count(`SELECT COUNT(*) FROM archive_members WHERE state = 'sealed'`) != len(ids) {
					t.Fatalf("failed commit: %+v, %d hot", first, hot)
				}
				for _, statement := range []string{`DROP TRIGGER fail_archive_removal ON archive_members`, `DROP FUNCTION fail_archive_removal()`} {
					if _, err := env.db.Exec(statement); err != nil {
						t.Fatal(err)
					}
				}
			case runner.StepBetweenRemovalBatches:
				if hot == 0 || hot == len(ids) {
					t.Fatalf("%d of %d hot after a crash between batches", hot, len(ids))
				}
			case runner.StepAfterRemoval:
				if hot != 0 || env.count(`SELECT COUNT(*) FROM archive_runs WHERE status = 'running'`) != 1 {
					t.Fatalf("%d hot after the last batch", hot)
				}
			}
			second := env.mustRun()
			if second.Removal.Removed != int64(hot) || second.Removal.AlreadyGone != 0 || second.Removal.Stale != 0 || len(env.auditIDs()) != 0 {
				t.Fatalf("second run %+v after %d hot", second.Removal, hot)
			}
			if env.count(`SELECT COUNT(*) FROM archive_members WHERE state = 'hot_removed'`) != len(ids) {
				t.Fatal("not every member is hot_removed once")
			}
			env.requireNoUnrecordedRemoval()
		})
	}
}

// Option B of R.9 on PostgreSQL: after the export, one conversation bundle
// loses its objects file. In the removal of the same run that bundle fails
// its check: its members stay sealed and every row of theirs stays in the
// hot store, the other bundles' members are removed, and the run completes
// with the segment counted and logged with a stable code. Once the file is
// back, the next run removes them.
func TestPostgresArchiveRemovalHoldsBackADamagedBundle(t *testing.T) {
	env := newRemovalEnv(t)
	env.traffic([]protofixture.Protocol{protofixture.OpenAIChat, protofixture.AnthropicMessages}, 4)
	ids := env.auditIDs()
	env.due()
	var held []string
	var objects string
	damage := func(step string) error {
		if step != runner.StepBeforeRecordPass || objects != "" {
			return nil
		}
		reader, _ := env.readArchive()
		for _, entry := range reader.Index().Bundles() {
			if entry.Manifest.BundleKind != "conversation" || objects != "" {
				continue
			}
			for _, file := range entry.Manifest.Files {
				if file.Role == "objects" {
					objects = filepath.Join(filepath.Dir(entry.ManifestPath), file.Name)
				}
			}
			for _, member := range entry.Manifest.Members {
				held = append(held, member.AuditID)
			}
		}
		if objects == "" {
			t.Fatal("no conversation bundle with an objects file")
		}
		if err := os.Rename(objects, objects+".aside"); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	env.step.Store(&damage)
	before := map[string]map[string]int{}
	result := env.mustRun()
	env.step.Store(nil)
	removal := result.Removal
	if removal.BundleCheckFailedSegments != 1 || removal.HeldBackMembers != int64(len(held)) || removal.Removed != int64(len(ids)-len(held)) ||
		removal.Stale != 0 || removal.Skipped != 0 {
		t.Fatalf("removal %+v, %d held", removal, len(held))
	}
	if hot := env.auditIDs(); len(hot) != len(held) {
		t.Fatalf("%d audits hot, %d held back", len(hot), len(held))
	}
	for _, id := range held {
		var state string
		if err := env.db.QueryRow(`SELECT state FROM archive_members WHERE audit_id = $1`, id).Scan(&state); err != nil || state != storage.ArchiveMemberSealed {
			t.Fatalf("%s member %q (%v)", id, state, err)
		}
		before[id] = map[string]int{}
		for _, table := range []string{"audit_records", "http_stages", "body_streams", "body_chunks", "parsed_results", "turns", "integrity_events"} {
			before[id][table] = env.count(`SELECT COUNT(*) FROM `+table+` WHERE audit_id = $1`, id)
		}
		if before[id]["audit_records"] != 1 || before[id]["turns"] != 1 || before[id]["integrity_events"] == 0 {
			t.Fatalf("%s rows %v", id, before[id])
		}
	}
	env.requireNoUnrecordedRemoval()
	logs := env.logs.String()
	if strings.Count(logs, `"error_category":"archive_bundle_check_failed"`) != 1 || !strings.Contains(logs, `"reason":"file_missing"`) ||
		!strings.Contains(logs, `"bundle_check_failed_segments":1`) || strings.Contains(logs, env.cfg.Archive.Dir) {
		t.Fatalf("logs %s", logs)
	}

	if err := os.Rename(objects+".aside", objects); err != nil {
		t.Fatal(err)
	}
	next := env.mustRun()
	if next.Removal.Removed != int64(len(held)) || next.Removal.BundleCheckFailedSegments != 0 || len(env.auditIDs()) != 0 {
		t.Fatalf("next run %+v", next.Removal)
	}
}
