package integration_test

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/protofixture"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/postgres"
)

// exportNow exports one audit from a fresh export snapshot.
func (rig *archiveRig) exportNow(id string) *postgres.ArchiveExport {
	rig.t.Helper()
	snapshot, err := rig.store.OpenArchiveSnapshot(rig.ctx, postgres.ArchiveSnapshotOptions{Cipher: rig.cipher, Fingerprinter: rig.keys})
	if err != nil {
		rig.t.Fatal(err)
	}
	defer snapshot.Close()
	export, err := snapshot.Export(id, 1)
	if err != nil {
		rig.t.Fatalf("export %s: %v", id, err)
	}
	return export
}

// recordSections names the sections of two records that differ.
func recordSections(left, right *archive.Record) []string {
	var differ []string
	pairs := map[string][2]any{
		"audit": {left.Audit, right.Audit}, "stages": {left.Stages, right.Stages}, "headers": {left.Headers, right.Headers},
		"bodies": {left.Bodies, right.Bodies}, "raw_chunks": {left.RawChunks, right.RawChunks}, "timelines": {left.Timelines, right.Timelines},
		"parsed_result": {left.ParsedResult, right.ParsedResult}, "token_link": {left.TokenLink, right.TokenLink},
		"conversation": {left.Conversation, right.Conversation}, "project_identity": {left.ProjectIdentity, right.ProjectIdentity},
		"integrity_events": {left.IntegrityEvents, right.IntegrityEvents},
	}
	if left.Turn != nil && right.Turn != nil {
		pairs["turn.row.parent_turn_id"] = [2]any{left.Turn.Row.ParentTurnID, right.Turn.Row.ParentTurnID}
		pairs["turn.row.parent_base"] = [2]any{left.Turn.Row.ParentBase, right.Turn.Row.ParentBase}
		pairs["turn.row.link_reason"] = [2]any{left.Turn.Row.LinkReason, right.Turn.Row.LinkReason}
		pairs["turn.row.link_confidence"] = [2]any{left.Turn.Row.LinkConfidence, right.Turn.Row.LinkConfidence}
		l, r := left.Turn.Row, right.Turn.Row
		l.ParentTurnID, r.ParentTurnID, l.ParentBase, r.ParentBase = nil, nil, "", ""
		l.LinkReason, r.LinkReason, l.LinkConfidence, r.LinkConfidence = "", "", 0, 0
		pairs["turn.row (other columns)"] = [2]any{l, r}
		pairs["turn.context"] = [2]any{left.Turn.Context, right.Turn.Context}
		pairs["turn.request_refs"] = [2]any{left.Turn.RequestRefs, right.Turn.RequestRefs}
		pairs["turn.response_items"] = [2]any{left.Turn.ResponseItems, right.Turn.ResponseItems}
		pairs["turn.objects"] = [2]any{left.Turn.Objects, right.Turn.Objects}
	} else {
		pairs["turn"] = [2]any{left.Turn, right.Turn}
	}
	for name, pair := range pairs {
		a, _ := json.Marshal(pair[0])
		b, _ := json.Marshal(pair[1])
		if string(a) != string(b) {
			differ = append(differ, name)
		}
	}
	sort.Strings(differ)
	return differ
}

// The lineage columns parent_turn_id and parent_base are "in the digest"
// (E.2, Q6), but the column coverage test on the live schema could only show
// that an arbitrary change excludes the audit (R.6 item 27). A legitimate
// change on PostgreSQL: retention deletes a turn's parent and its
// checkpoint rewrites the child as a root (retention_checkpoint). The
// child's record exported before and after differs in the lineage fields,
// its record digest and its change stamp change, and the export still
// passes the integrity re-check. The grandchild, whose own rows the delete
// does not touch, keeps its digest and stamp.
func TestArchiveLineageRewriteChangesDigestAndStamp(t *testing.T) {
	rig := newArchiveRig(t, archiveRigOptions{encrypt: true})
	conversation := protofixture.NewConversation(protofixture.OpenAIChat, false, protofixture.Options{Seed: 81}, 0)
	var ids []string
	for range 3 {
		ids = append(ids, rig.send(conversation.Next(protofixture.ScenarioBasic, protofixture.Features{})))
	}
	child, grandchild := ids[1], ids[2]
	beforeChild, beforeGrandchild := rig.exportNow(child), rig.exportNow(grandchild)
	if parent := beforeChild.Record.Turn.Row.ParentTurnID; parent == nil || beforeChild.Record.Turn.Row.ParentBase == "root" {
		t.Fatalf("the child is not linked to the first turn: %+v", beforeChild.Record.Turn.Row)
	}
	var cutoff int64
	if err := rig.db.QueryRow(`SELECT started_at_ns FROM audit_records WHERE audit_id = $1`, child).Scan(&cutoff); err != nil {
		t.Fatal(err)
	}
	deleted, err := rig.store.DeleteExpired(rig.ctx, cutoff, postgres.RetentionBatchLimit, 0)
	if err != nil || deleted.DeletedAudits != 1 {
		t.Fatalf("delete %+v: %v", deleted, err)
	}
	afterChild, afterGrandchild := rig.exportNow(child), rig.exportNow(grandchild)
	row := afterChild.Record.Turn.Row
	if row.ParentTurnID != nil || row.ParentBase != "root" || row.LinkReason != "retention_checkpoint" {
		t.Fatalf("the child after the delete: parent %v base %s reason %s", row.ParentTurnID, row.ParentBase, row.LinkReason)
	}
	sections := recordSections(beforeChild.Record, afterChild.Record)
	t.Logf("sections of the child's record changed by the checkpoint: %v", sections)
	if afterChild.Digest == beforeChild.Digest || afterChild.ChangeStamp == beforeChild.ChangeStamp {
		t.Fatalf("digest changed %v, stamp changed %v", afterChild.Digest != beforeChild.Digest, afterChild.ChangeStamp != beforeChild.ChangeStamp)
	}
	// The lineage change alone moves the digest: the after record with its
	// lineage put back as it was digests to the before record's value, when
	// nothing else of the record changed.
	restored := *afterChild.Record
	turn := *restored.Turn
	turn.Row = afterChild.Record.Turn.Row
	turn.Row.ParentTurnID, turn.Row.ParentBase = beforeChild.Record.Turn.Row.ParentTurnID, beforeChild.Record.Turn.Row.ParentBase
	turn.Row.LinkReason, turn.Row.LinkConfidence = beforeChild.Record.Turn.Row.LinkReason, beforeChild.Record.Turn.Row.LinkConfidence
	turn.Context = beforeChild.Record.Turn.Context
	restored.Turn = &turn
	if len(recordSections(beforeChild.Record, &restored)) == 0 {
		digest, err := archive.Digest(&restored)
		if err != nil || digest != beforeChild.Digest {
			t.Fatalf("restoring the lineage does not restore the digest (%v)", err)
		}
	} else {
		t.Logf("the checkpoint also changed %v; the digest change is not attributable to lineage alone", recordSections(beforeChild.Record, &restored))
	}
	for _, field := range []string{"parent_turn_id", "parent_base"} {
		changed := false
		for _, section := range sections {
			changed = changed || section == "turn.row."+field
		}
		if !changed {
			t.Fatalf("%s did not change", field)
		}
	}
	if afterGrandchild.Digest != beforeGrandchild.Digest || afterGrandchild.ChangeStamp != beforeGrandchild.ChangeStamp {
		t.Fatalf("the grandchild changed: sections %v", recordSections(beforeGrandchild.Record, afterGrandchild.Record))
	}
	if !reflect.DeepEqual(afterGrandchild.Record.Turn.Row.ParentTurnID, beforeGrandchild.Record.Turn.Row.ParentTurnID) {
		t.Fatal("the grandchild's parent changed")
	}
	if err := rig.store.VerifyIntegrityPayloads(rig.ctx); err != nil {
		t.Fatalf("payload verification after the checkpoint: %v", err)
	}
}

// The P3 gate's "conversation active during archiving" and "repeated run",
// with what internal/app's end-to-end test does not show: a new turn of a
// conversation arrives through the proxy while the run is writing that
// conversation's bundle (from the bundle writer's first file operation,
// after the export snapshot and before the intent). It is not in the bundle
// and not in the catalog, no member turns stale, the hot conversation still
// reads, and the next run archives it in a new bundle (materialised, its
// parent in the first) without touching the first. Two more runs change
// nothing on disk and nothing in the catalog but archive_runs. Across the
// export_only runs every row of every table of the hot store stays
// byte-identical (a per-table hash of every column), and the payload
// verification passes afterwards.
func TestArchiveRunsWhileTheConversationIsActive(t *testing.T) {
	rig := newArchiveRig(t, archiveRigOptions{encrypt: true, minTurns: 1})
	conversation := protofixture.NewConversation(protofixture.OpenAIChat, true, protofixture.Options{Seed: 82}, 0)
	var ids []string
	for range 3 {
		ids = append(ids, rig.send(conversation.Next(protofixture.ScenarioBasic, protofixture.Features{})))
	}
	gemini := protofixture.NewConversation(protofixture.Gemini, false, protofixture.Options{Seed: 83}, 1)
	for range 2 {
		ids = append(ids, rig.send(gemini.Next(protofixture.ScenarioBasic, protofixture.Features{})))
	}
	rig.due()
	late := ""
	arrive := func(operation, path string) error {
		if late == "" {
			late = rig.send(conversation.Next(protofixture.ScenarioBasic, protofixture.Features{}))
		}
		return nil
	}
	rig.fault.Store(&arrive)
	first := rig.mustRun()
	rig.fault.Store(nil)
	if late == "" {
		t.Fatal("no turn arrived during the run")
	}
	rig.requireCleanRun(first, len(ids))
	var members int
	if err := rig.db.QueryRow(`SELECT COUNT(*) FROM archive_members WHERE audit_id = $1`, late).Scan(&members); err != nil || members != 0 {
		t.Fatalf("the late turn has %d members (%v)", members, err)
	}
	reader := rig.reader(rig.dir)
	if _, err := reader.Audit(rig.ctx, late); err == nil {
		t.Fatal("the late turn is in a bundle")
	}
	if _, err := rig.hot.SessionConversation(rig.ctx, late); err != nil {
		t.Fatalf("the active conversation's new turn does not read: %v", err)
	}
	if _, err := rig.hot.ReconstructTurn(rig.ctx, late); err != nil {
		t.Fatalf("the new turn does not rebuild: %v", err)
	}
	for _, id := range ids {
		if _, err := rig.hot.ReconstructTurn(rig.ctx, id); err != nil {
			t.Fatalf("archived turn %s no longer rebuilds from the hot store: %v", id, err)
		}
	}

	filesBefore := rig.files()
	tablesBefore := rig.tableHashes()
	second := rig.mustRun()
	rig.requireCleanRun(second, 1)
	filesAfter := rig.files()
	for name, digest := range filesBefore {
		if filesAfter[name] != digest {
			t.Fatalf("the first run's file %s changed", name)
		}
	}
	reader = rig.reader(rig.dir)
	audit, err := reader.Audit(rig.ctx, late)
	if err != nil {
		t.Fatal(err)
	}
	if audit.Record.Turn.Context.Form != archive.ContextMaterialized || audit.Record.Turn.Row.ParentTurnID == nil {
		t.Fatalf("the late turn is in %s form, parent %v", audit.Record.Turn.Context.Form, audit.Record.Turn.Row.ParentTurnID)
	}
	comparison := rig.compare(reader, append(append([]string(nil), ids...), late))
	for _, difference := range comparison.differences {
		t.Error(difference)
	}

	catalog := rig.catalogRows()
	var runsBefore int
	if err := rig.db.QueryRow(`SELECT COUNT(*) FROM archive_runs`).Scan(&runsBefore); err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 2; round++ {
		again := rig.mustRun()
		if again.Counts.ExportedAudits != 0 || again.Counts.Segments != 0 || again.Counts.StaleAudits != 0 || again.Excluded != 0 {
			t.Fatalf("repeated run %d: %+v", round+3, again)
		}
	}
	if now := rig.files(); !reflect.DeepEqual(now, filesAfter) {
		t.Fatal("a repeated run changed the archive directory")
	}
	if now := rig.catalogRows(); now != catalog {
		t.Fatalf("a repeated run changed the catalog:\nbefore %s\nafter  %s", catalog, now)
	}
	var runs, completed int
	if err := rig.db.QueryRow(`SELECT COUNT(*), COUNT(*) FILTER (WHERE status = $1) FROM archive_runs`, storage.ArchiveRunCompleted).Scan(&runs, &completed); err != nil ||
		runs != runsBefore+2 || completed != runs {
		t.Fatalf("archive_runs %d (%d completed), before %d (%v)", runs, completed, runsBefore, err)
	}
	tablesAfter := rig.tableHashes()
	for table, digest := range tablesBefore {
		if tablesAfter[table] != digest {
			t.Errorf("export_only changed %s: %s -> %s", table, digest, tablesAfter[table])
		}
	}
	if len(tablesAfter) != len(tablesBefore) {
		t.Fatal("the set of tables changed")
	}
	if err := rig.store.VerifyIntegrityPayloads(rig.ctx); err != nil || rig.store.IntegrityPayloadState() == "failed" {
		t.Fatalf("payload verification after the runs: %v (%s)", err, rig.store.IntegrityPayloadState())
	}
	if err := rig.store.EnableIntegrity(rig.ctx, rig.key); err != nil {
		t.Fatalf("integrity chain after the runs: %v", err)
	}
}
