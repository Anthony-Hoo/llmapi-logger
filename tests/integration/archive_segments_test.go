package integration_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/archivecli"
	"llmapi-logger/internal/protofixture"
)

// moveBundle moves a bundle's manifest and data files out of the archive
// directory, into a directory of the test.
func moveBundle(t *testing.T, manifest, lines, objects string) {
	t.Helper()
	away := t.TempDir()
	for _, path := range []string{manifest, lines, objects} {
		if path == "" {
			continue
		}
		if err := os.Rename(path, filepath.Join(away, filepath.Base(path))); err != nil {
			t.Fatal(err)
		}
	}
}

// onlyBundle copies one bundle's three files into a new archive directory.
func onlyBundle(t *testing.T, root, manifest, lines, objects string) string {
	t.Helper()
	dir := t.TempDir()
	for _, path := range []string{manifest, lines, objects} {
		if path == "" {
			continue
		}
		relative, _ := filepath.Rel(root, path)
		target := filepath.Join(dir, relative)
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// Plan section 7 bullet 3, across runs: a conversation archived by two runs
// (the second with a branch: two children of one parent). With the first
// bundle's files moved away, the second bundle alone gives the complete
// context of each of its turns through the reader tool (its first turn, whose
// parent is in the first bundle, in materialised form), equal to the hot
// store in every J.3 kind, and export --conversation lists exactly its turns.
func TestArchiveLaterSegmentReadsAloneAcrossRuns(t *testing.T) {
	rig := newArchiveRig(t, archiveRigOptions{encrypt: true, minTurns: 1})
	conversation := protofixture.NewConversation(protofixture.OpenAIChat, false, protofixture.Options{Seed: 71}, 0)
	var first []string
	for range 3 {
		first = append(first, rig.send(conversation.Next(protofixture.ScenarioBasic, protofixture.Features{Tools: len(first) == 1})))
	}
	rig.due()
	rig.requireCleanRun(rig.mustRun(), 3)
	var second []string
	second = append(second, rig.send(conversation.Next(protofixture.ScenarioBasic, protofixture.Features{Image: true})))
	if !conversation.CanBranch() {
		t.Fatal("the conversation cannot branch here")
	}
	fork := conversation.Fork()
	second = append(second, rig.send(conversation.Next(protofixture.ScenarioBasic, protofixture.Features{})))
	second = append(second, rig.send(fork.Next(protofixture.ScenarioBasic, protofixture.Features{})))
	second = append(second, rig.send(conversation.Next(protofixture.ScenarioBasic, protofixture.Features{})))
	rig.requireCleanRun(rig.mustRun(), len(second))

	manifest, lines, objects := bundleOf(t, rig.dir, first[0])
	if again, _, _ := bundleOf(t, rig.dir, second[0]); again == manifest {
		t.Fatal("the two runs wrote one bundle")
	}
	moveBundle(t, manifest, lines, objects)
	reader := rig.reader(rig.dir)
	if _, err := reader.Audit(rig.ctx, first[0]); archivecli.ErrorCode(err) != "not_found" {
		t.Fatalf("the moved bundle's audit: %v", err)
	}
	comparison := rig.compare(reader, second)
	for _, difference := range comparison.differences {
		t.Error(difference)
	}
	if comparison.values["turn.request"] != len(second) || comparison.values["session"] != len(second) {
		t.Fatalf("too little compared:\n%s", comparison.report())
	}
	head, err := reader.Audit(rig.ctx, second[0])
	if err != nil {
		t.Fatal(err)
	}
	if head.Record.Turn.Context.Form != archive.ContextMaterialized || head.Record.Turn.Row.ParentTurnID == nil {
		t.Fatalf("the later segment's first turn is %s with parent %v", head.Record.Turn.Context.Form, head.Record.Turn.Row.ParentTurnID)
	}
	if pair := siblings(t, reader, second); pair == nil {
		rows, _ := rig.db.Query(`SELECT audit_id, COALESCE(parent_turn_id, '-'), parent_base, link_reason, request_item_count FROM turns ORDER BY created_at_ns`)
		for rows.Next() {
			var a, c, d, e string
			var n int
			_ = rows.Scan(&a, &c, &d, &e, &n)
			t.Logf("%s parent %s base %s reason %s items %d", a, c, d, e, n)
		}
		rows.Close()
		t.Fatal("no two turns of the later segment share a parent: the branch is not in it")
	}
	var out bytes.Buffer
	if err := archivecli.ExportConversationTurns(rig.ctx, reader, head.Record.Turn.Row.ConversationID, &out); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(out.String(), "\n"); lines != len(second) {
		t.Fatalf("export --conversation gives %d turns, want %d", lines, len(second))
	}
}

// Plan section 7 bullet 3, within one run: the runner rolls a segment as
// soon as it holds more than segment_max_bytes. Configuration allows 16 MiB
// at the least (config.MinArchiveSegmentMaxBytes), which these fixtures
// would need minutes to reach; the runner itself accepts any positive limit,
// so the test assembles it with a limit of one byte and every segment holds
// one record. A conversation with a branch therefore lies in one segment per
// turn, the two children of the branch in two different segments. Each
// segment, copied alone into an empty directory, reads every one of its
// turns completely and equal to the hot store; every turn but the root is
// materialised.
func TestArchiveSegmentsRollWithinARun(t *testing.T) {
	rig := newArchiveRig(t, archiveRigOptions{encrypt: true, minTurns: 1, segmentMaxBytes: 1})
	conversation := protofixture.NewConversation(protofixture.OpenAIChat, false, protofixture.Options{Seed: 72}, 0)
	var ids []string
	ids = append(ids, rig.send(conversation.Next(protofixture.ScenarioBasic, protofixture.Features{})))
	ids = append(ids, rig.send(conversation.Next(protofixture.ScenarioBasic, protofixture.Features{Image: true})))
	fork := conversation.Fork()
	ids = append(ids, rig.send(conversation.Next(protofixture.ScenarioBasic, protofixture.Features{})))
	ids = append(ids, rig.send(fork.Next(protofixture.ScenarioBasic, protofixture.Features{})))
	ids = append(ids, rig.send(conversation.Next(protofixture.ScenarioBasic, protofixture.Features{})))
	rig.due()
	result := rig.mustRun()
	rig.requireCleanRun(result, len(ids))
	if result.Counts.Segments != int64(len(ids)) {
		t.Fatalf("%d segments for %d audits", result.Counts.Segments, len(ids))
	}
	parents := map[string]string{}
	segments := map[string]string{}
	materialised := 0
	for _, id := range ids {
		manifest, lines, objects := bundleOf(t, rig.dir, id)
		segments[id] = manifest
		dir := onlyBundle(t, rig.dir, manifest, lines, objects)
		reader := rig.reader(dir)
		comparison := rig.compare(reader, []string{id})
		for _, difference := range comparison.differences {
			t.Errorf("segment alone: %s", difference)
		}
		if comparison.values["turn.request"] != 1 {
			t.Fatalf("%s: the rebuilt request was not compared:\n%s", id, comparison.report())
		}
		audit, err := reader.Audit(rig.ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if parent := audit.Record.Turn.Row.ParentTurnID; parent != nil {
			parents[id] = *parent
			if audit.Record.Turn.Context.Form != archive.ContextMaterialized {
				t.Fatalf("%s: a turn whose parent is in another segment is in %s form", id, audit.Record.Turn.Context.Form)
			}
			materialised++
		}
	}
	pair := siblingsOf(parents)
	if materialised != len(ids)-1 || pair == nil || segments[pair[0]] == segments[pair[1]] {
		t.Fatalf("branch not split across segments: parents %v", parents)
	}
}

// siblingsOf returns two audits whose turns have the same parent, by the
// map of audit id to parent turn id.
func siblingsOf(parents map[string]string) []string {
	byParent := map[string]string{}
	for id, parent := range parents {
		if other, ok := byParent[parent]; ok {
			return []string{other, id}
		}
		byParent[parent] = id
	}
	return nil
}

// siblings is siblingsOf for audits read from reader.
func siblings(t *testing.T, reader *archivecli.Reader, ids []string) []string {
	t.Helper()
	parents := map[string]string{}
	for _, id := range ids {
		audit, err := reader.Audit(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if parent := audit.Record.Turn.Row.ParentTurnID; parent != nil {
			parents[id] = *parent
		}
	}
	return siblingsOf(parents)
}
