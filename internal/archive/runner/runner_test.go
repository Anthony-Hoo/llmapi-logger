package runner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/archive/bundle"
	"llmapi-logger/internal/storage"
)

const protocolChat = "openai.chat_completions"
const protocolMessages = "anthropic.messages"

// B.3: a conversation with conversation_min_turns due turns is its own
// bundle; a shorter one and the turnless audits go to one bucket per
// protocol, the turnless audits last. Lines keep (created_at_ns, audit_id)
// order, parents first. Every bundle verifies, every audit is in exactly one
// sealed member, and a second run exports nothing.
func TestRunGroupsIntoConversationAndBucketBundles(t *testing.T) {
	h := newHarness(t)
	long := h.addConversation("conv_long", protocolChat, 4, baseTimeNS)
	short := h.addConversation("conv_short", protocolChat, 2, baseTimeNS+100)
	other := h.addConversation("conv_other", protocolMessages, 1, baseTimeNS+200)
	loose := []*fakeAudit{h.addTurnless("loose-b", protocolChat, baseTimeNS+50), h.addTurnless("loose-a", protocolChat, baseTimeNS+50)}
	late := h.addTurnless("late", protocolChat, h.clock.Now().UnixNano())

	result := h.mustRun()
	if result.Counts.ExportedAudits != 9 || result.Counts.Segments != 3 || result.Counts.DeferredAudits != 0 {
		t.Fatalf("result %+v", result)
	}
	h.verifyAll()
	kinds := map[string][]string{}
	for _, entry := range h.bundles() {
		manifest := entry.Manifest
		var members []string
		for _, member := range manifest.Members {
			members = append(members, member.AuditID)
		}
		key := manifest.BundleKind + "/" + *manifest.Protocol
		kinds[key] = append(kinds[key], joined(members))
	}
	want := map[string]string{
		"conversation/" + protocolChat: joined(ids(long)),
		"bucket/" + protocolChat:       joined(append(ids(short), "loose-a", "loose-b")),
		"bucket/" + protocolMessages:   joined(ids(other)),
	}
	if len(kinds) != len(want) {
		t.Fatalf("bundles %v", kinds)
	}
	for key, members := range want {
		if got := kinds[key]; len(got) != 1 || got[0] != members {
			t.Fatalf("%s = %v, want %s", key, got, members)
		}
	}
	h.requireEachOnce(append(append(append(ids(long), ids(short)...), ids(other)...), ids(loose)...)...)
	if _, sealed := h.store.sealedMembers()[late.id]; sealed {
		t.Fatal("an audit after the cutoff was archived")
	}
	if !strings.Contains(h.logs.String(), `"msg":"archive run completed"`) || strings.Contains(h.logs.String(), h.dir) {
		t.Fatalf("completion log %s", h.logs.String())
	}

	again := h.mustRun()
	if again.Counts.ExportedAudits != 0 || again.Counts.Segments != 0 {
		t.Fatalf("second run %+v", again)
	}
	if len(h.bundles()) != 3 {
		t.Fatal("second run wrote a bundle")
	}
}

// B.3: below the turn threshold, a conversation whose due plaintext reaches
// conversation_min_bytes is a bundle of its own.
func TestConversationReachingTheByteThresholdIsItsOwnBundle(t *testing.T) {
	h := newHarness(t)
	h.options.ConversationMinTurns = 100
	big := h.addConversation("conv_big", protocolChat, 3, baseTimeNS)
	tiny := h.addConversation("conv_tiny", protocolChat, 1, baseTimeNS+100)
	// Twice what the one-turn conversation holds: three turns reach it.
	record := tiny[0].build()
	if err := record.Canonicalize(); err != nil {
		t.Fatal(err)
	}
	h.options.ConversationMinBytes = 2 * estimateBytes(record, map[string]bool{})
	h.mustRun()
	var conversation, bucket string
	for _, entry := range h.bundles() {
		var members []string
		for _, member := range entry.Manifest.Members {
			members = append(members, member.AuditID)
		}
		switch entry.Manifest.BundleKind {
		case archive.BundleConversation:
			conversation = joined(members)
		case archive.BundleBucket:
			bucket = joined(members)
		}
	}
	if conversation != joined(ids(big)) || bucket != joined(ids(tiny)) {
		t.Fatalf("conversation %q, bucket %q, files %q, threshold %d", conversation, bucket, h.files(), h.options.ConversationMinBytes)
	}
}

// B.4: a bundle rolls to the next segment once it passes segment_max_bytes;
// an audit never spans segments, and a child whose parent is in the earlier
// segment is written materialised (the bundle verifies on its own).
func TestBundlesRollBySize(t *testing.T) {
	h := newHarness(t)
	h.options.SegmentMaxBytes = 2000
	long := h.addConversation("conv_roll", protocolChat, 6, baseTimeNS)
	result := h.mustRun()
	if result.Counts.Segments < 2 {
		t.Fatalf("segments %d", result.Counts.Segments)
	}
	h.verifyAll()
	seen := map[string]int{}
	for _, entry := range h.bundles() {
		if !strings.Contains(entry.ManifestPath, "_s0001") && !strings.Contains(entry.ManifestPath, "_s0002") && !strings.Contains(entry.ManifestPath, "_s0003") &&
			!strings.Contains(entry.ManifestPath, "_s0004") && !strings.Contains(entry.ManifestPath, "_s0005") && !strings.Contains(entry.ManifestPath, "_s0006") {
			t.Fatalf("segment name %s", filepath.Base(entry.ManifestPath))
		}
		for _, member := range entry.Manifest.Members {
			seen[member.AuditID]++
		}
	}
	for _, id := range ids(long) {
		if seen[id] != 1 {
			t.Fatalf("audit %s in %d segments", id, seen[id])
		}
	}
	h.requireEachOnce(ids(long)...)
}

// B.1, B.2: passes of pass_audits along the watermark; the audits of a
// conversation the pass touches are completed past the watermark; every due
// audit is exported once over several passes.
func TestPassesFollowTheWatermark(t *testing.T) {
	h := newHarness(t)
	h.options.PassAudits = 2
	var all []string
	for index := 0; index < 5; index++ {
		all = append(all, h.addTurnless("a-"+string(rune('a'+index)), protocolChat, baseTimeNS+int64(index)).id)
	}
	conversation := h.addConversation("conv_w", protocolChat, 3, baseTimeNS+10)
	result := h.mustRun()
	if result.Counts.ExportedAudits != 8 {
		t.Fatalf("result %+v", result)
	}
	h.requireEachOnce(append(all, ids(conversation)...)...)
	watermark, _ := h.store.Watermark(context.Background(), 0)
	if watermark == nil || watermark.AuditID != conversation[2].id {
		t.Fatalf("watermark %+v", watermark)
	}
}

// Q8, H.4, R.6 item 18: an audit that is not terminal is deferred with its
// reason; an integrity exclusion is deferred integrity_failed and counted;
// an exclusion that is not an integrity failure is export_failed; a vanished
// audit is not deferred. Deferred audits are looked at again once per run
// and exported once they are due.
func TestDeferralsAndExclusions(t *testing.T) {
	h := newHarness(t)
	pending := h.addTurnless("pending", protocolChat, baseTimeNS+1)
	pending.deferral = storage.ArchiveDeferredParsePending
	caller := h.addTurnless("caller", protocolChat, baseTimeNS+2)
	caller.deferral = storage.ArchiveDeferredCallerPending
	tampered := h.addTurnless("tampered", protocolChat, baseTimeNS+3)
	tampered.exclusion, tampered.integrity = "event_mac", true
	timeline := h.addTurnless("timeline", protocolChat, baseTimeNS+4)
	timeline.exclusion = "timeline"
	gone := h.addTurnless("gone", protocolChat, baseTimeNS+5)
	gone.exclusion = "not_found"
	fine := h.addTurnless("fine", protocolChat, baseTimeNS+6)

	result := h.mustRun()
	if result.Counts.ExportedAudits != 1 || result.Counts.IntegrityFailedAudits != 1 || result.Counts.DeferredAudits != 4 || result.Excluded != 2 {
		t.Fatalf("result %+v", result)
	}
	want := map[string]string{"pending": storage.ArchiveDeferredParsePending, "caller": storage.ArchiveDeferredCallerPending,
		"tampered": storage.ArchiveDeferredIntegrityFailed, "timeline": storage.ArchiveDeferredExportFailed}
	if len(h.store.deferred) != len(want) {
		t.Fatalf("deferred %+v", h.store.deferred)
	}
	for id, reason := range want {
		if h.store.deferred[id].Reason != reason {
			t.Fatalf("deferred %s = %+v, want %s", id, h.store.deferred[id], reason)
		}
	}
	logs := h.logs.String()
	if !strings.Contains(logs, `"error_category":"archive_integrity_failed"`) || !strings.Contains(logs, `"deferred_integrity_failed":1`) ||
		!strings.Contains(logs, `"deferred_export_failed":1`) {
		t.Fatalf("logs %s", logs)
	}
	h.requireEachOnce(fine.id)

	// The parse finished and the tampered row was repaired: the next run
	// looks at the deferred audits again and exports them.
	pending.deferral, tampered.exclusion, tampered.integrity = "", "", false
	delete(h.store.audits, "caller")
	again := h.mustRun()
	if again.Counts.ExportedAudits != 2 {
		t.Fatalf("second run %+v", again)
	}
	h.requireEachOnce(fine.id, pending.id, tampered.id)
	if _, ok := h.store.deferred["caller"]; ok {
		t.Fatal("a vanished deferred audit stayed deferred")
	}
	if h.store.deferred["timeline"].Reason != storage.ArchiveDeferredExportFailed || len(h.store.deferred) != 1 {
		t.Fatalf("deferred after the second run %+v", h.store.deferred)
	}
}

// B.2: the run stops between passes at its deadline; the next run goes on
// from the watermark.
func TestRunStopsBetweenPassesAtTheDeadline(t *testing.T) {
	h := newHarness(t)
	h.options.PassAudits = 2
	h.options.RunDeadline = time.Minute
	for index := 0; index < 5; index++ {
		h.addTurnless("d-"+string(rune('a'+index)), protocolChat, baseTimeNS+int64(index))
	}
	h.options.Step = func(step string) error {
		if step == StepBeforeRecordPass {
			h.clock.advance(2 * time.Minute)
		}
		return nil
	}
	first := h.mustRun()
	if !first.DeadlineReached || first.Counts.ExportedAudits != 2 {
		t.Fatalf("first %+v", first)
	}
	h.options.Step = nil
	second := h.mustRun()
	if second.Counts.ExportedAudits != 3 {
		t.Fatalf("second %+v", second)
	}
	h.requireEachOnce("d-a", "d-b", "d-c", "d-d", "d-e")
}

// H.4: a full disk or an I/O error at any write step fails the run with
// archive_failed: no manifest is published, nothing is sealed, the writer's
// temporary files are gone and the audits stay due for the next run.
func TestWriteFailuresLeaveNothingPublished(t *testing.T) {
	for _, operation := range []string{bundle.FaultCreate, bundle.FaultWrite, bundle.FaultSync, bundle.FaultClose, bundle.FaultLink, bundle.FaultDirSync, bundle.FaultMkdir} {
		t.Run(operation, func(t *testing.T) {
			h := newHarness(t)
			conversation := h.addConversation("conv_f", protocolChat, 3, baseTimeNS)
			loose := h.addTurnless("loose", protocolChat, baseTimeNS+100)
			h.options.Fault = func(op, path string) error {
				if op == operation {
					return errors.New("injected: no space left on device")
				}
				return nil
			}
			result, err := h.run()
			if err == nil || result.Status != storage.ArchiveRunFailed {
				t.Fatalf("result %+v, %v", result, err)
			}
			files := h.files()
			if countMatching(files, func(file string) bool { return strings.HasSuffix(file, bundle.ManifestSuffix) }) != 0 || countMatching(files, isTemp) != 0 {
				t.Fatalf("files after a failed write: %q", files)
			}
			if len(h.store.sealedMembers()) != 0 {
				t.Fatal("a member was sealed")
			}
			if segments, _ := h.store.Segments(context.Background(), storage.ArchiveSegmentPublishing); len(segments) != 0 {
				t.Fatalf("intents left %+v", segments)
			}
			if !strings.Contains(h.logs.String(), `"error_category":"archive_failed"`) {
				t.Fatalf("logs %s", h.logs.String())
			}
			h.options.Fault = nil
			h.mustRun()
			h.requireEachOnce(append(ids(conversation), loose.id)...)
		})
	}
}

// H.4: an intent that cannot be registered discards the sealed files.
func TestIntentFailureDiscardsTheSegment(t *testing.T) {
	h := newHarness(t)
	h.addTurnless("only", protocolChat, baseTimeNS)
	h.store.fail["RegisterIntent"] = errors.New("writer unavailable")
	if result, err := h.run(); err == nil || result.Reason != "intent_failed" {
		t.Fatalf("result %+v, %v", result, err)
	}
	if files := h.files(); len(files) != 0 {
		t.Fatalf("files %q", files)
	}
	delete(h.store.fail, "RegisterIntent")
	h.mustRun()
	h.requireEachOnce("only")
}

// H.6: a run stopped after each step of a segment's publication is
// completed by the next run's reconciliation without a duplicate and
// without losing a member.
func TestReconciliationCompletesARunStoppedAtEachStep(t *testing.T) {
	for _, step := range []string{StepAfterIntent, StepAfterPublish, StepBeforeSeal, StepBeforeRecordPass} {
		t.Run(step, func(t *testing.T) {
			h := newHarness(t)
			conversation := h.addConversation("conv_c", protocolChat, 3, baseTimeNS)
			loose := h.addTurnless("loose", protocolChat, baseTimeNS+100)
			all := append(ids(conversation), loose.id)
			h.options.Step = func(name string) error {
				if name == step {
					return errors.New("crash")
				}
				return nil
			}
			if _, err := h.run(); !errors.Is(err, errCrash) {
				t.Fatalf("run error %v", err)
			}
			if h.store.runs[0].Status != storage.ArchiveRunRunning {
				t.Fatal("a crashed run was finished")
			}
			h.options.Step = nil
			result := h.mustRun()
			if h.store.runs[0].Status != storage.ArchiveRunInterrupted {
				t.Fatalf("old run %s", h.store.runs[0].Status)
			}
			h.verifyAll()
			h.requireEachOnce(all...)
			files := h.files()
			if countMatching(files, isTemp) != 0 {
				t.Fatalf("temporary files left %q", files)
			}
			manifests := countMatching(files, func(file string) bool { return strings.HasSuffix(file, bundle.ManifestSuffix) })
			members := 0
			for _, entry := range h.bundles() {
				members += len(entry.Manifest.Members)
			}
			if members != len(all) {
				t.Fatalf("%d members in %d manifests, want %d (files %q)", members, manifests, len(all), files)
			}
			switch step {
			case StepAfterIntent:
				if result.ReconciledSealed != 0 {
					t.Fatalf("result %+v", result)
				}
			case StepAfterPublish, StepBeforeSeal:
				if result.ReconciledSealed != 1 {
					t.Fatalf("reconciled %d", result.ReconciledSealed)
				}
			}
		})
	}
}

// H.6 item 1 resumes at H.2 step 6: a bundle published before a crash is
// sampled again before reconciliation seals it, and rejected when it differs.
func TestReconciliationSamplesBeforeSealing(t *testing.T) {
	h := newHarness(t)
	h.addTurnless("only", protocolChat, baseTimeNS)
	h.options.Step = func(step string) error {
		if step == StepAfterPublish {
			return errors.New("crash")
		}
		return nil
	}
	if _, err := h.run(); !errors.Is(err, errCrash) {
		t.Fatal(err)
	}
	h.options.Step = nil
	h.sampler.differ = func(string) bool { return true }
	result, err := h.run()
	if err == nil || result.Reason != "sample_mismatch" || result.ReconciledSealed != 0 {
		t.Fatalf("result %+v, %v", result, err)
	}
	if countMatching(h.files(), func(file string) bool { return strings.HasSuffix(file, bundle.RejectedSuffix) }) == 0 {
		t.Fatalf("files %q", h.files())
	}
	h.sampler.differ = nil
	h.mustRun()
	h.requireEachOnce("only")
}

// J.3: a sampled member that differs from the hot store voids the bundle
// (renamed .rejected, intent dropped) unless its change stamp shows it
// changed after the export, when it counts as stale and the bundle stands.
func TestSampleMismatch(t *testing.T) {
	t.Run("unchanged record voids the bundle", func(t *testing.T) {
		h := newHarness(t)
		h.addTurnless("only", protocolChat, baseTimeNS)
		h.sampler.differ = func(string) bool { return true }
		result, err := h.run()
		if err == nil || result.Reason != "sample_mismatch" {
			t.Fatalf("result %+v, %v", result, err)
		}
		files := h.files()
		if countMatching(files, func(file string) bool { return strings.HasSuffix(file, bundle.RejectedSuffix) }) == 0 ||
			countMatching(files, func(file string) bool { return strings.HasSuffix(file, bundle.ManifestSuffix) }) != 0 {
			t.Fatalf("files %q", files)
		}
		if len(h.store.segments) != 0 {
			t.Fatal("the intent was not dropped")
		}
		h.sampler.differ = nil
		h.mustRun()
		h.requireEachOnce("only")
	})
	t.Run("changed record is stale", func(t *testing.T) {
		h := newHarness(t)
		audit := h.addTurnless("only", protocolChat, baseTimeNS)
		h.sampler.differ = func(string) bool {
			audit.stamp = stampOf("only", 1) // a late write after the export
			return true
		}
		result := h.mustRun()
		if result.Counts.Segments != 1 || result.Counts.StaleAudits != 1 {
			t.Fatalf("result %+v", result)
		}
	})
}

// J.2: a bundle that fails the re-read after publication is rejected and
// its intent dropped; its audits stay due.
func TestRereadFailureRejectsTheBundle(t *testing.T) {
	h := newHarness(t)
	h.addTurnless("only", protocolChat, baseTimeNS)
	h.options.Step = func(step string) error {
		if step != StepAfterPublish {
			return nil
		}
		for _, file := range h.files() {
			if strings.HasSuffix(file, bundle.EncryptedSuffix) {
				path := filepath.Join(h.dir, filepath.FromSlash(file))
				data, _ := os.ReadFile(path)
				data[len(data)-1] ^= 1
				_ = os.Chmod(path, 0o600)
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
		return nil
	}
	result, err := h.run()
	if err == nil || result.Status != storage.ArchiveRunFailed {
		t.Fatalf("result %+v %v", result, err)
	}
	if len(h.store.segments) != 0 || countMatching(h.files(), func(file string) bool { return strings.HasSuffix(file, bundle.ManifestSuffix) }) != 0 {
		t.Fatalf("segments %+v files %q", h.store.segments, h.files())
	}
	h.options.Step = nil
	h.mustRun()
	h.requireEachOnce("only")
}

// H.6 item 2: bundles the catalog does not know (a catalog restored from a
// backup) are registered sealed with stale members, and the audits are
// selected again at the next revision.
func TestUnknownBundlesAreRegisteredStale(t *testing.T) {
	h := newHarness(t)
	conversation := h.addConversation("conv_u", protocolChat, 3, baseTimeNS)
	h.mustRun()
	restored := newFakeStore(h.fixture.payloads)
	restored.audits = h.store.audits
	h.store = restored
	h.options.Store = restored
	result := h.mustRun()
	if result.Counts.ExportedAudits != 3 {
		t.Fatalf("result %+v", result)
	}
	sealed := restored.sealedMembers()
	for _, id := range ids(conversation) {
		var states []string
		for _, member := range sealed[id] {
			states = append(states, member.State)
		}
		if joined(states) != "stale,sealed" && joined(states) != "sealed,stale" {
			t.Fatalf("%s members %+v", id, sealed[id])
		}
	}
	h.verifyAll()
}

// C.6: expired gaps are exported into one gap bundle and registered; a
// second run exports none, and export_only deletes nothing.
func TestGapsAreExportedOnce(t *testing.T) {
	h := newHarness(t)
	h.store.gaps = []archive.Gap{
		{ID: 1, StartedAtNS: baseTimeNS, EndedAtNS: baseTimeNS + 10, Reason: "db_unavailable", RequestCount: 2, Detail: "", CreatedAtNS: baseTimeNS + 11},
		{ID: 2, StartedAtNS: baseTimeNS + 20, EndedAtNS: baseTimeNS + 30, Reason: "queue_full", RequestCount: 1, Detail: "", CreatedAtNS: baseTimeNS + 31},
		{ID: 3, StartedAtNS: h.clock.Now().UnixNano(), EndedAtNS: h.clock.Now().UnixNano() + 1, Reason: "queue_full", RequestCount: 1, CreatedAtNS: h.clock.Now().UnixNano() + 2},
	}
	result := h.mustRun()
	if result.ExportedGaps != 2 || len(h.store.gapMembers) != 2 || len(h.store.gaps) != 3 {
		t.Fatalf("result %+v gaps %+v", result, h.store.gapMembers)
	}
	h.verifyAll()
	if again := h.mustRun(); again.ExportedGaps != 0 {
		t.Fatalf("second run %+v", again)
	}
}

// A run stopped by its context leaves the catalog row running (the next
// run marks it interrupted) and nothing half-published.
func TestCancelledRunIsLeftRunning(t *testing.T) {
	h := newHarness(t)
	h.addConversation("conv_x", protocolChat, 3, baseTimeNS)
	ctx, cancel := context.WithCancel(context.Background())
	h.options.Step = func(step string) error {
		if step == StepAfterIntent {
			cancel()
		}
		return nil
	}
	runner := h.runner()
	if _, err := runner.RunOnce(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	if h.store.runs[0].Status != storage.ArchiveRunRunning {
		t.Fatal("cancelled run was finished")
	}
	h.options.Step = nil
	h.mustRun()
	h.verifyAll()
	h.requireEachOnce("conv_x-t00", "conv_x-t01", "conv_x-t02")
}

// A run never overlaps another.
func TestRunNeverOverlaps(t *testing.T) {
	h := newHarness(t)
	h.addTurnless("only", protocolChat, baseTimeNS)
	runner := h.runner()
	entered := make(chan struct{})
	release := make(chan struct{})
	h.options.Step = nil
	runner.options.Step = func(step string) error {
		if step == StepAfterIntent {
			close(entered)
			<-release
		}
		return nil
	}
	done := make(chan error, 1)
	go func() {
		_, err := runner.RunOnce(context.Background())
		done <- err
	}()
	<-entered
	if _, err := runner.RunOnce(context.Background()); !errors.Is(err, ErrRunInProgress) {
		t.Fatalf("overlap err %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
