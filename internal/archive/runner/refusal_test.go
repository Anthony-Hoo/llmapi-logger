package runner

import (
	"context"
	"errors"
	"strings"
	"testing"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/archive/bundle"
	"llmapi-logger/internal/storage"
)

// linesOf reads every verified line of every bundle, by audit.
func (h *harness) linesOf() map[string]*archive.Record {
	h.t.Helper()
	out := map[string]*archive.Record{}
	for _, entry := range h.bundles() {
		opened, err := bundle.Open(entry.ManifestPath, bundle.ReadOptions{Signer: h.options.Keys, EncryptionKey: h.options.Keys.EncryptionKey()})
		if err != nil {
			h.t.Fatal(err)
		}
		if _, err := opened.Verify(context.Background()); err != nil {
			h.t.Fatal(err)
		}
		if err := opened.Records(context.Background(), func(line bundle.Line) error {
			out[line.Record.Audit.AuditID] = line.Record
			return nil
		}); err != nil {
			h.t.Fatal(err)
		}
	}
	return out
}

// A record the writer refuses after its line is written (a raw chunk that
// differs from the line: payload_mismatch) leaves the segment aborted. The
// runner excludes that member only, defers it export_failed, rebuilds the
// segment from the other members in the same pass, and the children of the
// refused turn are written in materialised form. The watermark advances and
// the next run does not fail.
func TestRefusedParentLeavesItsChildrenMaterialised(t *testing.T) {
	h := newHarness(t)
	audits := h.addConversation("conv_r", protocolChat, 4, baseTimeNS)
	parent := audits[1]
	record := parent.build()
	h.fixture.withRaw(record, storage.StageResponseReceived, []byte("raw of the parent"), 5)
	// The snapshot hands the writer a different chunk than the line names.
	h.fixture.payloads.chunks[chunkID{parent.id, storage.StageResponseReceived, 1}] = []byte("XXXXX")
	loose := h.addTurnless("loose", protocolChat, baseTimeNS+100)

	result := h.mustRun()
	if result.Refused != 1 || result.Excluded != 1 || result.Counts.ExportedAudits != 4 || result.Counts.Segments != 2 {
		t.Fatalf("result %+v", result)
	}
	if h.store.deferred[parent.id].Reason != storage.ArchiveDeferredExportFailed || len(h.store.deferred) != 1 {
		t.Fatalf("deferred %+v", h.store.deferred)
	}
	h.requireEachOnce(audits[0].id, audits[2].id, audits[3].id, loose.id)
	if _, archived := h.store.sealedMembers()[parent.id]; archived {
		t.Fatal("the refused member was archived")
	}
	lines := h.linesOf()
	if _, ok := lines[parent.id]; ok {
		t.Fatal("a bundle holds the refused record")
	}
	if form := lines[audits[2].id].Turn.Context.Form; form != archive.ContextMaterialized {
		t.Fatalf("child of the refused turn written in %s form", form)
	}
	if form := lines[audits[3].id].Turn.Context.Form; form != archive.ContextDelta {
		t.Fatalf("grandchild written in %s form", form)
	}
	if !strings.Contains(h.logs.String(), `"error_category":"archive_record_refused"`) ||
		!strings.Contains(h.logs.String(), `"reason":"payload_mismatch"`) || !strings.Contains(h.logs.String(), `"refused_audits":1`) {
		t.Fatalf("logs %s", h.logs.String())
	}
	watermark, _ := h.store.Watermark(context.Background(), h.runner().FormatVersion())
	if watermark == nil || watermark.AuditID != audits[3].id { // the last audit by start
		t.Fatalf("watermark %+v", watermark)
	}
	files := h.files()
	if countMatching(files, isTemp) != 0 {
		t.Fatalf("temporary files %q", files)
	}
	// The deferred re-check of the next run tries it once more: still
	// refused, still deferred, and the run completes.
	again := h.mustRun()
	if again.Refused != 1 || again.Counts.ExportedAudits != 0 || h.store.deferred[parent.id].Reason != storage.ArchiveDeferredExportFailed {
		t.Fatalf("second run %+v", again)
	}
}

// A refusal before anything of the record is written (the record is
// outside the bundle's conversation: invalid_record) excludes it the same
// way, and the rest of the conversation bundle is sealed.
func TestRefusalBeforeTheLineIsWritten(t *testing.T) {
	h := newHarness(t)
	audits := h.addConversation("conv_q", protocolChat, 3, baseTimeNS)
	stray := audits[2]
	other := h.fixture.withTurn(h.fixture.audit(stray.id, protocolChat, stray.startedNS), "conv_elsewhere", nil, *stray.turnCreatedNS, "stray")
	stray.build = func() *archive.Record { return other }
	result := h.mustRun()
	if result.Refused != 1 || result.Counts.ExportedAudits != 2 || h.store.deferred[stray.id].Reason != storage.ArchiveDeferredExportFailed {
		t.Fatalf("result %+v deferred %+v", result, h.store.deferred)
	}
	if !strings.Contains(h.logs.String(), `"reason":"invalid_record"`) {
		t.Fatalf("logs %s", h.logs.String())
	}
	h.requireEachOnce(audits[0].id, audits[1].id)
}

// An I/O failure is not a refusal: the run still fails as archive_failed and
// nothing is deferred.
func TestWriteFailureIsNotARefusal(t *testing.T) {
	h := newHarness(t)
	h.addTurnless("only", protocolChat, baseTimeNS)
	h.options.Fault = func(operation, path string) error {
		if operation == bundle.FaultWrite {
			return errors.New("injected")
		}
		return nil
	}
	result, err := h.run()
	if err == nil || result.Status != storage.ArchiveRunFailed || result.Refused != 0 || len(h.store.deferred) != 0 {
		t.Fatalf("result %+v, %v, deferred %+v", result, err, h.store.deferred)
	}
}

// J.3: one sampled member of a bucket reads back differently with its stamp
// unchanged. The bundle is rejected, that member deferred export_failed, and
// the other members are written into a new bundle in the same run.
func TestSampleMismatchDefersOneMemberAndRewritesTheRest(t *testing.T) {
	h := newHarness(t)
	for _, id := range []string{"m-a", "m-b", "m-c"} {
		h.addTurnless(id, protocolChat, baseTimeNS+int64(len(id)))
	}
	h.sampler.differ = func(id string) bool { return id == "m-b" }
	result := h.mustRun()
	if result.SampleMismatched != 1 || result.Counts.Segments != 1 || result.Counts.ExportedAudits != 2 {
		t.Fatalf("result %+v", result)
	}
	if h.store.deferred["m-b"].Reason != storage.ArchiveDeferredExportFailed || len(h.store.deferred) != 1 {
		t.Fatalf("deferred %+v", h.store.deferred)
	}
	h.requireEachOnce("m-a", "m-c")
	if countMatching(h.files(), func(file string) bool { return strings.HasSuffix(file, bundle.ManifestSuffix+bundle.RejectedSuffix) }) != 1 {
		t.Fatalf("files %q", h.files())
	}
	if len(h.bundles()) != 1 {
		t.Fatal("more than one live bundle")
	}
	// The next run's deferred re-check exports it once it reads back equal.
	h.sampler.differ = nil
	again := h.mustRun()
	if again.Counts.ExportedAudits != 1 || len(h.store.deferred) != 0 {
		t.Fatalf("second run %+v deferred %+v", again, h.store.deferred)
	}
	h.requireEachOnce("m-a", "m-b", "m-c")
}
