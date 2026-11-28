package runner

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/archive/bundle"
	"llmapi-logger/internal/storage"
)

// safeComponent is the bundle package's rule for a conversation id or a
// protocol in a file name. A conversation whose id it refuses goes to the
// bucket, whose name does not carry the id.
var safeComponent = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// write groups the selected audits and writes them (B.3): a conversation
// with at least conversation_min_turns due turns, or whose due turns reach
// conversation_min_bytes, is a conversation bundle; the other conversations
// and the audits without a turn go to one bucket bundle per protocol. Each
// segment is published, checked and sealed as soon as it is complete.
func (work *pass) write(selected map[string]storage.ArchiveCandidate) error {
	conversations := map[string][]storage.ArchiveCandidate{}
	turnless := map[string][]storage.ArchiveCandidate{}
	for _, candidate := range selected {
		if candidate.ConversationID != nil {
			conversations[*candidate.ConversationID] = append(conversations[*candidate.ConversationID], candidate)
		} else {
			turnless[candidate.Protocol] = append(turnless[candidate.Protocol], candidate)
		}
	}
	ids := make([]string, 0, len(conversations))
	for id := range conversations {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		members := conversations[id]
		// R.5 item 4: (turns.created_at_ns, audit_id), parents first.
		sort.Slice(members, func(left, right int) bool {
			a, b := members[left], members[right]
			if *a.TurnCreatedAtNS != *b.TurnCreatedAtNS {
				return *a.TurnCreatedAtNS < *b.TurnCreatedAtNS
			}
			return a.AuditID < b.AuditID
		})
		if err := work.writeConversation(id, members); err != nil {
			return err
		}
	}
	protocols := make([]string, 0, len(turnless))
	for protocol := range turnless {
		protocols = append(protocols, protocol)
	}
	sort.Strings(protocols)
	for _, protocol := range protocols {
		members := turnless[protocol]
		sort.Slice(members, func(left, right int) bool {
			a, b := members[left], members[right]
			if a.StartedAtNS != b.StartedAtNS {
				return a.StartedAtNS < b.StartedAtNS
			}
			return a.AuditID < b.AuditID
		})
		for _, candidate := range members {
			item, err := work.export(candidate)
			if err != nil {
				return err
			}
			if item != nil {
				if err := work.bucket(protocol).add(item); err != nil {
					return err
				}
			}
		}
	}
	protocols = protocols[:0]
	for protocol := range work.buckets {
		protocols = append(protocols, protocol)
	}
	sort.Strings(protocols)
	for _, protocol := range protocols {
		if err := work.buckets[protocol].seal(); err != nil {
			return err
		}
	}
	return nil
}

// writeConversation writes the due audits of one conversation. Below the
// turn threshold the records are held (at most conversation_min_bytes of
// lines and objects, the metadata estimate of estimateBytes) until either
// the byte threshold makes the conversation a bundle of its own or the
// conversation ends and they go to the buckets.
func (work *pass) writeConversation(conversationID string, members []storage.ArchiveCandidate) error {
	options := work.run.options()
	own := safeComponent.MatchString(conversationID)
	for _, member := range members {
		own = own && member.Protocol == members[0].Protocol && safeComponent.MatchString(member.Protocol)
	}
	var target *sink
	if own && len(members) >= options.ConversationMinTurns {
		target = work.newSink(archive.BundleConversation, members[0].Protocol, conversationID)
	}
	var held []*exported
	var heldBytes int64
	seen := map[string]bool{}
	for _, member := range members {
		item, err := work.export(member)
		if err != nil {
			return err
		}
		if item == nil {
			continue
		}
		if target != nil {
			if err := target.add(item); err != nil {
				return err
			}
			continue
		}
		held = append(held, item)
		heldBytes += estimateBytes(item.export.Record, seen)
		if own && heldBytes >= options.ConversationMinBytes {
			target = work.newSink(archive.BundleConversation, members[0].Protocol, conversationID)
			for _, item := range held {
				if err := target.add(item); err != nil {
					return err
				}
			}
			held = nil
		}
	}
	if target != nil {
		return target.seal()
	}
	for _, item := range held {
		if err := work.bucket(item.candidate.Protocol).add(item); err != nil {
			return err
		}
	}
	return nil
}

// estimateBytes is what a held record adds to its conversation's archive
// plaintext: the line, the objects not counted yet and the raw chunks.
func estimateBytes(record *archive.Record, seen map[string]bool) int64 {
	var total int64
	if line, _, parts, err := archive.EncodeLine(record); err == nil {
		total += int64(len(line))
		for _, part := range parts {
			total += int64(len(part.Data))
		}
	}
	if turn := record.Turn; turn != nil {
		for _, object := range turn.Objects {
			if !seen[string(object.Hash)] {
				seen[string(object.Hash)] = true
				total += object.PlaintextLength
			}
		}
		for _, binary := range turn.Binaries {
			if !seen[string(binary.Hash)] {
				seen[string(binary.Hash)] = true
				total += binary.PlaintextLength
			}
		}
	}
	for _, chunk := range record.RawChunks {
		total += chunk.PlaintextLength
	}
	return total
}

func (work *pass) bucket(protocol string) *sink {
	if existing, ok := work.buckets[protocol]; ok {
		return existing
	}
	created := work.newSink(archive.BundleBucket, protocol, "")
	work.buckets[protocol] = created
	return created
}

func (work *pass) newSink(kind, protocol, conversationID string) *sink {
	created := &sink{work: work, kind: kind, protocol: protocol, conversation: conversationID}
	work.sinks = append(work.sinks, created)
	return created
}

// abort removes the temporary files of every open segment of the pass.
func (work *pass) abort() {
	for _, open := range work.sinks {
		open.abort()
	}
}

// sink is one bundle being written: its segments roll by size (B.4).
type sink struct {
	work         *pass
	kind         string
	protocol     string
	conversation string
	index        int
	writer       *bundle.SegmentWriter
	members      map[string]memberInfo
	// pending lists, in order, the candidates written to the current
	// segment, so the segment can be rebuilt from the snapshot when one
	// member has to leave it.
	pending []storage.ArchiveCandidate
}

// recordRefusals are the bundle writer's reasons that concern the record
// being added, not the files or the snapshot: the record fails the format's
// checks, its place in the segment order, its request context, or its
// payloads differ from its own line, or one entry is too large. Any other
// reason (I/O, a payload the snapshot cannot supply, names, closed writer)
// fails the run.
var recordRefusals = map[string]bool{
	bundle.ReasonInvalidRecord:   true,
	bundle.ReasonOrder:           true,
	bundle.ReasonContextMismatch: true,
	bundle.ReasonPayloadMismatch: true,
	bundle.ReasonEntryTooLarge:   true,
}

// add writes one member to the bundle. A refusal of the record itself
// excludes that member only: SegmentWriter.Add has then aborted the whole
// segment (an error is final and removes its files, so no partial record can
// be published), and the segment is rebuilt from its other members, read
// again from the still open snapshot. A child whose refused parent is no
// longer in the segment is written in materialised form by the writer.
func (target *sink) add(item *exported) error {
	work := target.work
	if target.writer == nil {
		// Segment numbers run on across the passes of a run: two passes'
		// buckets can cover the same seconds, and the name (which carries
		// the run id) must still differ.
		key := target.kind + "\x00" + target.protocol + "\x00" + target.conversation
		work.run.segmentIndex[key]++
		target.index = work.run.segmentIndex[key]
		options, release := work.run.writerOptions()
		writer, err := bundle.NewSegment(options, bundle.Spec{Kind: target.kind, Protocol: target.protocol, ConversationID: target.conversation, Index: target.index}, work.snapshot)
		release()
		if err != nil {
			return work.run.writeFailure(err)
		}
		target.writer, target.members = writer, map[string]memberInfo{}
	}
	if err := target.writer.Add(item.export.Record); err != nil {
		target.writer = nil // Add removed the segment's files
		if work.run.ctx.Err() != nil || !recordRefusals[bundle.ReasonOf(err)] {
			return work.run.writeFailure(err)
		}
		work.exclude(item.candidate.AuditID, "archive record refused", "archive_record_refused", bundle.ReasonOf(err))
		work.run.result.Refused++
		return target.rebuild("")
	}
	target.members[item.candidate.AuditID] = memberInfo{digest: item.export.Digest, stamp: item.export.ChangeStamp, turnCreated: item.export.TurnCreatedAtNS}
	target.pending = append(target.pending, item.candidate)
	if target.writer.Full() {
		return target.seal()
	}
	return nil
}

// rebuild writes the members of the dropped current segment again, in
// order, without skip. The new segment stays open as the old one was.
func (target *sink) rebuild(skip string) error {
	members := target.pending
	target.pending, target.members = nil, nil
	for _, candidate := range members {
		if candidate.AuditID == skip {
			continue
		}
		item, err := target.work.export(candidate)
		if err != nil {
			return err
		}
		if item == nil {
			continue
		}
		if err := target.add(item); err != nil {
			return err
		}
	}
	return nil
}

func (target *sink) seal() error {
	if target.writer == nil {
		return nil
	}
	work := target.work
	writer, members, pending := target.writer, target.members, target.pending
	target.writer, target.members, target.pending = nil, nil, nil
	sealed, err := writer.Seal()
	if err != nil {
		return work.run.writeFailure(err)
	}
	ids, err := work.run.commit(true, sealed, members, nil)
	work.exported = append(work.exported, ids...)
	var mismatch *failure
	if err != nil && errors.As(err, &mismatch) && mismatch.auditID != "" {
		// The bundle was rejected and its intent dropped. A bundle with a
		// member that does not read back equal must not stand, but the
		// member is one record: defer it and write the others again now.
		work.exclude(mismatch.auditID, "archive sample mismatch", "archive_sample_mismatch", "sample_mismatch")
		work.run.result.SampleMismatched++
		target.pending = pending
		if err := target.rebuild(mismatch.auditID); err != nil {
			return err
		}
		return target.seal()
	}
	return err
}

// exclude defers one member that the export read but the bundle cannot
// hold (export_failed) and logs it with a stable code and no id. The audit
// stays in the hot store; the deferred re-check of a later run looks at it
// again.
func (work *pass) exclude(auditID, message, category, reason string) {
	work.deferred[auditID] = storage.ArchiveDeferredExportFailed
	work.run.result.Excluded++
	work.run.options().Logger.Warn(message, "error_category", category, "reason", reason)
}

func (target *sink) abort() {
	if target.writer != nil {
		target.writer.Abort()
		target.writer = nil
	}
}

// writeFailure is the run error of a writer failure (H.4): the writer
// removed its temporary files; nothing was registered.
func (current *run) writeFailure(err error) error {
	if current.ctx.Err() != nil {
		return current.ctx.Err()
	}
	return fail("", err)
}

// writerOptions are the bundle writer's options; release clears the copy of
// the encryption key once the writer has taken its own.
func (current *run) writerOptions() (bundle.Options, func()) {
	options := current.options()
	writer := bundle.Options{
		Root: options.Dir, Signer: options.Keys, Encrypt: options.Encrypt, SegmentMaxBytes: options.SegmentMaxBytes,
		SourceSchemaVersion: options.SourceSchemaVersion, RunID: current.id, Now: options.Now, Fault: options.Fault,
	}
	if options.Encrypt {
		writer.EncryptionKey = options.Keys.EncryptionKey()
	}
	return writer, func() { clear(writer.EncryptionKey) }
}

func (current *run) readOptions() (bundle.ReadOptions, func()) {
	options := current.options()
	read := bundle.ReadOptions{Signer: options.Keys, EncryptionKey: options.Keys.EncryptionKey(), Events: options.Events}
	return read, func() { clear(read.EncryptionKey) }
}

// commit takes a sealed segment through H.2 steps 4 to 7: register the
// intent, publish, re-read (J.2) and sample (J.3), seal in the catalog. It
// returns the members' audit ids once the segment is sealed. On a failure
// after the intent it follows H.4: a bundle that fails the checks is
// rejected (renamed, never deleted) and its intent dropped; a failed seal
// leaves the published, checked segment to the next reconciliation.
func (current *run) commit(sample bool, sealed *bundle.Sealed, members map[string]memberInfo, gapIDs []int64) ([]string, error) {
	options := current.options()
	manifest := sealed.Manifest()
	path := sealed.ManifestPath()
	relative, err := filepath.Rel(options.Dir, path)
	if err != nil {
		sealed.Discard()
		return nil, fail("manifest_name", err)
	}
	nowNS := current.now().UnixNano()
	var diskBytes int64
	for _, file := range manifest.Files {
		diskBytes += file.Bytes
	}
	fingerprint := options.Keys.KeyFingerprint()
	first, last := manifest.FirstStartedAtNS, manifest.LastEndedAtNS
	intent := storage.ArchiveIntent{
		Segment: storage.ArchiveSegment{
			SegmentID: manifest.SegmentID, RunID: current.id, BundleKind: manifest.BundleKind, FormatVersion: current.runner.formatVersion,
			ManifestName: filepath.ToSlash(relative), KeyFingerprint: fingerprint[:], Encrypted: manifest.Encrypted,
			MemberCount: int64(len(manifest.Members) + len(gapIDs)), DiskBytes: diskBytes, FirstStartedAtNS: &first, LastEndedAtNS: &last,
			State: storage.ArchiveSegmentPublishing, CreatedAtNS: nowNS,
		},
		GapIDs: gapIDs,
	}
	ids := make([]string, 0, len(manifest.Members))
	for _, member := range manifest.Members {
		info := members[member.AuditID]
		intent.Members = append(intent.Members, storage.ArchiveMember{
			AuditID: member.AuditID, Revision: member.Revision, RecordDigest: bytes.Clone(member.RecordDigest[:]),
			ChangeStamp: bytes.Clone(info.stamp[:]), StartedAtNS: member.StartedAtNS, TurnCreatedAtNS: info.turnCreated, StateChangedAtNS: nowNS,
		})
		ids = append(ids, member.AuditID)
	}
	registered, err := options.Store.RegisterIntent(current.ctx, intent)
	if err != nil {
		sealed.Discard()
		if current.ctx.Err() != nil {
			return nil, current.ctx.Err()
		}
		return nil, fail("intent_failed", err)
	}
	if err := current.step(StepAfterIntent); err != nil {
		return nil, err
	}
	if err := sealed.Publish(); err != nil {
		current.dropIntent(manifest.SegmentID)
		return nil, fail("", err)
	}
	if err := current.step(StepAfterPublish); err != nil {
		return nil, err
	}
	stale := map[string]bool{}
	for _, key := range registered.Stale {
		stale[key.AuditID] = true
	}
	if err := current.check(path, members, gapIDs, stale, sample); err != nil {
		if current.ctx.Err() != nil {
			// Shutdown, not a bad bundle: the next reconciliation re-reads it.
			return nil, current.ctx.Err()
		}
		_ = bundle.Reject(path)
		current.dropIntent(manifest.SegmentID)
		return nil, err
	}
	if err := current.step(StepBeforeSeal); err != nil {
		return nil, err
	}
	digest, size, err := fileDigest(path)
	if err != nil {
		return nil, fail("seal_failed", err)
	}
	if err := options.Store.SealSegment(current.ctx, storage.ArchiveSeal{
		SegmentID: manifest.SegmentID, ManifestSHA256: digest[:], DiskBytes: diskBytes + size, SealedAtNS: current.now().UnixNano(),
	}); err != nil {
		if current.ctx.Err() != nil {
			return nil, current.ctx.Err()
		}
		return nil, fail("seal_failed", err)
	}
	counts := &current.result.Counts
	counts.Segments++
	counts.DiskBytes += diskBytes + size
	counts.StaleAudits += int64(len(registered.Stale))
	counts.ExportedAudits += int64(len(manifest.Members) - len(registered.Stale))
	return ids, nil
}

func (current *run) dropIntent(segmentID string) {
	// A drop that fails leaves a publishing intent whose manifest is gone:
	// the next reconciliation drops it.
	_, _ = current.options().Store.DropIntent(current.ctx, segmentID)
}

func fileDigest(path string) ([32]byte, int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return [32]byte{}, 0, err
	}
	return sha256.Sum256(data), int64(len(data)), nil
}

// check re-reads a published bundle (J.2) and compares each member's
// recomputed digest with the export snapshot's, or the gap count; then it
// runs the read-equivalence sample (J.3).
func (current *run) check(path string, members map[string]memberInfo, gapIDs []int64, stale map[string]bool, sample bool) error {
	read, release := current.readOptions()
	defer release()
	opened, err := bundle.Open(path, read)
	if err != nil {
		return fail("", err)
	}
	report, err := opened.Verify(current.ctx)
	if err != nil {
		return fail("", err)
	}
	if gapIDs != nil {
		if report.Gaps != int64(len(gapIDs)) {
			return fail("count_mismatch", errors.New("gap count differs"))
		}
		return nil
	}
	if len(report.Members) != len(members) {
		return fail("count_mismatch", errors.New("member count differs"))
	}
	for _, member := range report.Members {
		info, ok := members[member.AuditID]
		if !ok || info.digest != member.Digest {
			return fail("digest_mismatch", errors.New("recomputed digest differs from the snapshot's"))
		}
	}
	if !sample {
		return nil
	}
	return current.sample(opened, members, stale)
}
