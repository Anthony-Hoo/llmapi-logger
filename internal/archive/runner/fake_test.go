package runner

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/archivecli"
	"llmapi-logger/internal/storage"
)

// fakeAudit is one audit of the fake hot store.
type fakeAudit struct {
	id            string
	startedNS     int64
	protocol      string
	conversation  *string
	turnCreatedNS *int64
	deferral      string
	exclusion     string
	integrity     bool
	stamp         [32]byte
	build         func() *archive.Record
	// parent is the audit of the parent turn; removing it checkpoints this
	// audit, which changes its stamp (remove_test.go).
	parent string
}

// fakeStore is an in-memory hot store and catalog with the semantics R.6
// gives the PostgreSQL one, as far as the runner relies on them.
type fakeStore struct {
	mu         sync.Mutex
	payloads   *payloads
	audits     map[string]*fakeAudit
	gaps       []archive.Gap
	runs       []*storage.ArchiveRun
	segments   map[string]*storage.ArchiveSegment
	members    []*storage.ArchiveMember
	gapMembers map[int64]string
	deferred   map[string]storage.ArchiveDeferred
	// fail makes the named method return the error.
	fail map[string]error
	// The removal (remove_test.go): the batches in call order, the
	// checkpoints the removal of a parent caused, and the removed gaps.
	removalBatches [][]string
	checkpoints    int
	removedGaps    map[int64]bool
	calls          []string
}

func newFakeStore(payloads *payloads) *fakeStore {
	return &fakeStore{payloads: payloads, audits: map[string]*fakeAudit{}, segments: map[string]*storage.ArchiveSegment{},
		gapMembers: map[int64]string{}, deferred: map[string]storage.ArchiveDeferred{}, fail: map[string]error{}, removedGaps: map[int64]bool{}}
}

func (store *fakeStore) injected(method string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.fail[method]
}

func (store *fakeStore) currentLocked(auditID string, formatVersion int64) bool {
	for _, member := range store.members {
		if member.AuditID == auditID && member.State != storage.ArchiveMemberStale && store.segments[member.SegmentID].FormatVersion == formatVersion {
			return true
		}
	}
	return false
}

func (store *fakeStore) candidateLocked(audit *fakeAudit, formatVersion int64) storage.ArchiveCandidate {
	next := int64(1)
	for _, member := range store.members {
		if member.AuditID == audit.id && member.Revision >= next {
			next = member.Revision + 1
		}
	}
	return storage.ArchiveCandidate{AuditID: audit.id, StartedAtNS: audit.startedNS, Protocol: audit.protocol, ConversationID: audit.conversation,
		TurnCreatedAtNS: audit.turnCreatedNS, Deferral: audit.deferral, Current: store.currentLocked(audit.id, formatVersion), NextRevision: next}
}

func (store *fakeStore) sortedAudits() []*fakeAudit {
	all := make([]*fakeAudit, 0, len(store.audits))
	for _, audit := range store.audits {
		all = append(all, audit)
	}
	sort.Slice(all, func(left, right int) bool {
		a, b := all[left], all[right]
		if a.startedNS != b.startedNS {
			return a.startedNS < b.startedNS
		}
		return a.id < b.id
	})
	return all
}

// --- Store ---

func (store *fakeStore) OpenSnapshot(context.Context) (Snapshot, error) {
	if err := store.injected("OpenSnapshot"); err != nil {
		return nil, err
	}
	return &fakeSnapshot{store: store}, nil
}

func (store *fakeStore) BeginRun(_ context.Context, run storage.ArchiveRun) (int64, error) {
	if err := storage.ValidateArchiveRun(run); err != nil {
		return 0, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	var interrupted int64
	for _, old := range store.runs {
		if old.Status == storage.ArchiveRunRunning {
			old.Status = storage.ArchiveRunInterrupted
			interrupted++
		}
	}
	owned := run
	store.runs = append(store.runs, &owned)
	return interrupted, nil
}

func (store *fakeStore) runLocked(runID string) *storage.ArchiveRun {
	for _, run := range store.runs {
		if run.RunID == runID {
			return run
		}
	}
	return nil
}

func (store *fakeStore) FinishRun(_ context.Context, finish storage.ArchiveRunFinish) error {
	if err := storage.ValidateArchiveRunFinish(finish); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	run := store.runLocked(finish.RunID)
	if run == nil || run.Status != storage.ArchiveRunRunning {
		return errors.New("fake: run not running")
	}
	run.Status, run.Counts = finish.Status, finish.Counts
	finished := finish.FinishedAtNS
	run.FinishedAtNS = &finished
	return nil
}

func (store *fakeStore) RecordPass(_ context.Context, pass storage.ArchivePass) error {
	if err := store.injected("RecordPass"); err != nil {
		return err
	}
	if err := storage.ValidateArchivePass(pass); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	run := store.runLocked(pass.RunID)
	if run == nil || run.Status != storage.ArchiveRunRunning {
		return errors.New("fake: run not running")
	}
	if pass.Watermark != nil {
		watermark := *pass.Watermark
		run.Watermark = &watermark
	}
	if pass.Counts != nil {
		run.Counts = *pass.Counts
	}
	for _, row := range pass.Deferred {
		if old, ok := store.deferred[row.AuditID]; ok {
			row.FirstSeenAtNS = old.FirstSeenAtNS
		}
		store.deferred[row.AuditID] = row
	}
	for _, id := range pass.Resolved {
		delete(store.deferred, id)
	}
	return nil
}

func (store *fakeStore) RegisterIntent(_ context.Context, intent storage.ArchiveIntent) (storage.ArchiveIntentResult, error) {
	if err := store.injected("RegisterIntent"); err != nil {
		return storage.ArchiveIntentResult{}, err
	}
	if err := storage.ValidateArchiveIntent(intent); err != nil {
		return storage.ArchiveIntentResult{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.segments[intent.Segment.SegmentID]; exists {
		return storage.ArchiveIntentResult{}, errors.New("fake: segment exists")
	}
	for _, segment := range store.segments {
		if segment.ManifestName == intent.Segment.ManifestName {
			return storage.ArchiveIntentResult{}, errors.New("fake: manifest name exists")
		}
	}
	var result storage.ArchiveIntentResult
	var added []*storage.ArchiveMember
	for _, member := range intent.Members {
		for _, existing := range store.members {
			if existing.AuditID == member.AuditID && existing.Revision >= member.Revision {
				return storage.ArchiveIntentResult{}, errors.New("fake: revision not above existing")
			}
		}
		owned := member
		owned.SegmentID, owned.State = intent.Segment.SegmentID, storage.ArchiveMemberSealed
		audit, exists := store.audits[member.AuditID]
		if !exists || string(audit.stamp[:]) != string(member.ChangeStamp) {
			owned.State = storage.ArchiveMemberStale
			result.Stale = append(result.Stale, storage.ArchiveMemberKey{AuditID: member.AuditID, Revision: member.Revision})
		}
		for _, existing := range store.members {
			if existing.AuditID == member.AuditID && existing.State == storage.ArchiveMemberSealed {
				existing.State = storage.ArchiveMemberStale
				result.Superseded = append(result.Superseded, storage.ArchiveMemberKey{AuditID: existing.AuditID, Revision: existing.Revision})
			}
		}
		added = append(added, &owned)
	}
	for _, gapID := range intent.GapIDs {
		if _, exists := store.gapMembers[gapID]; exists {
			return storage.ArchiveIntentResult{}, errors.New("fake: gap exported twice")
		}
	}
	segment := intent.Segment
	store.segments[segment.SegmentID] = &segment
	store.members = append(store.members, added...)
	for _, gapID := range intent.GapIDs {
		store.gapMembers[gapID] = segment.SegmentID
	}
	return result, nil
}

func (store *fakeStore) SealSegment(_ context.Context, seal storage.ArchiveSeal) error {
	if err := store.injected("SealSegment"); err != nil {
		return err
	}
	if err := storage.ValidateArchiveSeal(seal); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	segment := store.segments[seal.SegmentID]
	if segment == nil || segment.State != storage.ArchiveSegmentPublishing {
		return errors.New("fake: not publishing")
	}
	segment.State, segment.ManifestSHA256, segment.DiskBytes = storage.ArchiveSegmentSealed, seal.ManifestSHA256, seal.DiskBytes
	sealed := seal.SealedAtNS
	segment.SealedAtNS = &sealed
	return nil
}

func (store *fakeStore) DropIntent(_ context.Context, segmentID string) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	segment := store.segments[segmentID]
	if segment == nil {
		return false, nil
	}
	if segment.State != storage.ArchiveSegmentPublishing {
		return false, errors.New("fake: only publishing")
	}
	delete(store.segments, segmentID)
	kept := store.members[:0]
	for _, member := range store.members {
		if member.SegmentID != segmentID {
			kept = append(kept, member)
		}
	}
	store.members = kept
	for gapID, owner := range store.gapMembers {
		if owner == segmentID {
			delete(store.gapMembers, gapID)
		}
	}
	return true, nil
}

func (store *fakeStore) RegisterReconciled(_ context.Context, reconciled storage.ArchiveReconciled) (storage.ArchiveReconciledResult, error) {
	if err := storage.ValidateArchiveReconciled(reconciled); err != nil {
		return storage.ArchiveReconciledResult{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.segments[reconciled.Segment.SegmentID]; exists {
		return storage.ArchiveReconciledResult{}, errors.New("fake: segment exists")
	}
	segment := reconciled.Segment
	store.segments[segment.SegmentID] = &segment
	var result storage.ArchiveReconciledResult
	for _, member := range reconciled.Members {
		duplicate := false
		for _, existing := range store.members {
			if existing.AuditID == member.AuditID && existing.Revision == member.Revision {
				duplicate = true
			}
		}
		if duplicate {
			result.SkippedMembers = append(result.SkippedMembers, storage.ArchiveMemberKey{AuditID: member.AuditID, Revision: member.Revision})
			continue
		}
		owned := member
		owned.SegmentID, owned.State = segment.SegmentID, storage.ArchiveMemberStale
		store.members = append(store.members, &owned)
	}
	for _, gapID := range reconciled.GapIDs {
		if _, exists := store.gapMembers[gapID]; exists {
			result.SkippedGaps = append(result.SkippedGaps, gapID)
			continue
		}
		store.gapMembers[gapID] = segment.SegmentID
	}
	return result, nil
}

func (store *fakeStore) Segment(_ context.Context, segmentID string) (storage.ArchiveSegment, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if segment, ok := store.segments[segmentID]; ok {
		return *segment, true, nil
	}
	return storage.ArchiveSegment{}, false, nil
}

func (store *fakeStore) Segments(_ context.Context, state string) ([]storage.ArchiveSegment, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	var out []storage.ArchiveSegment
	for _, segment := range store.segments {
		if segment.State == state {
			out = append(out, *segment)
		}
	}
	sort.Slice(out, func(left, right int) bool { return out[left].SegmentID < out[right].SegmentID })
	return out, nil
}

func (store *fakeStore) SegmentMembers(_ context.Context, segmentID string) ([]storage.ArchiveMember, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	var out []storage.ArchiveMember
	for _, member := range store.members {
		if member.SegmentID == segmentID {
			out = append(out, *member)
		}
	}
	return out, nil
}

func (store *fakeStore) SegmentGaps(_ context.Context, segmentID string) ([]int64, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	var out []int64
	for gapID, owner := range store.gapMembers {
		if owner == segmentID {
			out = append(out, gapID)
		}
	}
	return out, nil
}

func (store *fakeStore) HasCurrentMember(_ context.Context, auditID string) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, member := range store.members {
		if member.AuditID == auditID && member.State != storage.ArchiveMemberStale {
			return true, nil
		}
	}
	return false, nil
}

func (store *fakeStore) Deferred(_ context.Context, after string, limit int) ([]storage.ArchiveDeferred, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	var out []storage.ArchiveDeferred
	for _, row := range store.deferred {
		if row.AuditID > after {
			out = append(out, row)
		}
	}
	sort.Slice(out, func(left, right int) bool { return out[left].AuditID < out[right].AuditID })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (store *fakeStore) LastCompletedRun(context.Context) (*storage.ArchiveRun, error) {
	if err := store.injected("LastCompletedRun"); err != nil {
		return nil, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for index := len(store.runs) - 1; index >= 0; index-- {
		if store.runs[index].Status == storage.ArchiveRunCompleted {
			run := *store.runs[index]
			return &run, nil
		}
	}
	return nil, nil
}

func (store *fakeStore) AnyRun(context.Context) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.runs) > 0, nil
}

func (store *fakeStore) Watermark(_ context.Context, formatVersion int64) (*storage.ArchivePosition, error) {
	if err := store.injected("Watermark"); err != nil {
		return nil, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for index := len(store.runs) - 1; index >= 0; index-- {
		if run := store.runs[index]; run.FormatVersion == formatVersion && run.Watermark != nil {
			watermark := *run.Watermark
			return &watermark, nil
		}
	}
	return nil, nil
}

func (store *fakeStore) ChangeStamp(_ context.Context, auditID string) ([32]byte, bool, error) {
	if err := store.injected("ChangeStamp"); err != nil {
		return [32]byte{}, false, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	audit, ok := store.audits[auditID]
	if !ok {
		return [32]byte{}, false, nil
	}
	return audit.stamp, true, nil
}

// --- Snapshot ---

type fakeSnapshot struct {
	store  *fakeStore
	closed bool
}

func (snapshot *fakeSnapshot) ContentObject(hash []byte) (archive.ContentObject, error) {
	return snapshot.store.payloads.ContentObject(hash)
}

func (snapshot *fakeSnapshot) BinaryObject(hash []byte) (archive.BinaryObject, error) {
	return snapshot.store.payloads.BinaryObject(hash)
}

func (snapshot *fakeSnapshot) RawChunk(auditID, stage string, seq int64) ([]byte, error) {
	return snapshot.store.payloads.RawChunk(auditID, stage, seq)
}

func (snapshot *fakeSnapshot) Due(after *storage.ArchivePosition, cutoffNS, formatVersion int64, limit int) (storage.ArchiveDuePage, error) {
	store := snapshot.store
	store.mu.Lock()
	defer store.mu.Unlock()
	var page storage.ArchiveDuePage
	for _, audit := range store.sortedAudits() {
		if audit.startedNS >= cutoffNS {
			continue
		}
		if after != nil && (audit.startedNS < after.StartedAtNS || audit.startedNS == after.StartedAtNS && audit.id <= after.AuditID) {
			continue
		}
		if len(page.Candidates) == limit {
			page.More = true
			break
		}
		page.Candidates = append(page.Candidates, store.candidateLocked(audit, formatVersion))
	}
	if count := len(page.Candidates); count > 0 {
		last := page.Candidates[count-1]
		page.Last = &storage.ArchivePosition{StartedAtNS: last.StartedAtNS, AuditID: last.AuditID}
	}
	return page, nil
}

func (snapshot *fakeSnapshot) Candidates(ids []string, formatVersion int64) ([]storage.ArchiveCandidate, error) {
	store := snapshot.store
	store.mu.Lock()
	defer store.mu.Unlock()
	var out []storage.ArchiveCandidate
	for _, id := range ids {
		if audit, ok := store.audits[id]; ok {
			out = append(out, store.candidateLocked(audit, formatVersion))
		}
	}
	return out, nil
}

func (snapshot *fakeSnapshot) ConversationCandidates(ids []string, cutoffNS, formatVersion int64) ([]storage.ArchiveCandidate, error) {
	store := snapshot.store
	store.mu.Lock()
	defer store.mu.Unlock()
	wanted := map[string]bool{}
	for _, id := range ids {
		wanted[id] = true
	}
	var out []storage.ArchiveCandidate
	for _, audit := range store.sortedAudits() {
		if audit.conversation != nil && wanted[*audit.conversation] && audit.startedNS < cutoffNS {
			out = append(out, store.candidateLocked(audit, formatVersion))
		}
	}
	return out, nil
}

func (snapshot *fakeSnapshot) StaleCandidates(cutoffNS, formatVersion int64, after string, limit int) ([]storage.ArchiveCandidate, error) {
	store := snapshot.store
	store.mu.Lock()
	defer store.mu.Unlock()
	var out []storage.ArchiveCandidate
	ids := make([]string, 0, len(store.audits))
	for id := range store.audits {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		audit := store.audits[id]
		hasStale := false
		for _, member := range store.members {
			if member.AuditID == id && member.State == storage.ArchiveMemberStale {
				hasStale = true
			}
		}
		if hasStale && !store.currentLocked(id, formatVersion) && audit.startedNS < cutoffNS && id > after && len(out) < limit {
			out = append(out, store.candidateLocked(audit, formatVersion))
		}
	}
	return out, nil
}

func (snapshot *fakeSnapshot) Export(auditID string, revision int64) (*Export, error) {
	store := snapshot.store
	store.mu.Lock()
	audit, ok := store.audits[auditID]
	store.mu.Unlock()
	if !ok {
		return nil, &Exclusion{AuditID: auditID, Reason: "not_found"}
	}
	if audit.exclusion != "" {
		return nil, &Exclusion{AuditID: auditID, Reason: audit.exclusion, Integrity: audit.integrity}
	}
	record := audit.build()
	record.Revision = revision
	if err := record.Canonicalize(); err != nil {
		return nil, err
	}
	digest, err := archive.Digest(record)
	if err != nil {
		return nil, err
	}
	return &Export{Record: record, Digest: digest, ChangeStamp: audit.stamp, TurnCreatedAtNS: audit.turnCreatedNS}, nil
}

func (snapshot *fakeSnapshot) DueGaps(cutoffNS, afterID int64, limit int) ([]archive.Gap, error) {
	store := snapshot.store
	store.mu.Lock()
	defer store.mu.Unlock()
	var out []archive.Gap
	for _, gap := range store.gaps {
		if _, exported := store.gapMembers[gap.ID]; !exported && gap.EndedAtNS < cutoffNS && gap.ID > afterID && len(out) < limit {
			out = append(out, gap)
		}
	}
	return out, nil
}

func (snapshot *fakeSnapshot) Close() error {
	snapshot.closed = true
	return nil
}

// fakeSampler answers every comparison with equal, or calls differ; fail,
// when set, makes the comparison impossible (the hot side cannot be read).
type fakeSampler struct {
	mu       sync.Mutex
	differ   func(auditID string) bool
	fail     func(auditID string) error
	compared []string
}

func (sampler *fakeSampler) Compare(_ context.Context, audit *archivecli.AuditRecord) (bool, error) {
	sampler.mu.Lock()
	defer sampler.mu.Unlock()
	id := audit.Record.Audit.AuditID
	sampler.compared = append(sampler.compared, id)
	if sampler.fail != nil {
		if err := sampler.fail(id); err != nil {
			return false, err
		}
	}
	return sampler.differ == nil || !sampler.differ(id), nil
}

func (sampler *fakeSampler) comparedCount(id string) int {
	sampler.mu.Lock()
	defer sampler.mu.Unlock()
	count := 0
	for _, compared := range sampler.compared {
		if compared == id {
			count++
		}
	}
	return count
}

// sealedMembers lists, per audit, the members in sealed segments.
func (store *fakeStore) sealedMembers() map[string][]storage.ArchiveMember {
	store.mu.Lock()
	defer store.mu.Unlock()
	out := map[string][]storage.ArchiveMember{}
	for _, member := range store.members {
		if store.segments[member.SegmentID].State == storage.ArchiveSegmentSealed {
			out[member.AuditID] = append(out[member.AuditID], *member)
		}
	}
	return out
}

func joined(values []string) string { return strings.Join(values, ",") }
