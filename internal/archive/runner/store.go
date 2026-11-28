package runner

import (
	"context"
	"database/sql"
	"errors"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/archive/bundle"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/postgres"
)

// Store is what a run reads and writes: the export snapshot and the catalog
// (design I, R.6). FromPostgres adapts the PostgreSQL store; the tests use
// fakes.
type Store interface {
	// OpenSnapshot begins one export snapshot (H.2 step 1).
	OpenSnapshot(ctx context.Context) (Snapshot, error)

	BeginRun(ctx context.Context, run storage.ArchiveRun) (int64, error)
	FinishRun(ctx context.Context, finish storage.ArchiveRunFinish) error
	RecordPass(ctx context.Context, pass storage.ArchivePass) error
	RegisterIntent(ctx context.Context, intent storage.ArchiveIntent) (storage.ArchiveIntentResult, error)
	SealSegment(ctx context.Context, seal storage.ArchiveSeal) error
	DropIntent(ctx context.Context, segmentID string) (bool, error)
	RegisterReconciled(ctx context.Context, reconciled storage.ArchiveReconciled) (storage.ArchiveReconciledResult, error)

	// Segment returns one segment; found is false for an unknown id.
	Segment(ctx context.Context, segmentID string) (segment storage.ArchiveSegment, found bool, err error)
	// Segments returns every segment in state.
	Segments(ctx context.Context, state string) ([]storage.ArchiveSegment, error)
	// SegmentMembers returns the member rows of a conversation or bucket
	// segment, SegmentGaps the gap ids of a gaps segment.
	SegmentMembers(ctx context.Context, segmentID string) ([]storage.ArchiveMember, error)
	SegmentGaps(ctx context.Context, segmentID string) ([]int64, error)
	// HasCurrentMember reports whether the audit has a member that is not
	// stale.
	HasCurrentMember(ctx context.Context, auditID string) (bool, error)
	// Deferred pages the deferred audits in audit_id order.
	Deferred(ctx context.Context, after string, limit int) ([]storage.ArchiveDeferred, error)
	// LastCompletedRun is the completed run that started last, nil if none.
	LastCompletedRun(ctx context.Context) (*storage.ArchiveRun, error)
	// AnyRun reports whether the catalog has any run (guard 3).
	AnyRun(ctx context.Context) (bool, error)
	Watermark(ctx context.Context, formatVersion int64) (*storage.ArchivePosition, error)
	// ChangeStamp is the audit's change stamp as the hot store holds it now.
	ChangeStamp(ctx context.Context, auditID string) ([32]byte, bool, error)
}

// Snapshot is one export snapshot: the selection queries, the export of one
// audit and, as bundle.Payloads, the plaintext the segment writer asks for.
type Snapshot interface {
	bundle.Payloads
	Due(after *storage.ArchivePosition, cutoffNS, formatVersion int64, limit int) (storage.ArchiveDuePage, error)
	Candidates(auditIDs []string, formatVersion int64) ([]storage.ArchiveCandidate, error)
	ConversationCandidates(conversationIDs []string, cutoffNS, formatVersion int64) ([]storage.ArchiveCandidate, error)
	StaleCandidates(cutoffNS, formatVersion int64, after string, limit int) ([]storage.ArchiveCandidate, error)
	// Export reads one audit. An exclusion of this audit alone is an
	// *Exclusion; any other error is a failure of the snapshot.
	Export(auditID string, revision int64) (*Export, error)
	DueGaps(cutoffNS, afterID int64, limit int) ([]archive.Gap, error)
	Close() error
}

// Export is one exported audit (postgres.ArchiveExport).
type Export struct {
	Record          *archive.Record
	Digest          [32]byte
	ChangeStamp     [32]byte
	TurnCreatedAtNS *int64
}

// Exclusion excludes one audit from the export (postgres.ArchiveMemberError).
// Integrity reports an integrity failure; the store has then already set its
// payload state to failed (P item 4), so the runner does not do it again.
type Exclusion struct {
	AuditID   string
	Reason    string
	Integrity bool
}

func (exclusion *Exclusion) Error() string {
	return "archive runner: audit excluded: " + exclusion.Reason
}

// PostgresStore is the method set of *postgres.Store the adapter uses.
type PostgresStore interface {
	OpenArchiveSnapshot(context.Context, postgres.ArchiveSnapshotOptions) (*postgres.ArchiveSnapshot, error)
	BeginArchiveRun(context.Context, postgres.ArchiveRun) (int64, error)
	FinishArchiveRun(context.Context, postgres.ArchiveRunFinish) error
	RecordArchivePass(context.Context, postgres.ArchivePass) error
	RegisterArchiveIntent(context.Context, postgres.ArchiveIntent) (postgres.ArchiveIntentResult, error)
	SealArchiveSegment(context.Context, postgres.ArchiveSeal) error
	DropArchiveIntent(context.Context, string) (bool, error)
	RegisterReconciledArchive(context.Context, postgres.ArchiveReconciled) (postgres.ArchiveReconciledResult, error)
	ArchiveSegment(context.Context, string) (postgres.ArchiveSegment, error)
	ListArchiveSegments(context.Context, string, string, int) ([]postgres.ArchiveSegment, error)
	ListArchiveMembers(context.Context, postgres.ArchiveMemberQuery) ([]postgres.ArchiveMember, error)
	ListArchiveGapMembers(context.Context, string, string, int64, int) ([]postgres.ArchiveGapMember, error)
	ListArchiveDeferred(context.Context, string, int) ([]postgres.ArchiveDeferred, error)
	LastArchiveRun(context.Context, string) (*postgres.ArchiveRun, error)
	ArchiveWatermark(context.Context, int64) (*postgres.ArchivePosition, error)
	ArchiveChangeStamp(context.Context, string) ([32]byte, bool, error)
}

// FromPostgres adapts the PostgreSQL store. options carries the audit cipher
// and the credential fingerprinter (security.ArchiveKeys).
func FromPostgres(store PostgresStore, options postgres.ArchiveSnapshotOptions) Store {
	return &pgStore{store: store, options: options}
}

type pgStore struct {
	store   PostgresStore
	options postgres.ArchiveSnapshotOptions
}

// listPage is the page size of the catalog listings the adapter walks.
const listPage = 1000

func (adapter *pgStore) OpenSnapshot(ctx context.Context) (Snapshot, error) {
	snapshot, err := adapter.store.OpenArchiveSnapshot(ctx, adapter.options)
	if err != nil {
		return nil, err
	}
	return pgSnapshot{snapshot}, nil
}

func (adapter *pgStore) BeginRun(ctx context.Context, run storage.ArchiveRun) (int64, error) {
	return adapter.store.BeginArchiveRun(ctx, run)
}

func (adapter *pgStore) FinishRun(ctx context.Context, finish storage.ArchiveRunFinish) error {
	return adapter.store.FinishArchiveRun(ctx, finish)
}

func (adapter *pgStore) RecordPass(ctx context.Context, pass storage.ArchivePass) error {
	return adapter.store.RecordArchivePass(ctx, pass)
}

func (adapter *pgStore) RegisterIntent(ctx context.Context, intent storage.ArchiveIntent) (storage.ArchiveIntentResult, error) {
	return adapter.store.RegisterArchiveIntent(ctx, intent)
}

func (adapter *pgStore) SealSegment(ctx context.Context, seal storage.ArchiveSeal) error {
	return adapter.store.SealArchiveSegment(ctx, seal)
}

func (adapter *pgStore) DropIntent(ctx context.Context, segmentID string) (bool, error) {
	return adapter.store.DropArchiveIntent(ctx, segmentID)
}

func (adapter *pgStore) RegisterReconciled(ctx context.Context, reconciled storage.ArchiveReconciled) (storage.ArchiveReconciledResult, error) {
	return adapter.store.RegisterReconciledArchive(ctx, reconciled)
}

func (adapter *pgStore) Segment(ctx context.Context, segmentID string) (storage.ArchiveSegment, bool, error) {
	segment, err := adapter.store.ArchiveSegment(ctx, segmentID)
	if errors.Is(err, sql.ErrNoRows) {
		return storage.ArchiveSegment{}, false, nil
	}
	return segment, err == nil, err
}

func (adapter *pgStore) Segments(ctx context.Context, state string) ([]storage.ArchiveSegment, error) {
	var all []storage.ArchiveSegment
	after := ""
	for {
		page, err := adapter.store.ListArchiveSegments(ctx, state, after, listPage)
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		if len(page) < listPage {
			return all, nil
		}
		after = page[len(page)-1].SegmentID
	}
}

func (adapter *pgStore) SegmentMembers(ctx context.Context, segmentID string) ([]storage.ArchiveMember, error) {
	var all []storage.ArchiveMember
	var after *storage.ArchiveMemberKey
	for {
		page, err := adapter.store.ListArchiveMembers(ctx, postgres.ArchiveMemberQuery{SegmentID: segmentID, After: after, Limit: listPage})
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		if len(page) < listPage {
			return all, nil
		}
		last := page[len(page)-1]
		after = &storage.ArchiveMemberKey{AuditID: last.AuditID, Revision: last.Revision}
	}
}

func (adapter *pgStore) SegmentGaps(ctx context.Context, segmentID string) ([]int64, error) {
	var all []int64
	var after int64
	for {
		page, err := adapter.store.ListArchiveGapMembers(ctx, segmentID, "", after, listPage)
		if err != nil {
			return nil, err
		}
		for _, gap := range page {
			all = append(all, gap.GapID)
		}
		if len(page) < listPage {
			return all, nil
		}
		after = page[len(page)-1].GapID
	}
}

// HasCurrentMember lists the members after (auditID, 0): the audit's own
// rows come first, in revision order.
func (adapter *pgStore) HasCurrentMember(ctx context.Context, auditID string) (bool, error) {
	after := &storage.ArchiveMemberKey{AuditID: auditID}
	for {
		page, err := adapter.store.ListArchiveMembers(ctx, postgres.ArchiveMemberQuery{After: after, Limit: 100})
		if err != nil {
			return false, err
		}
		for _, member := range page {
			if member.AuditID != auditID {
				return false, nil
			}
			if member.State != storage.ArchiveMemberStale {
				return true, nil
			}
		}
		if len(page) < 100 {
			return false, nil
		}
		last := page[len(page)-1]
		after = &storage.ArchiveMemberKey{AuditID: last.AuditID, Revision: last.Revision}
	}
}

func (adapter *pgStore) Deferred(ctx context.Context, after string, limit int) ([]storage.ArchiveDeferred, error) {
	return adapter.store.ListArchiveDeferred(ctx, after, limit)
}

func (adapter *pgStore) LastCompletedRun(ctx context.Context) (*storage.ArchiveRun, error) {
	return adapter.store.LastArchiveRun(ctx, storage.ArchiveRunCompleted)
}

func (adapter *pgStore) AnyRun(ctx context.Context) (bool, error) {
	run, err := adapter.store.LastArchiveRun(ctx, "")
	return run != nil, err
}

func (adapter *pgStore) Watermark(ctx context.Context, formatVersion int64) (*storage.ArchivePosition, error) {
	return adapter.store.ArchiveWatermark(ctx, formatVersion)
}

func (adapter *pgStore) ChangeStamp(ctx context.Context, auditID string) ([32]byte, bool, error) {
	return adapter.store.ArchiveChangeStamp(ctx, auditID)
}

type pgSnapshot struct{ *postgres.ArchiveSnapshot }

func (snapshot pgSnapshot) Export(auditID string, revision int64) (*Export, error) {
	exported, err := snapshot.ArchiveSnapshot.Export(auditID, revision)
	if err != nil {
		var member *postgres.ArchiveMemberError
		if errors.As(err, &member) {
			return nil, &Exclusion{AuditID: member.AuditID, Reason: member.Reason, Integrity: member.Integrity()}
		}
		return nil, err
	}
	return &Export{Record: exported.Record, Digest: exported.Digest, ChangeStamp: exported.ChangeStamp, TurnCreatedAtNS: exported.TurnCreatedAtNS}, nil
}

var (
	_ Store         = (*pgStore)(nil)
	_ Snapshot      = pgSnapshot{}
	_ PostgresStore = (*postgres.Store)(nil)
)
