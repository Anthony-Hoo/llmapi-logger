package sqlite

import (
	"context"
	"database/sql"

	"llmapi-logger/internal/storage"
)

// Session analysis (doc/features/24-session-analysis.md) runs on PostgreSQL
// only. The SQLite store remains for legacy fixtures and offline import
// verification, so it answers the session analysis surface as an empty store.

func (store *Store) ListSessionCandidates(context.Context, int64, int64, int64, int) ([]storage.SessionCandidate, error) {
	return nil, nil
}

func (store *Store) LoadSessionAudits(context.Context, []byte, []byte) ([]storage.SessionAuditRow, bool, error) {
	return nil, false, nil
}

func (store *Store) SaveSessionSignals(context.Context, storage.SessionSignals, []storage.SessionTextFPR, *storage.SessionPack) error {
	return nil
}

func (store *Store) ListSessionProjects(context.Context, int64, int64, int) ([]storage.SessionProjectRef, error) {
	return nil, nil
}

func (store *Store) UpdateSessionProjects(context.Context, []storage.SessionProjectRef) error {
	return nil
}

func (store *Store) PruneSessionAnalysis(context.Context, int64, int64) (int64, error) {
	return 0, nil
}

func (store *Store) RecordSessionAnalysisRun(context.Context, storage.SessionAnalysisRun) error {
	return nil
}

func (store *Store) ListSessionSignals(context.Context, storage.SessionSignalFilter, storage.SessionSignalCursor, int) (storage.SessionSignalPage, error) {
	return storage.SessionSignalPage{Rows: []storage.SessionSignals{}}, nil
}

func (store *Store) SessionSignalTotals(context.Context, storage.SessionSignalFilter) (storage.SessionSignalTotals, error) {
	return storage.SessionSignalTotals{}, nil
}

func (store *Store) LatestSessionAnalysisRun(context.Context) (storage.SessionAnalysisRun, error) {
	return storage.SessionAnalysisRun{}, sql.ErrNoRows
}

func (store *Store) SaveSessionPack(context.Context, storage.SessionPack, [][]byte) error {
	return nil
}

func (store *Store) LoadSessionPack(context.Context, []byte) (storage.SessionPack, error) {
	return storage.SessionPack{}, sql.ErrNoRows
}

func (store *Store) ListChatDigestMembers(context.Context, []byte, string, int64, int64, int) ([]storage.SessionSignals, error) {
	return nil, nil
}

func (store *Store) ListPendingDigestMembers(context.Context, int) ([]storage.SessionSignals, error) {
	return nil, nil
}

func (store *Store) SaveChatDigests(context.Context, storage.ChatDigestBucket, []storage.ChatDigestChunk, [][]byte) error {
	return nil
}

func (store *Store) RecordAnalysisView(context.Context, storage.AnalysisView) error {
	return nil
}

func (store *Store) ListFacetCandidates(context.Context, int64, string, string, int) ([]storage.SessionPack, error) {
	return nil, nil
}

func (store *Store) SaveSessionFacet(context.Context, storage.SessionFacet, []storage.SessionTextFPR) error {
	return nil
}

func (store *Store) LoadSessionFacet(context.Context, []byte) (storage.SessionFacet, error) {
	return storage.SessionFacet{}, sql.ErrNoRows
}

func (store *Store) SaveFacetCalibration(context.Context, storage.FacetCalibration) error {
	return nil
}

func (store *Store) LatestFacetCalibration(context.Context, string, string) (storage.FacetCalibration, error) {
	return storage.FacetCalibration{}, sql.ErrNoRows
}

func (store *Store) ActiveAnalysisKeys(context.Context, int64, int64) ([]storage.ScopeKey, error) {
	return nil, nil
}

func (store *Store) ActiveAnalysisProjects(context.Context, int64, int64) ([]int64, error) {
	return nil, nil
}

func (store *Store) ListPeriodScopeKeys(context.Context, int64, string) ([][]byte, error) {
	return nil, nil
}

func (store *Store) FacetEnums(context.Context, int64, int64, storage.FacetScope) ([]storage.FacetEnumRow, error) {
	return nil, nil
}

func (store *Store) RepeatedFingerprints(context.Context, int64, storage.FacetScope, int) ([]storage.RepeatedFPR, error) {
	return nil, nil
}

func (store *Store) UpsertSuggestion(context.Context, storage.Suggestion) error {
	return nil
}

func (store *Store) ListSuggestions(context.Context, string, []byte, *int64, int) ([]storage.Suggestion, error) {
	return nil, nil
}

func (store *Store) DismissSuggestion(context.Context, int64, string, int64) error {
	return sql.ErrNoRows
}

func (store *Store) SavePeriodStats(context.Context, storage.PeriodStats) error {
	return nil
}

func (store *Store) LoadPeriodStats(context.Context, int64, string, []byte, *int64) (storage.PeriodStats, error) {
	return storage.PeriodStats{}, sql.ErrNoRows
}

func (store *Store) TopCostSessions(context.Context, storage.SessionSignalFilter, int) ([]storage.SessionSignals, error) {
	return nil, nil
}
