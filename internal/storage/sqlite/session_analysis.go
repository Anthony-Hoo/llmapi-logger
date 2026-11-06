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

func (store *Store) LoadSessionAudits(context.Context, []byte) ([]storage.SessionAuditRow, bool, error) {
	return nil, false, nil
}

func (store *Store) SaveSessionSignals(context.Context, storage.SessionSignals, []storage.SessionTextFPR) error {
	return nil
}

func (store *Store) PruneSessionAnalysis(context.Context, int64) (int64, error) {
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

func (store *Store) RecordAnalysisView(context.Context, storage.AnalysisView) error {
	return nil
}
