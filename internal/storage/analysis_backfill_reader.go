package storage

// AnalysisBackfillCursor is the keyset position after which the next backfill
// page continues. Pages run oldest first, so the cursor only moves forwards.
type AnalysisBackfillCursor struct {
	StartedAtNS int64
	AuditID     string
}

// AnalysisBackfillCandidate names one parsed audit that has no current
// audit_analysis row.
type AnalysisBackfillCandidate struct {
	AuditID     string
	StartedAtNS int64
}
