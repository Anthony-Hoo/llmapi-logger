package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

func (store *Store) QueryStreamTimeline(ctx context.Context, auditID, stage string) (StoredStreamTimeline, error) {
	if ctx == nil {
		return StoredStreamTimeline{}, errors.New("sqlite: nil context")
	}
	if auditID == "" || !validStage(stage) {
		return StoredStreamTimeline{}, errors.New("sqlite: invalid stream timeline identity")
	}
	if store == nil || store.isClosed() {
		return StoredStreamTimeline{}, ErrClosed
	}
	var result StoredStreamTimeline
	var first, last sql.NullInt64
	var complete int
	err := store.readerDB.QueryRowContext(ctx, `
SELECT t.audit_id, t.stage, b.observed_length, t.event_count,
       t.first_event_at_ns, t.last_event_at_ns, t.timeline_complete,
       t.compression, t.plaintext_length, t.timeline_enc
FROM body_streams AS b
JOIN stream_timelines AS t
  ON t.audit_id = b.audit_id AND t.stage = b.source_stage
WHERE b.audit_id = ? AND b.stage = ?`, auditID, stage).Scan(
		&result.AuditID,
		&result.Stage,
		&result.ObservedLength,
		&result.EventCount,
		&first,
		&last,
		&complete,
		&result.Compression,
		&result.PlaintextLength,
		&result.DataEnc,
	)
	if err != nil {
		return StoredStreamTimeline{}, fmt.Errorf("sqlite: read stream timeline: %w", err)
	}
	result.FirstEventAtNS = nullInt64Pointer(first)
	result.LastEventAtNS = nullInt64Pointer(last)
	result.Complete = complete != 0
	result.DataEnc = cloneBytes(result.DataEnc)
	return result, nil
}
