package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// UpsertTokenLink persists the non-secret caller identity obtained from the
// NewAPI system log and marks the lookup resolved in the same transaction.
func (store *Store) UpsertTokenLink(ctx context.Context, link TokenLink) error {
	if err := validateTokenLink(link); err != nil {
		return err
	}
	return store.submitSync(ctx, writeRequest{kind: writeUpsertTokenLink, data: link})
}

func upsertTokenLink(transaction *sql.Tx, link TokenLink) error {
	_, err := transaction.Exec(`
INSERT INTO token_links (
    audit_id, newapi_token_id, token_name, masked_key, linked_at_ns,
    newapi_user_id, username
) VALUES (?, ?, ?, '', ?, ?, ?)
ON CONFLICT(audit_id) DO UPDATE SET
    newapi_token_id = excluded.newapi_token_id,
    token_name = excluded.token_name,
    masked_key = '',
    linked_at_ns = excluded.linked_at_ns,
    newapi_user_id = excluded.newapi_user_id,
    username = excluded.username`,
		link.AuditID,
		link.NewAPITokenID,
		link.TokenName,
		link.LinkedAtNS,
		link.NewAPIUserID,
		link.Username,
	)
	if err != nil {
		return fmt.Errorf("sqlite writer: upsert token link: %w", err)
	}
	result, err := transaction.Exec(`
UPDATE audit_records
SET caller_status = ?, caller_attempts = ?, caller_next_at_ns = NULL,
    caller_updated_at_ns = ?
WHERE audit_id = ? AND newapi_request_id = ? AND caller_status = ?`,
		CallerResolved,
		link.Attempts,
		link.LinkedAtNS,
		link.AuditID,
		link.NewAPIRequestID,
		CallerPending,
	)
	if err != nil {
		return fmt.Errorf("sqlite writer: resolve caller lookup: %w", err)
	}
	return requireOneRow(result, "resolve caller lookup")
}

// RetryCallerLookup records one unsuccessful lookup. A nil next-at value marks
// the audit terminally unresolved; otherwise the same pending row is retried.
func (store *Store) RetryCallerLookup(ctx context.Context, retry CallerRetry) error {
	if err := validateCallerRetry(retry); err != nil {
		return err
	}
	return store.submitSync(ctx, writeRequest{kind: writeRetryCallerLookup, data: retry})
}

func retryCallerLookup(transaction *sql.Tx, retry CallerRetry) error {
	status := CallerPending
	if retry.NextAttemptAtNS == nil {
		status = CallerUnresolved
	}
	result, err := transaction.Exec(`
UPDATE audit_records
SET caller_status = ?, caller_attempts = ?, caller_next_at_ns = ?,
    caller_updated_at_ns = ?
WHERE audit_id = ? AND newapi_request_id = ? AND caller_status = ?`,
		status,
		retry.Attempts,
		retry.NextAttemptAtNS,
		retry.UpdatedAtNS,
		retry.AuditID,
		retry.RequestID,
		CallerPending,
	)
	if err != nil {
		return fmt.Errorf("sqlite writer: retry caller lookup: %w", err)
	}
	return requireOneRow(result, "retry caller lookup")
}

// ListDueCallerLookups returns persisted pending work in stable audit order.
func (store *Store) ListDueCallerLookups(ctx context.Context, nowNS int64, limit int) ([]CallerLookup, error) {
	if ctx == nil {
		return nil, errors.New("sqlite: nil context")
	}
	if store == nil || store.isClosed() {
		return nil, ErrClosed
	}
	if nowNS <= 0 || limit < 1 || limit > 1024 {
		return nil, errors.New("sqlite: invalid caller lookup scan")
	}
	rows, err := store.readerDB.QueryContext(ctx, `
SELECT audit_id, newapi_request_id, caller_attempts
FROM audit_records
WHERE caller_status = ? AND newapi_request_id IS NOT NULL
  AND caller_next_at_ns IS NOT NULL AND caller_next_at_ns <= ?
ORDER BY caller_next_at_ns, started_at_ns, audit_id
LIMIT ?`, CallerPending, nowNS, limit)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list due caller lookups: %w", err)
	}
	defer rows.Close()
	result := make([]CallerLookup, 0, limit)
	for rows.Next() {
		var item CallerLookup
		if err := rows.Scan(&item.AuditID, &item.RequestID, &item.Attempts); err != nil {
			return nil, fmt.Errorf("sqlite: scan due caller lookup: %w", err)
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate due caller lookups: %w", err)
	}
	return result, nil
}
