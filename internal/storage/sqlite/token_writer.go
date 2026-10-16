package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// UpsertTokenLink persists the non-secret caller identity and the billing
// result obtained from the NewAPI system log and marks the lookup resolved in
// the same transaction.
func (store *Store) UpsertTokenLink(ctx context.Context, link TokenLink) error {
	if err := validateTokenLink(link); err != nil {
		return err
	}
	return store.submitSync(ctx, writeRequest{kind: writeUpsertTokenLink, data: cloneTokenLink(link)})
}

func cloneTokenLink(link TokenLink) TokenLink {
	link.Quota = cloneInt64Pointer(link.Quota)
	link.BilledPromptTokens = cloneInt64Pointer(link.BilledPromptTokens)
	link.BilledCompletionTokens = cloneInt64Pointer(link.BilledCompletionTokens)
	if link.QuotaPerUnit != nil {
		value := *link.QuotaPerUnit
		link.QuotaPerUnit = &value
	}
	return link
}

func cloneInt64Pointer(value *int64) *int64 {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

func upsertTokenLink(transaction *sql.Tx, link TokenLink) error {
	_, err := transaction.Exec(`
INSERT INTO token_links (
    audit_id, newapi_user_id, username, newapi_token_id, token_name, linked_at_ns,
    billing_state, quota, quota_per_unit, billed_prompt_tokens, billed_completion_tokens
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(audit_id) DO UPDATE SET
    newapi_user_id = excluded.newapi_user_id,
    username = excluded.username,
    newapi_token_id = excluded.newapi_token_id,
    token_name = excluded.token_name,
    linked_at_ns = excluded.linked_at_ns,
    billing_state = excluded.billing_state,
    quota = excluded.quota,
    quota_per_unit = excluded.quota_per_unit,
    billed_prompt_tokens = excluded.billed_prompt_tokens,
    billed_completion_tokens = excluded.billed_completion_tokens`,
		link.AuditID,
		link.NewAPIUserID,
		link.Username,
		link.NewAPITokenID,
		link.TokenName,
		link.LinkedAtNS,
		link.BillingState,
		link.Quota,
		link.QuotaPerUnit,
		link.BilledPromptTokens,
		link.BilledCompletionTokens,
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

// UpdateTokenLinkBilling records one historical billing backfill result. It
// only touches the billing columns of a link that is still unchecked: the
// caller identity and audit_records.caller_status are never changed here.
func (store *Store) UpdateTokenLinkBilling(ctx context.Context, update BillingUpdate) error {
	if err := validateBillingUpdate(update); err != nil {
		return err
	}
	update.Quota = cloneInt64Pointer(update.Quota)
	update.BilledPromptTokens = cloneInt64Pointer(update.BilledPromptTokens)
	update.BilledCompletionTokens = cloneInt64Pointer(update.BilledCompletionTokens)
	if update.QuotaPerUnit != nil {
		value := *update.QuotaPerUnit
		update.QuotaPerUnit = &value
	}
	return store.submitSync(ctx, writeRequest{kind: writeUpdateTokenLinkBilling, data: update})
}

func updateTokenLinkBilling(transaction *sql.Tx, update BillingUpdate) error {
	result, err := transaction.Exec(`
UPDATE token_links
SET billing_state = ?, billing_attempts = ?, quota = ?, quota_per_unit = ?,
    billed_prompt_tokens = ?, billed_completion_tokens = ?
WHERE audit_id = ? AND billing_state = ?`,
		update.State,
		update.Attempts,
		update.Quota,
		update.QuotaPerUnit,
		update.BilledPromptTokens,
		update.BilledCompletionTokens,
		update.AuditID,
		BillingUnchecked,
	)
	if err != nil {
		return fmt.Errorf("sqlite writer: update token link billing: %w", err)
	}
	return requireOneRow(result, "update token link billing")
}

// NextBillingBackfill returns the newest unchecked token link, or false when
// none is left.
func (store *Store) NextBillingBackfill(ctx context.Context) (BillingBackfillItem, bool, error) {
	if ctx == nil {
		return BillingBackfillItem{}, false, errors.New("sqlite: nil context")
	}
	if store == nil || store.isClosed() {
		return BillingBackfillItem{}, false, ErrClosed
	}
	var item BillingBackfillItem
	err := store.readerDB.QueryRowContext(ctx, `
SELECT t.audit_id, a.newapi_request_id, t.billing_attempts
FROM token_links AS t
JOIN audit_records AS a ON a.audit_id = t.audit_id
WHERE t.billing_state = ? AND a.newapi_request_id IS NOT NULL
ORDER BY t.linked_at_ns DESC, t.audit_id
LIMIT 1`, BillingUnchecked).Scan(&item.AuditID, &item.RequestID, &item.Attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return BillingBackfillItem{}, false, nil
	}
	if err != nil {
		return BillingBackfillItem{}, false, fmt.Errorf("sqlite: next billing backfill: %w", err)
	}
	return item, true, nil
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

// ListDueCallerLookups returns persisted pending work in stable audit order,
// with the audit's response status for the billing rules.
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
SELECT audit_id, newapi_request_id, caller_attempts, status_code
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
		var status sql.NullInt64
		if err := rows.Scan(&item.AuditID, &item.RequestID, &item.Attempts, &status); err != nil {
			return nil, fmt.Errorf("sqlite: scan due caller lookup: %w", err)
		}
		if status.Valid {
			code := int(status.Int64)
			item.StatusCode = &code
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate due caller lookups: %w", err)
	}
	return result, nil
}
