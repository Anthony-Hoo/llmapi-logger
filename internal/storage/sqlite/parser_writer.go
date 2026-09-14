package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"llmapi-logger/internal/security"
)

var errInvalidParsedResult = errors.New("sqlite: invalid parsed result")

// ResetProcessingParses returns work left by an interrupted process to the
// pending state. It is intended to run once before the worker startup scan.
func (store *Store) ResetProcessingParses(ctx context.Context) error {
	return store.submitSync(ctx, writeRequest{kind: writeResetProcessingParses})
}

// ClaimPendingParse atomically moves one eligible audit from pending to
// processing. False means another worker already claimed it or it is ineligible.
func (store *Store) ClaimPendingParse(ctx context.Context, auditID string) (bool, error) {
	if auditID == "" {
		return false, errors.New("sqlite: empty audit id")
	}
	claim := &parseClaim{AuditID: auditID}
	if err := store.submitSync(ctx, writeRequest{kind: writeClaimPendingParse, data: claim}); err != nil {
		return false, err
	}
	return claim.Claimed, nil
}

// ReleaseProcessingParse records a save failure with persistent backoff, or
// stores a terminal error after five failures. The original raw is retained.
// The update is intentionally idempotent because a timed-out SaveParsedResult
// may still have committed before this recovery operation reaches the writer.
func (store *Store) ReleaseProcessingParse(ctx context.Context, auditID string) error {
	if auditID == "" {
		return errors.New("sqlite: empty audit id")
	}
	return store.submitSync(ctx, writeRequest{kind: writeReleaseProcessingParse, data: auditID})
}

// SaveParsedResult atomically overwrites the latest parsed result and moves
// the parent audit from processing to the same terminal parse status.
func (store *Store) SaveParsedResult(ctx context.Context, result ParsedResult) error {
	if err := validateParsedResult(result); err != nil {
		return err
	}
	return store.submitSync(ctx, writeRequest{kind: writeSaveParsedResult, data: cloneParsedResult(result)})
}

// SaveParsedAudit atomically stores the parser summary, the verified turn
// graph, and the final raw-evidence retention decision.
func (store *Store) SaveParsedAudit(ctx context.Context, value ParsedAudit) error {
	if err := validateParsedAudit(value); err != nil {
		return err
	}
	return store.submitSync(ctx, writeRequest{kind: writeSaveParsedAudit, data: cloneParsedAudit(value)})
}

func resetProcessingParses(transaction *sql.Tx) error {
	_, err := transaction.Exec(`
UPDATE audit_records
SET parse_status = 'pending'
WHERE parse_status = 'processing'
  AND forward_status <> 'rejected'`)
	if err != nil {
		return fmt.Errorf("sqlite writer: reset processing parses: %w", err)
	}
	return nil
}

func claimPendingParse(transaction *sql.Tx, claim *parseClaim) error {
	if claim == nil || claim.AuditID == "" {
		return errors.New("sqlite writer: invalid parse claim")
	}
	result, err := transaction.Exec(`
UPDATE audit_records
SET parse_status = 'processing'
WHERE audit_id = ?
  AND ended_at_ns IS NOT NULL
  AND parse_status = 'pending'
  AND (parse_next_at_ns IS NULL OR parse_next_at_ns <= ?)
  AND forward_status <> 'rejected'`, claim.AuditID, time.Now().UnixNano())
	if err != nil {
		return fmt.Errorf("sqlite writer: claim pending parse: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite writer: claim pending parse rows affected: %w", err)
	}
	if rows > 1 {
		return fmt.Errorf("sqlite writer: claim pending parse affected %d rows", rows)
	}
	claim.Claimed = rows == 1
	return nil
}

const maxParseSaveFailures = 5

func releaseProcessingParse(transaction *sql.Tx, auditID string, signer *security.IntegritySigner, now time.Time) error {
	if auditID == "" {
		return errors.New("sqlite writer: empty audit id")
	}
	var failures int
	var parserName string
	err := transaction.QueryRow(`
SELECT parse_save_failures, parser_name FROM audit_records
WHERE audit_id = ? AND parse_status = 'processing' AND forward_status <> 'rejected'`, auditID).Scan(&failures, &parserName)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // A timed-out save may already have committed.
	}
	if err != nil {
		return fmt.Errorf("sqlite writer: read parse retry: %w", err)
	}
	failures++
	var nextAt any
	if failures < maxParseSaveFailures {
		nextAt = now.Add(30 * time.Second * time.Duration(1<<(failures-1))).UnixNano()
	} else {
		code := "parsed_result_save_failed"
		if err := saveParsedResult(transaction, ParsedResult{
			AuditID: auditID, ParserName: parserName, ParserVersion: "unknown",
			Status: ParseError, ErrorCode: &code, ParsedAtNS: now.UnixNano(),
		}, signer); err != nil {
			return err
		}
	}
	_, err = transaction.Exec(`
UPDATE audit_records
SET parse_save_failures = ?, parse_next_at_ns = ?,
    parse_status = CASE WHEN parse_status = 'processing' THEN 'pending' ELSE parse_status END
WHERE audit_id = ?`, failures, nextAt, auditID)
	if err != nil {
		return fmt.Errorf("sqlite writer: release processing parse: %w", err)
	}
	return nil
}

func saveParsedResult(transaction *sql.Tx, result ParsedResult, signer *security.IntegritySigner) error {
	return saveParsedAudit(transaction, ParsedAudit{Result: result}, signer)
}

func boolDatabaseValue(value *bool) any {
	if value == nil {
		return nil
	}
	return boolInteger(*value)
}
