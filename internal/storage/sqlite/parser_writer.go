package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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

// ReleaseProcessingParse makes a claimed audit eligible for a later retry.
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
  AND forward_status <> 'rejected'`, claim.AuditID)
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

func releaseProcessingParse(transaction *sql.Tx, auditID string) error {
	if auditID == "" {
		return errors.New("sqlite writer: empty audit id")
	}
	result, err := transaction.Exec(`
UPDATE audit_records
SET parse_status = 'pending'
WHERE audit_id = ?
  AND parse_status = 'processing'
  AND forward_status <> 'rejected'`, auditID)
	if err != nil {
		return fmt.Errorf("sqlite writer: release processing parse: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite writer: release processing parse rows affected: %w", err)
	}
	if rows > 1 {
		return fmt.Errorf("sqlite writer: release processing parse affected %d rows", rows)
	}
	return nil
}

func saveParsedResult(transaction *sql.Tx, result ParsedResult) error {
	_, err := transaction.Exec(`
INSERT INTO parsed_results (
    audit_id, parser_name, parser_version, status,
    request_model, response_model, requested_stream, observed_stream,
    response_id, usage_input, usage_output, usage_total,
    error_type, error_code, message_count, tool_call_count, has_tool_call,
    parsed_json_enc, parsed_at_ns
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(audit_id) DO UPDATE SET
    parser_name = excluded.parser_name,
    parser_version = excluded.parser_version,
    status = excluded.status,
    request_model = excluded.request_model,
    response_model = excluded.response_model,
    requested_stream = excluded.requested_stream,
    observed_stream = excluded.observed_stream,
    response_id = excluded.response_id,
    usage_input = excluded.usage_input,
    usage_output = excluded.usage_output,
    usage_total = excluded.usage_total,
    error_type = excluded.error_type,
    error_code = excluded.error_code,
    message_count = excluded.message_count,
    tool_call_count = excluded.tool_call_count,
    has_tool_call = excluded.has_tool_call,
    parsed_json_enc = excluded.parsed_json_enc,
    parsed_at_ns = excluded.parsed_at_ns`,
		result.AuditID,
		result.ParserName,
		result.ParserVersion,
		result.Status,
		result.RequestModel,
		result.ResponseModel,
		boolDatabaseValue(result.RequestedStream),
		boolDatabaseValue(result.ObservedStream),
		result.ResponseID,
		result.UsageInput,
		result.UsageOutput,
		result.UsageTotal,
		result.ErrorType,
		result.ErrorCode,
		result.MessageCount,
		result.ToolCallCount,
		boolDatabaseValue(result.HasToolCall),
		nullableBytes(result.ParsedJSONEnc),
		result.ParsedAtNS,
	)
	if err != nil {
		return fmt.Errorf("sqlite writer: save parsed result: %w", err)
	}

	parent, err := transaction.Exec(`
UPDATE audit_records
SET parse_status = ?
WHERE audit_id = ?
  AND parser_name = ?
  AND parse_status = 'processing'
  AND forward_status <> 'rejected'`, result.Status, result.AuditID, result.ParserName)
	if err != nil {
		return fmt.Errorf("sqlite writer: finish parse status: %w", err)
	}
	return requireOneRow(parent, "finish parse status")
}

func boolDatabaseValue(value *bool) any {
	if value == nil {
		return nil
	}
	return boolInteger(*value)
}
