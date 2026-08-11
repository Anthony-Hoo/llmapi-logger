package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// ListAudits reads only the narrow columns needed by the audit list. limit is
// the requested page size; one extra row is read to determine HasMore.
func (store *Store) ListAudits(ctx context.Context, filter AuditQueryFilter, cursor AuditQueryCursor, limit int) (AuditListPage, error) {
	if ctx == nil {
		return AuditListPage{}, errors.New("sqlite: nil context")
	}
	if store == nil || store.isClosed() {
		return AuditListPage{}, ErrClosed
	}
	if limit < 1 || limit > 200 {
		return AuditListPage{}, fmt.Errorf("sqlite: query limit must be between 1 and 200")
	}
	if (cursor.BeforeStartedAtNS == 0) != (cursor.BeforeID == "") {
		return AuditListPage{}, errors.New("sqlite: incomplete audit cursor")
	}

	var statement strings.Builder
	statement.WriteString(`
SELECT a.audit_id, a.started_at_ns, a.ended_at_ns, a.route_id, a.protocol,
       a.parser_name, a.method, a.path, a.mode, a.status_code,
       a.forward_status, a.capture_status, a.parse_status, a.blocked_by,
       a.block_code, a.error_code, p.request_model, p.response_model,
       t.newapi_token_id, t.token_name
FROM audit_records AS a
LEFT JOIN parsed_results AS p ON p.audit_id = a.audit_id
LEFT JOIN token_links AS t ON t.audit_id = a.audit_id
WHERE 1 = 1`)
	arguments := make([]any, 0, 16)
	appendCondition := func(condition string, values ...any) {
		statement.WriteString("\n  AND ")
		statement.WriteString(condition)
		arguments = append(arguments, values...)
	}
	if filter.FromNS != nil {
		appendCondition("a.started_at_ns >= ?", *filter.FromNS)
	}
	if filter.ToNS != nil {
		appendCondition("a.started_at_ns <= ?", *filter.ToNS)
	}
	if filter.Protocol != "" {
		appendCondition("a.protocol = ?", filter.Protocol)
	}
	if filter.Path != "" {
		appendCondition("a.path = ?", filter.Path)
	}
	if filter.Model != "" {
		appendCondition("(p.request_model = ? OR p.response_model = ?)", filter.Model, filter.Model)
	}
	if filter.StatusCode != nil {
		appendCondition("a.status_code = ?", *filter.StatusCode)
	}
	if filter.ForwardStatus != "" {
		appendCondition("a.forward_status = ?", filter.ForwardStatus)
	}
	if filter.BlockedBy != "" {
		appendCondition("a.blocked_by = ?", filter.BlockedBy)
	}
	if filter.BlockCode != "" {
		appendCondition("a.block_code = ?", filter.BlockCode)
	}
	if filter.CaptureStatus != "" {
		appendCondition("a.capture_status = ?", filter.CaptureStatus)
	}
	if filter.NewAPITokenID != nil {
		appendCondition("t.newapi_token_id = ?", *filter.NewAPITokenID)
	}
	if filter.TokenName != "" {
		appendCondition("t.token_name = ?", filter.TokenName)
	}
	if cursor.BeforeID != "" {
		appendCondition("(a.started_at_ns < ? OR (a.started_at_ns = ? AND a.audit_id < ?))", cursor.BeforeStartedAtNS, cursor.BeforeStartedAtNS, cursor.BeforeID)
	}
	statement.WriteString("\nORDER BY a.started_at_ns DESC, a.audit_id DESC\nLIMIT ?")
	arguments = append(arguments, limit+1)

	rows, err := store.readerDB.QueryContext(ctx, statement.String(), arguments...)
	if err != nil {
		return AuditListPage{}, fmt.Errorf("sqlite: list audits: %w", err)
	}
	defer rows.Close()

	result := AuditListPage{Rows: make([]AuditListRow, 0, limit)}
	for rows.Next() {
		var row AuditListRow
		if err := scanAuditListRow(rows, &row); err != nil {
			return AuditListPage{}, fmt.Errorf("sqlite: scan audit list: %w", err)
		}
		if len(result.Rows) == limit {
			result.HasMore = true
			break
		}
		result.Rows = append(result.Rows, row)
	}
	if err := rows.Err(); err != nil {
		return AuditListPage{}, fmt.Errorf("sqlite: iterate audit list: %w", err)
	}
	return result, nil
}

// QueryAuditDetail reads one transactionally consistent detail projection. It
// loads the encrypted request URI, Header values, and parsed conversation for
// the authenticated query service, but never loads Body chunks.
func (store *Store) QueryAuditDetail(ctx context.Context, auditID string) (AuditQueryDetail, error) {
	if ctx == nil {
		return AuditQueryDetail{}, errors.New("sqlite: nil context")
	}
	if auditID == "" {
		return AuditQueryDetail{}, errors.New("sqlite: empty audit id")
	}
	if store == nil || store.isClosed() {
		return AuditQueryDetail{}, ErrClosed
	}

	transaction, err := store.readerDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return AuditQueryDetail{}, fmt.Errorf("sqlite: begin query detail: %w", err)
	}
	defer transaction.Rollback()

	detail := AuditQueryDetail{}
	if err := scanAuditListRow(transaction.QueryRowContext(ctx, `
SELECT a.audit_id, a.started_at_ns, a.ended_at_ns, a.route_id, a.protocol,
       a.parser_name, a.method, a.path, a.mode, a.status_code,
       a.forward_status, a.capture_status, a.parse_status, a.blocked_by,
       a.block_code, a.error_code, p.request_model, p.response_model,
       t.newapi_token_id, t.token_name
FROM audit_records AS a
LEFT JOIN parsed_results AS p ON p.audit_id = a.audit_id
LEFT JOIN token_links AS t ON t.audit_id = a.audit_id
WHERE a.audit_id = ?`, auditID), &detail.Audit); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AuditQueryDetail{}, sql.ErrNoRows
		}
		return AuditQueryDetail{}, fmt.Errorf("sqlite: read query detail: %w", err)
	}
	if err := transaction.QueryRowContext(ctx, `
SELECT request_uri_enc
FROM audit_records
WHERE audit_id = ?`, auditID).Scan(&detail.RequestURIEnc); err != nil {
		return AuditQueryDetail{}, fmt.Errorf("sqlite: read encrypted request URI: %w", err)
	}
	detail.RequestURIEnc = cloneBytes(detail.RequestURIEnc)
	if detail.Stages, err = readStages(ctx, transaction, auditID); err != nil {
		return AuditQueryDetail{}, err
	}
	if detail.Headers, err = readHeaderEvidence(ctx, transaction, auditID); err != nil {
		return AuditQueryDetail{}, err
	}
	if detail.Bodies, err = readBodies(ctx, transaction, auditID); err != nil {
		return AuditQueryDetail{}, err
	}
	if detail.ParsedResult, err = readParsedResultSummary(ctx, transaction, auditID); err != nil {
		return AuditQueryDetail{}, err
	}
	if detail.TokenLink, err = readTokenLinkSummary(ctx, transaction, auditID); err != nil {
		return AuditQueryDetail{}, err
	}
	if err := transaction.Commit(); err != nil {
		return AuditQueryDetail{}, fmt.Errorf("sqlite: commit query detail: %w", err)
	}
	return detail, nil
}

// RawBodyMeta returns the aggregate metadata needed before starting an HTTP
// raw-body response.
func (store *Store) RawBodyMeta(ctx context.Context, auditID, stage string) (RawBodyMetadata, error) {
	if ctx == nil {
		return RawBodyMetadata{}, errors.New("sqlite: nil context")
	}
	if auditID == "" || !validStage(stage) {
		return RawBodyMetadata{}, errors.New("sqlite: invalid raw body identity")
	}
	if store == nil || store.isClosed() {
		return RawBodyMetadata{}, ErrClosed
	}

	var metadata RawBodyMetadata
	var digest []byte
	var hashComplete, eofSeen int
	var errorCode sql.NullString
	err := store.readerDB.QueryRowContext(ctx, `
SELECT audit_id, stage, observed_length, stored_length, sha256,
       hash_complete, eof_seen, state, error_code
FROM body_streams
WHERE audit_id = ? AND stage = ?`, auditID, stage).Scan(
		&metadata.AuditID,
		&metadata.Stage,
		&metadata.ObservedLength,
		&metadata.StoredLength,
		&digest,
		&hashComplete,
		&eofSeen,
		&metadata.State,
		&errorCode,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RawBodyMetadata{}, sql.ErrNoRows
		}
		return RawBodyMetadata{}, fmt.Errorf("sqlite: read raw body metadata: %w", err)
	}
	metadata.SHA256 = cloneBytes(digest)
	metadata.HashComplete = hashComplete != 0
	metadata.EOFSeen = eofSeen != 0
	metadata.ErrorCode = nullStringPointer(errorCode)
	return metadata, nil
}

// StreamBodyChunks iterates encrypted owning chunks in sequence order without
// collecting the complete Body in memory. The callback must not retain the
// DataEnc slice after it returns.
func (store *Store) StreamBodyChunks(ctx context.Context, auditID, stage string, visit func(BodyChunk) error) error {
	if ctx == nil {
		return errors.New("sqlite: nil context")
	}
	if auditID == "" || !validStage(stage) {
		return errors.New("sqlite: invalid raw body identity")
	}
	if visit == nil {
		return errors.New("sqlite: nil chunk visitor")
	}
	if store == nil || store.isClosed() {
		return ErrClosed
	}

	rows, err := store.readerDB.QueryContext(ctx, `
SELECT audit_id, stage, seq, "offset", plaintext_length, observed_at_ns, data_enc
FROM body_chunks
WHERE audit_id = ? AND stage = ?
ORDER BY seq`, auditID, stage)
	if err != nil {
		return fmt.Errorf("sqlite: stream body chunks: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var chunk BodyChunk
		if err := rows.Scan(
			&chunk.AuditID,
			&chunk.Stage,
			&chunk.Seq,
			&chunk.Offset,
			&chunk.PlaintextLength,
			&chunk.ObservedAtNS,
			&chunk.DataEnc,
		); err != nil {
			return fmt.Errorf("sqlite: scan body chunk: %w", err)
		}
		if err := visit(chunk); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("sqlite: iterate body chunks: %w", err)
	}
	return nil
}

func scanAuditListRow(row rowScanner, destination *AuditListRow) error {
	var endedAt, statusCode, newAPITokenID sql.NullInt64
	var blockedBy, blockCode, errorCode, requestModel, responseModel, tokenName sql.NullString
	if err := row.Scan(
		&destination.AuditID,
		&destination.StartedAtNS,
		&endedAt,
		&destination.RouteID,
		&destination.Protocol,
		&destination.ParserName,
		&destination.Method,
		&destination.Path,
		&destination.Mode,
		&statusCode,
		&destination.ForwardStatus,
		&destination.CaptureStatus,
		&destination.ParseStatus,
		&blockedBy,
		&blockCode,
		&errorCode,
		&requestModel,
		&responseModel,
		&newAPITokenID,
		&tokenName,
	); err != nil {
		return err
	}
	destination.EndedAtNS = nullInt64Pointer(endedAt)
	destination.StatusCode = nullIntPointer(statusCode)
	destination.BlockedBy = nullStringPointer(blockedBy)
	destination.BlockCode = nullStringPointer(blockCode)
	destination.ErrorCode = nullStringPointer(errorCode)
	destination.RequestModel = nullStringPointer(requestModel)
	destination.ResponseModel = nullStringPointer(responseModel)
	destination.NewAPITokenID = nullInt64Pointer(newAPITokenID)
	destination.TokenName = nullStringPointer(tokenName)
	return nil
}

func readHeaderEvidence(ctx context.Context, transaction *sql.Tx, auditID string) ([]HeaderEvidence, error) {
	rows, err := transaction.QueryContext(ctx, `
SELECT stage, kind, name, value_index, value_length, value_enc
FROM http_headers
WHERE audit_id = ?
ORDER BY `+stageOrderSQL+`, kind, name, value_index`, auditID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: read header evidence: %w", err)
	}
	defer rows.Close()

	headers := make([]HeaderEvidence, 0)
	for rows.Next() {
		var header HeaderEvidence
		if err := rows.Scan(&header.Stage, &header.Kind, &header.Name, &header.ValueIndex, &header.ValueLength, &header.ValueEnc); err != nil {
			return nil, fmt.Errorf("sqlite: scan header evidence: %w", err)
		}
		header.ValueEnc = cloneBytes(header.ValueEnc)
		headers = append(headers, header)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate header evidence: %w", err)
	}
	return headers, nil
}

func readParsedResultSummary(ctx context.Context, transaction *sql.Tx, auditID string) (*ParsedResultSummary, error) {
	var result ParsedResultSummary
	var requestedStream, observedStream, hasToolCall sql.NullInt64
	var requestModel, responseModel, responseID, errorType, errorCode sql.NullString
	var usageInput, usageOutput, usageTotal, messageCount, toolCallCount sql.NullInt64
	var parsedJSONEnc []byte
	err := transaction.QueryRowContext(ctx, `
SELECT parser_name, parser_version, status, request_model, response_model,
       requested_stream, observed_stream, response_id, usage_input,
       usage_output, usage_total, error_type, error_code, message_count,
       tool_call_count, has_tool_call, parsed_json_enc, parsed_at_ns
FROM parsed_results
WHERE audit_id = ?`, auditID).Scan(
		&result.ParserName,
		&result.ParserVersion,
		&result.Status,
		&requestModel,
		&responseModel,
		&requestedStream,
		&observedStream,
		&responseID,
		&usageInput,
		&usageOutput,
		&usageTotal,
		&errorType,
		&errorCode,
		&messageCount,
		&toolCallCount,
		&hasToolCall,
		&parsedJSONEnc,
		&result.ParsedAtNS,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: read parsed result summary: %w", err)
	}
	result.RequestModel = nullStringPointer(requestModel)
	result.ResponseModel = nullStringPointer(responseModel)
	result.RequestedStream = nullBoolPointer(requestedStream)
	result.ObservedStream = nullBoolPointer(observedStream)
	result.ResponseID = nullStringPointer(responseID)
	result.UsageInput = nullInt64Pointer(usageInput)
	result.UsageOutput = nullInt64Pointer(usageOutput)
	result.UsageTotal = nullInt64Pointer(usageTotal)
	result.ErrorType = nullStringPointer(errorType)
	result.ErrorCode = nullStringPointer(errorCode)
	result.MessageCount = nullInt64Pointer(messageCount)
	result.ToolCallCount = nullInt64Pointer(toolCallCount)
	result.HasToolCall = nullBoolPointer(hasToolCall)
	result.ParsedJSONEnc = cloneBytes(parsedJSONEnc)
	return &result, nil
}

func readTokenLinkSummary(ctx context.Context, transaction *sql.Tx, auditID string) (*TokenLinkSummary, error) {
	var result TokenLinkSummary
	err := transaction.QueryRowContext(ctx, `
SELECT newapi_token_id, token_name, linked_at_ns
FROM token_links
WHERE audit_id = ?`, auditID).Scan(&result.NewAPITokenID, &result.TokenName, &result.LinkedAtNS)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: read token link summary: %w", err)
	}
	return &result, nil
}

func nullBoolPointer(value sql.NullInt64) *bool {
	if !value.Valid {
		return nil
	}
	converted := value.Int64 != 0
	return &converted
}
